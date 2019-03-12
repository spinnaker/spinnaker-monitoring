# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pylint: disable=missing-docstring

import collections
import datetime
import json
import os
import logging
import textwrap
import time
from multiprocessing.pool import ThreadPool

from command_processor import CommandHandler
from command_processor import get_global_options
import google_service
import http_server
import stackdriver_descriptors
import stackdriver_service
from spectator_client import ResponseProcessor

from stackdriver_service import StackdriverMetricsService
try:
  from googleapiclient.errors import HttpError
  STACKDRIVER_AVAILABLE = True
except ImportError:
  STACKDRIVER_AVAILABLE = False

try:
  import httplib
except ImportError:
  import http.client as httplib


def get_descriptor_list(options):
  stackdriver = stackdriver_service.make_service(options)
  return stackdriver_descriptors.get_descriptor_list(stackdriver)


def audit_results_to_output(audit_results, empty_message):
  summary = audit_results.summary_string().replace('\n', '\n  ')
  if not summary:
    summary = empty_message
  lines = audit_results.lines
  lines.append('SUMMARY:')
  lines.append('  ' + summary)
  return '\n'.join(lines)


class BaseStackdriverCommandHandler(CommandHandler):
  """Base CommandHandler for Stackdriver commands."""

  @property
  def enabled(self):
    """Determine if stackdriver is enabled so commands are visible.

    This is only applicable to web commands. Commandline commands are always
    available.
    """
    return 'stackdriver' in (get_global_options()
                             .get('monitor', {}).get('metric_store', []))

  def add_argparser(self, subparsers):
    """Implements CommandHandler."""
    parser = super(BaseStackdriverCommandHandler, self).add_argparser(
        subparsers)
    stackdriver_service.StackdriverMetricsService.add_parser_arguments(parser)
    return parser


class UpsertCustomDescriptorsHandler(BaseStackdriverCommandHandler):
  """Create or update Stackdriver custom metric descriptors.
  """

  SERVICE_LIST = [
      'clouddriver', 'deck', 'echo', 'fiat', 'front50',
      'gate', 'halyard', 'igor', 'kayenta', 'monitoring-service',
      'rosco'
  ]

  def process_commandline_request(self, options):
    """Implements CommandHandler."""
    options = google_service.normalize_options(options)
    if not options.get('manage_stackdriver_descriptors'):
      options['manage_stackdriver_descriptors'] = 'create'
    stackdriver = stackdriver_service.make_service(options)
    manager = stackdriver_descriptors.MetricDescriptorManager(
        stackdriver, ResponseProcessor(options))
    audit_results = manager.audit_descriptors(
        options, service_list=self.SERVICE_LIST)

    message = audit_results_to_output(
        audit_results,
        'Metric_filters are not configured, or are empty.')
    self.output(options, message)

    if audit_results.errors:
      raise ValueError('Encountered %d errors' % audit_results.errors)

  def process_web_request(self, request, path, params, fragment):
    """Implements CommandHandler."""
    options = dict(get_global_options())
    stackdriver_options = options['stackdriver']
    mode = params.get('mode', 'none').lower()
    stackdriver_options['manage_descriptors'] = mode
    stackdriver = stackdriver_service.make_service(options)
    manager = stackdriver.descriptor_manager
    audit_results = manager.audit_descriptors(options)

    create_html = ''
    delete_html = ''
    full_html = ''
    if audit_results.num_unresolved_issues > 0:
      if audit_results.missing_count or audit_results.outdated_count:
        create_html = ('<a href="{path}?mode=create">Create/Update ONLY</a>'
                       .format(path=path))

      if audit_results.obsoleted_count:
        delete_html = ('<a href="{path}?mode=delete">Delete ONLY</a>'
                       .format(path=path))

      if create_html and delete_html:
        full_html = ('<a href="{path}?mode=full">Create/Update AND Delete</a>'
                     .format(path=path))
    if not create_html:
      create_html = '<i>No Create/Update Needed</i>'
    if not delete_html:
      delete_html = '<i>No Extra Descriptors</i>'

    text = audit_results_to_output(
        audit_results, 'Metric Filters not configured.')

    stackdriver_metric_prefix = stackdriver_descriptors.determine_metric_prefix(
        stackdriver_options)
    unchanged_names = audit_results.unchanged_descriptor_names
    if unchanged_names:
      unchanged = '{count} Unchanged Descriptors:\n  - {list}'.format(
          count=len(unchanged_names),
          list='\n  - '.join([name[name.find(stackdriver_metric_prefix):]
                              for name in unchanged_names]))
    else:
      unchanged = ''

    body = textwrap.dedent("""
          <b>Actions</b>
          <p/>
          {create}<br/>{delete}<br/>{full}
          <p/>
          <hr/>
          <b>Audit Results</b>
          <p/>
          <pre>{unchanged}
          {text}
          </pre>
      """.format(unchanged=unchanged, text=text,
                 create=create_html, delete=delete_html, full=full_html))

    response_code = (httplib.OK if audit_results.errors == 0
                     else httplib.INTERNAL_SERVER_ERROR)
    headers = {'Content-Type': 'text/html'}
    request.respond(response_code, headers, body)


class ListCustomDescriptorsHandler(BaseStackdriverCommandHandler):
  """Administrative handler to list all the known descriptors."""

  def process_commandline_request(self, options):
    descriptor_list = get_descriptor_list(options)
    json_text = json.JSONEncoder(indent=2).encode(descriptor_list)
    self.output(options, json_text)

  def process_web_request(self, request, path, params, fragment):
    options = dict(get_global_options())
    options.update(params)
    descriptor_list = get_descriptor_list(options)
    metric_prefix = stackdriver_descriptors.determine_metric_prefix(
        options['stackdriver'])

    if self.accepts_content_type(request, 'text/html'):
      html = self.descriptors_to_html(metric_prefix, descriptor_list)
      html_doc = http_server.build_html_document(
          html, title='Custom Descriptors')
      request.respond(200, {'ContentType': 'text/html'}, html_doc)
    elif self.accepts_content_type(request, 'application/json'):
      json_doc = json.JSONEncoder(indent=2).encode(descriptor_list)
      request.respond(200, {'ContentType': 'application/json'}, json_doc)
    else:
      text = self.descriptors_to_text(metric_prefix, descriptor_list)
      request.respond(200, {'ContentType': 'text/plain'}, text)

  def collect_rows(self, metric_prefix, descriptor_list):
    rows = []
    for elem in descriptor_list:
      type_name = elem['type'][len(metric_prefix):]
      labels = elem.get('labels', [])
      label_names = [k['key'] for k in labels]
      rows.append((type_name, label_names))
    return rows

  def descriptors_to_html(self, metric_prefix, descriptor_list):
    rows = self.collect_rows(metric_prefix, descriptor_list)

    html = ['<table>', '<tr><th>Metric Type</th><th>Labels</th></tr>']
    html.extend(['<tr><td><b>{0}</b></td><td><code>{1}</code></td></tr>'
                 .format(row[0], ', '.join(row[1]))
                 for row in rows])
    html.append('</table>')
    html.append('<p>Found {0} Spinnaker Metrics</p>'
                .format(len(descriptor_list)))
    return '\n'.join(html)

  def descriptors_to_text(self, metric_prefix, descriptor_list):
    rows = self.collect_rows(metric_prefix, descriptor_list)

    text = []
    for row in rows:
      text.append('{0}\n  Tags={1}'.format(row[0], ','.join(row[1])))
    text.append('Found {0} Spinnaker Metrics'.format(len(descriptor_list)))
    return '\n\n'.join(text)


class SurveyInfo(collections.namedtuple(
    'DescriptorSurveyInfo',
    ['type_name', 'iso_time', 'days_ago', 'error', 'deleted'])):
  """Information reported on custom metric descriptor."""

  UNKNOWN_DAYS_AGO = -1
  UNKNOWN_ISO = None

  @staticmethod
  def make_seen(type_name, iso_time, days_ago):
    """Construct SurveyInfo for descriptor that is in use."""
    return SurveyInfo(type_name, iso_time, days_ago, None, False)

  @staticmethod
  def make_unknown(type_name):
    """Construct SurveyInfo for descriptor that is not in use."""
    return SurveyInfo(
        type_name, SurveyInfo.UNKNOWN_ISO, SurveyInfo.UNKNOWN_DAYS_AGO,
        None, False)

  @staticmethod
  def make_deleted(type_name):
    """Construct SurveyInfo for descriptor that has been deleted."""
    return SurveyInfo(
        type_name, SurveyInfo.UNKNOWN_ISO, SurveyInfo.UNKNOWN_DAYS_AGO,
        None, True)

  @staticmethod
  def make_error(type_name, error):
    """Construct SurveyInfo for descriptor that could not be determined."""
    return SurveyInfo(
        type_name, SurveyInfo.UNKNOWN_ISO, SurveyInfo.UNKNOWN_DAYS_AGO,
        error, False)

  @staticmethod
  def to_days_since(days_ago):
    """Return 'days_ago' as a string."""
    if days_ago is None or days_ago == SurveyInfo.UNKNOWN_DAYS_AGO:
      return ''
    if days_ago < 1:
      return 'today'
    if days_ago == 1:
      return '1 day'
    return '%d days' % days_ago

  def days_ago_str(self):
    """Return 'days_ago' as a string."""
    return self.to_days_since(self.days_ago)


class StackdriverSurveyor(object):
  """Survey stackdriver custom metric descriptors for recent usage.

  This is for housekeeping to get rid of unused metric descriptors.
  We need to worry about that because descriptors are in short supply
  for the project, and Spinnaker wants more than is available.

  Since stackdriver descriptors are permanent, we'll provide a means
  to get rid of obsolete ones to make way for new ones. This class
  provides a means for detecting possible obsolete descriptors.
  """

  @property
  def project(self):
    """The project being surveyed."""
    return self.__project

  @property
  def start_time(self):
    """The start time string used for the survey."""
    return self.__op_params['interval_startTime']

  @property
  def end_time(self):
    """The end time string used for the survey."""
    return self.__op_params['interval_endTime']

  @property
  def days_since(self):
    """The number of days between start and end time."""
    return self.__days_since

  def __init__(self, options):
    num_threads = options.get('num_threads', 50)
    factory = stackdriver_service.make_service

    # The python client library is not thread friendly
    # so we'll need a different stub for each thread.
    # We only need the list method from that stub
    # so we'll build a pool of those.
    self.__op_methods = [
        factory(options).stub.projects().timeSeries().list
        for _ in range(num_threads)
    ]
    self.__project = factory(options).project

    self.__max_attempts = 10
    self.__secs_between_attempts = 2
    self.__days_since = int(options.get('days_since', 1))
    self.__today = datetime.datetime.today()
    self.__date_format = '%Y-%m-%dT%H:%M:%SZ'

    end_time = datetime.datetime.now()
    start_time = end_time.date() - datetime.timedelta(self.__days_since)

    self.__op_params = {
        'name': 'projects/' + self.__project,
        'interval_endTime': end_time.strftime(self.__date_format),
        'interval_startTime': start_time.strftime(self.__date_format),
        'pageSize': 1
    }

  def build_survey_from_descriptor_list(self, descriptor_list):
    """Returns a dict of SurveyInfo keyed by descriptor type_name.

    Args:
      descriptor_names: [list of descriptor objects]
    """
    type_names = [descriptor['type'] for descriptor in descriptor_list]
    return self.build_survey_from_type_names(type_names)

  def survey_to_sorted_list(self, survey):
    def sort_key(info):
      rank = -1 if info.error else info.days_ago
      return '%d %s' % (rank, info.type_name)

    return sorted(survey.values(), key=sort_key)

  def build_survey_from_type_names(self, type_names):
    """Returns a dict of SurveyInfo keyed by descriptor type_name.

    Args:
      type_names: [list of string]
    """
    num_threads = len(self.__op_methods)

    pool = ThreadPool(num_threads)
    process = lambda type_name: self.__survey_type(type_name)
    survey = pool.map(process, type_names)
    pool.close()
    pool.join()
    return {info.type_name: info for info in survey}

  def __survey_type(self, type_name):
    """Performs survey on a given descriptor type name.

    Returns:
      SurveyInfo
    """
    method = self.__op_methods.pop()
    op = method(filter='metric.type="%s"' % type_name, **self.__op_params)
    try:
      # Stackdriver likes to return random 500 errors,
      # especially when clients hammer it, so retry.
      attempt = 1
      while True:
        info, can_retry = self.__attempt_op(op, type_name)
        if not info.error or not can_retry:
          return info
        if attempt == self.__max_attempts:
          return info

        logging.error('Retryable error processing %s...', type_name)
        time.sleep(self.__secs_between_attempts)
        attempt += 1
        continue
    finally:
      # put back
      self.__op_methods.append(method)

  def __attempt_op(self, op, type_name):
    """Return SurveyInfo, can_retry."""

    try:
      result = op.execute()
      if not result:
        return SurveyInfo.make_unknown(type_name), False

      if 'timeSeries' not in result:
        logging.error('Unexpected result surveying "%s": %s',
                      type_name, result)
        return SurveyInfo.make_error(type_name, result), True

      last_iso = result['timeSeries'][0]['points'][0]['interval']['endTime']
      last_time = datetime.datetime.strptime(last_iso, self.__date_format)
      days_ago = (self.__today - last_time).days
      return SurveyInfo.make_seen(type_name, last_iso, days_ago), True

    except HttpError as err:
      retryable = err.resp.status >= 500
      logging.error('Error processing %s: %s', type_name, str(err))
      error = 'HTTP [%d]: %s ' % (err.resp.status, err.resp.reason)
      return SurveyInfo.make_error(type_name, error), retryable

    except Exception as e:
      logging.error('Error processing %s: %s', type_name, str(e))
      return SurveyInfo.make_error(type_name, str(e)), False


class ClearCustomDescriptorsHandler(BaseStackdriverCommandHandler):
  """Administrative handler to clear all the known descriptors.
  """

  def __do_clear(self, options):
    """Deletes exsiting custom metric descriptors."""
    stackdriver = stackdriver_service.make_service(options)
    audit_results = stackdriver_descriptors.AuditResults(stackdriver)
    descriptor_list = audit_results.descriptor_map.values()
    audit_results.unused_descriptors = {
        item['type']: item for item in descriptor_list
    }
    stackdriver.descriptor_manager.delete_descriptors(
        descriptor_list, audit_results)
    return audit_results

  def process_commandline_request(self, options):
    """Implements CommandHandler."""
    copy_options = dict(options)
    copy_options['clear_all'] = True
    audit_results = self.__do_clear(copy_options)
    text = audit_results_to_output(
        audit_results, 'No custom metric descriptors to delete.')
    self.output(options, text)

  def process_web_request(self, request, path, params, fragment):
    """Implements CommandHandler."""
    options = dict(get_global_options())
    options.update(params)

    if str(params.get('clear_all')).lower() != 'true':
      stackdriver = stackdriver_service.make_service(options)
      audit_results = stackdriver_descriptors.AuditResults(stackdriver)
      descriptor_list = audit_results.descriptor_map.values()
      descriptor_html = '\n<li> '.join(item['type'] for item in descriptor_list)
      html = textwrap.dedent("""\
          Clearing descriptors requires query parameter
          <code>clear_all=true</code>.
          <p/>
          Here are the {count} custom descriptors:
          <ul>
          <li>{descriptors}
          </ul>
          <p/>
          <a href="{path}?clear_all=true">Yes, delete everything!</a>
      """.format(count=len(descriptor_list),
                 descriptors=descriptor_html,
                 path=path))

      html_doc = http_server.build_html_document(
          html, title='Missing Parameters')
      request.respond(
          400, {'ContentType': 'text/html'}, html_doc)
      return

    audit_results = self.__do_clear(options)
    response_code = (httplib.OK if audit_results.obsoleted_count == 0
                     else httplib.INTERNAL_SERVER_ERROR)
    headers = {'Content-Type': 'text/plain'}
    body = audit_results_to_output(
        audit_results, "No custom descriptors to delete.")
    request.respond(response_code, headers, body)


class ListDashboardsHandler(BaseStackdriverCommandHandler):
  """Administrative handler to list all dashboards (not just spinnaker)."""

  def process_commandline_request(self, options):
    """Implements CommandHandler."""
    stackdriver = stackdriver_service.make_service(options)

    parent = 'projects/{0}'.format(stackdriver.project)
    dashboards = stackdriver.stub.projects().dashboards()
    request = dashboards.list(parent=parent)
    all_dashboards = []
    while  request:
      response = request.execute()
      all_dashboards.extend(response.get('dashboards', []))
      request = dashboards.list_next(request, response)

    found = {elem['name']: elem['displayName'] for elem in all_dashboards}
    self.output(options, str(found))


def lookup_dashboard(stackdriver, display_name):
  """Find the dashboard definition with the given display_name."""
  parent = 'projects/{0}'.format(stackdriver.project)
  dashboards = stackdriver.stub.projects().dashboards()
  request = dashboards.list(parent=parent)
  while request:
    response = request.execute()
    for elem in response.get('dashboards', []):
      if elem['displayName'] == display_name:
        return elem
      request = dashboards.list_next(request, response)
  return None


class GetDashboardHandler(BaseStackdriverCommandHandler):
  """Administrative handler to get a dashboard from its name."""

  def add_argparser(self, subparsers):
    """Implements CommandHandler."""
    parser = super(GetDashboardHandler, self).add_argparser(subparsers)
    parser.add_argument(
        '--name', required=True,
        help='The name of the dashboard to get.')
    return parser

  def process_commandline_request(self, options):
    """Implements CommandHandler."""
    display_name = options.get('name', None)
    if not display_name:
      raise ValueError('No name provided.')

    stackdriver = stackdriver_service.make_service(options)
    found = lookup_dashboard(stackdriver, display_name)

    if found is None:
      raise ValueError('"{0}" not found.'.format(display_name))
    json_text = json.JSONEncoder(indent=2).encode(found)
    self.output(options, json_text)


class UploadDashboardHandler(BaseStackdriverCommandHandler):
  """Administrative handler to upload a dashboard."""

  def add_argparser(self, subparsers):
    """Implements CommandHandler."""
    parser = super(UploadDashboardHandler, self).add_argparser(subparsers)
    parser.add_argument('--dashboard', required=True,
                        help='The path to the json dashboard file.')
    parser.add_argument(
        '--update', default=False, action='store_true',
        help='Update an existing dashboard rather than create a new one.')
    return parser

  def process_commandline_request(self, options):
    """Implements CommandHandler."""
    path = options.get('dashboard', None)
    if not path:
      raise ValueError('No dashboard provided.')
    with open(path, 'r') as infile:
      specification = json.JSONDecoder().decode(infile.read().decode('utf-8'))

    stackdriver = stackdriver_service.make_service(options)
    dashboards = stackdriver.stub.projects().dashboards()

    parent = 'projects/{0}'.format(stackdriver.project)
    if options.get('update', False):
      display_name = specification['displayName']
      found = lookup_dashboard(stackdriver, display_name)
      if found is None:
        raise ValueError('"{0}" not found.'.format(display_name))
      response = dashboards.update(
          name=found['name'], body=specification).execute()
      action = 'Updated'
    else:
      response = dashboards.create(parent=parent, body=specification).execute()
      action = 'Created'

    self.output(options, '{action} "{title}" with name {name}'.format(
        action=action, title=response['displayName'], name=response['name']))


def add_handlers(handler_list, subparsers):
  """Registers CommandHandlers for interacting with Stackdriver."""
  command_handlers = [
      ListCustomDescriptorsHandler(
          '/stackdriver/list_descriptors',
          'list_stackdriver',
          'Get the JSON of all the Stackdriver Custom Metric Descriptors.'),
      ClearCustomDescriptorsHandler(
          '/stackdriver/clear_descriptors',
          'clear_stackdriver',
          'Clear all the Stackdriver Custom Metrics'),
      UpsertCustomDescriptorsHandler(
          '/stackdriver/audit_descriptors',
          'upsert_stackdriver_descriptors',
          'Update the custom Stackdriver Metric Descriptors'
          ' from the Meter Specifications in the Spectator'
          ' transform filters'),
  ]

  if STACKDRIVER_AVAILABLE and os.environ.get('STACKDRIVER_API_KEY'):
    command_handlers.extend([
        ListDashboardsHandler('/stackdriver/list_dashboards',
                              'list_stackdriver_dashboards',
                              'List the available Stackdriver Dashboards'),
        GetDashboardHandler(None,
                            'get_stackdriver_dashboard',
                            'Get a specific dashboard by display name'),
        UploadDashboardHandler(None,
                               'upload_stackdriver_dashboard',
                               'Create or update specific dashboard')
    ])

  for handler in command_handlers:
    handler.add_argparser(subparsers)
    handler_list.append(handler)
