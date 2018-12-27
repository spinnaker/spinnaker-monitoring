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

import cgi
import collections
import datetime
import httplib
import json
import os
import logging
import textwrap
import time
from multiprocessing.pool import ThreadPool

from command_processor import CommandHandler
from command_processor import get_global_options
import http_server
import stackdriver_service
from spectator_client import ResponseProcessor

from stackdriver_service import StackdriverMetricsService
try:
  from googleapiclient.errors import HttpError
  STACKDRIVER_AVAILABLE = True
except ImportError:
  STACKDRIVER_AVAILABLE = False


def compare_descriptor_types(a, b):
  """Compare two metric types to sort them in order."""
  # pylint: disable=invalid-name
  a_root = a['type'][len(StackdriverMetricsService.CUSTOM_PREFIX):]
  b_root = b['type'][len(StackdriverMetricsService.CUSTOM_PREFIX):]
  return (-1 if a_root < b_root
          else 0 if a_root == b_root
          else 1)


def get_descriptor_list(options):
  """Return a list of all the stackdriver custom metric descriptors."""
  stackdriver = stackdriver_service.make_service(options)
  project = stackdriver.project
  type_map = stackdriver.fetch_all_custom_descriptors(project)
  descriptor_list = type_map.values()
  descriptor_list.sort(compare_descriptor_types)
  return descriptor_list


class BatchProcessor(object):
  """Helper class for managing events in batch."""

  @property
  def project(self):
    return self.__project

  def __init__(self, project, stackdriver, data_list,
               invocation_factory, get_name):
    """Constructor.

    Args:
      data_list: [object] The data to operate on.
    """
    self.__project = project
    self.__stackdriver = stackdriver
    self.__data_list = data_list
    self.__num_data = len(self.__data_list)
    self.__invocation_factory = invocation_factory
    self.__get_name = get_name

    self.batch_response = [None] * self.__num_data
    self.num_bad = 0  # number of unsuccessful responses.
    self.num_ok = 0   # number of successful responses.
    self.was_ok = [None] * self.__num_data

  def handle_batch_response(self, index_str, response, exception):
    """Record an individual response.

    Args:
      index_str: [string] The index in the batch response corresponds to
         the index in the original query so the mapping is 1:1.
      response: [HttpResponse] The response from the request, which succeeded.
      exception: [Exception] The exception from the request, which failed.
    """
    index = int(index_str)
    if exception:
      self.was_ok[index] = False
      self.num_bad += 1
      self.batch_response[index] = 'ERROR {0}'.format(
          cgi.escape(str(exception)))
      logging.error(exception)
    else:
      self.was_ok[index] = True
      self.num_ok += 1
      self.batch_response[index] = 'OK {0}'.format(
          cgi.escape(str(response)))

  def process(self):
    """Process all the data by sending one or more batches."""
    batch = self.__stackdriver.stub.new_batch_http_request()
    max_batch = 100
    count = 0

    for data in self.__data_list:
      invocation = self.__invocation_factory(data)
      batch.add(invocation, callback=self.handle_batch_response,
                request_id=str(count))
      count += 1
      if count % max_batch == 0:
        decorator = ('final batch'
                     if count == len(self.__data_list)
                     else 'batch')
        logging.info('Executing %s of %d', decorator, max_batch)
        batch.execute()
        batch = self.__stackdriver.stub.new_batch_http_request()

    if count % max_batch:
      logging.info('Executing final batch of %d', count % max_batch)
      batch.execute()

  def make_response(self, request, as_html, action, title):
    """Create a response for the caller to ultimately send."""
    if as_html:
      html_rows = [('<tr><td>{0}</td><td>{1}</td></tr>\n'
                    .format(self.__get_name(self.__data_list[i]),
                            self.batch_response[i]))
                   for i in range(self.__num_data)]
      html_body = '{0} {1} of {2}:\n<table>\n{3}\n</table>'.format(
          action, self.num_ok, self.__num_data, '\n'.join(html_rows))
      html_doc = http_server.build_html_document(
          html_body, title=title)
      return {'ContentType': 'text/html'}, html_doc

    text = ['{0}  {1}'.format(self.__get_name(self.__data_list[i]),
                              self.batch_response[i])
            for i in range(self.__num_data)]
    text.append('')
    text.append('{0} {1} of {2}'.format(action, self.num_ok, self.__num_data))
    return {'ContentType': 'text/plain'}, '\n'.join(text)


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

  TAG_TYPE_MAP = {
      ''.__class__: 'STRING',
      True.__class__: 'BOOL',
      int(0).__class__: 'INT64'
  }

  NON_CUMULATIVE_KIND_MAP = {
      'GAUGE': 'GAUGE'
  }

  # Only recognize units stackdriver can handle.
  # Other units (e.g. "requests") will be ignored.
  UNIT_MAP = {
      'bytes': 'By',
      'nanoseconds': 'ns',
      'milliseconds': 'ms'
  }

  def init_state(self, options):
    """Helper function to initialize command state.

    We'll add additional state rather than passing params around.
    """
    # Return value
    self.lines = []

    # Maps custom descriptor types refreshed and by whom
    self.seen = {}

    # For getting service meter specifications.
    self.response_processor = ResponseProcessor(options)

    # Definition as currently known to stackdriver.
    self.descriptor_map = {
        elem['type']: elem for elem in get_descriptor_list(options)
    }

    self.stackdriver = stackdriver_service.make_service(options)
    self.name_prefix = ('projects/{project}/metricDescriptors/'
                        .format(project=self.stackdriver.project))

    self.warnings = 0
    self.errors = 0
    self.updates = 0
    self.new = 0

  def upsert_service(self, service):
    """Update (or insert) metric descriptors for the given service.

    Args:
      service: [string] The name of the service whose metrics to update.
    """
    rulebase = self.response_processor.determine_service_metric_transformer(
        service).rulebase

    for key, rule in rulebase.items():
      meter_name = rule.determine_meter_name(key)
      spec = rule.rule_specification
      meter_kind = spec.get('kind')
      want = {
          'metricKind': self.NON_CUMULATIVE_KIND_MAP.get(meter_kind,
                                                         'CUMULATIVE'),
          'valueType': 'DOUBLE',
          'labels': self.__derive_labels(spec),
          'description': spec.get('docs'),
      }
      unit = self.UNIT_MAP.get(spec.get('unit'))
      if unit:
        want['unit'] = unit

      variants = {}
      if meter_kind in ['Timer', 'PercentileTimer']:
        if not rule.discard_tag_value('statistic', 'count'):
          variants['__count'] = {
              'description': 'Number of measurements in {timer}.'.format(
                  timer='%s__totalTime' % meter_name)
          }
        if not rule.discard_tag_value('statistic', 'totalTime'):
          variants['__totalTime'] = {
              'unit': 'ns'
          }
      elif meter_kind in ['DistrbutionSummary',
                          'PercentileDistributionSummary']:
        if not rule.discard_tag_value('statistic', 'count'):
          variants['__count'] = {
              'description': 'Number of measurements in {summary}.'.format(
                  summary='%s__totalAmount' % meter_name)
          }
        if not rule.discard_tag_value('statistic', 'totalAmount'):
          variants['__totalAmount'] = {
          }

      if meter_kind.startswith('Percentile'):
        if not rule.discard_tag_value('statistic', 'percentile'):
          variants['__percentile'] = {
            'description':
                'Percentile bucket time referenced by {summary}.'.format(
                    summary='%s__count')
           }
      self.__do_upsert(meter_name, want, variants, service)

  def __do_upsert(self, meter_name, want, variants, service):
    if not variants:
      variants = {'': {}}

    for key, value in variants.items():
      refined_name = meter_name + key
      actual_type = 'custom.googleapis.com/spinnaker/%s' % refined_name
      actual_name = self.name_prefix + actual_type
      already_saw = self.seen.get(actual_type)

      actual_want = dict(want)
      actual_want.update(value)
      actual_want['type'] = actual_type
      actual_want['name'] = actual_name

      if not self.__diff_descriptor(service, actual_want):
        self.seen[actual_type] = service
        continue

      if already_saw:
        self.warnings += 1
        self.lines.append(
            'WARNING: {name} conflicts with {service}\n'
            '   want {want!r}\n'
            '   have {have!r}\n'
            .format(name=actual_name, service=service,
                    want=actual_want,
                    have=self.descriptor_map.get(actual_type)))
        continue

      is_new = actual_type not in self.descriptor_map
      action = 'Create' if is_new else 'Update'
      ok = self.stackdriver.replace_custom_metric_descriptor(
          actual_name, actual_want, new_descriptor=is_new)
      if ok:
        self.descriptor_map[actual_type] = actual_want
        self.updates += 1 if not is_new else 0
        self.new += 1 if is_new else 0
        status = 'OK'
      else:
        self.errors += 1
        status = 'FAILED'
      self.seen[actual_type] = service
      self.lines.append(
          '* {status}: {action} {name!r}: {value!r}'
          .format(status=status, action=action,
              name=actual_name, value=actual_want))

  def __diff_descriptor(self, service, want):
    descriptor = self.descriptor_map.get(want['type'])
    if not descriptor:
      self.lines.append('No known descriptor for %s' % want['type'])
      return True
    result = False
    for key, expect in want.items():
      value = descriptor.get(key)
      if isinstance(expect, list):
        expect = sorted(expect)
        if isinstance(value, list):
          value = sorted(value)
      if value != expect:
        logging.info('{service} expected {key!r} in {type!r}'
                     ' to be {expect!r} not {found!r}\n'
                     .format(service=service, key=key,
                             type=want['type'], expect=expect,
                             found=value))
        result = True
    return result

  def __derive_labels(self, spec):
    result = {'spin_service': 'STRING', 'spin_variant': 'STRING'}
    for name in spec.get('tags') or []:
      result[name] = 'STRING'
    for name, value in spec.get('add_tags', {}).items():
      result[name] = self.TAG_TYPE_MAP[value.__class__]
    for info in spec.get('transform_tags', []):
      to = info['to']
      to_type = info['type']
      if not isinstance(to, list):
        to = [to]
        to_type = [to_type]
      for index, name in enumerate(to):
        result[name] = {'INT': 'INT64'}.get(to_type[index],
                                            to_type[index])

    if spec.get('per_account', False) and 'account' in result:
      del(result['account'])
    if spec.get('per_application', False) and 'application' in result:
      del(result['application'])

    normalized_result = []
    for key, valueType in result.items():
      label_descriptor = {'key': key}
      if valueType != 'STRING':
        label_descriptor['valueType'] = valueType
      normalized_result.append(label_descriptor)
    return sorted(normalized_result)

  def process_commandline_request(self, options):
    """Implements CommandHandler."""
    self.init_state(options)
    for service in self.SERVICE_LIST:
      self.upsert_service(service)

    unused = 0
    for key in self.descriptor_map.keys():
      if not key in self.seen:
        self.lines.append('Existing descriptor %r is no longer used.' % key)
        unused += 1

    self.lines.extend(['TOTALS:',
                       '  New Descriptors: %d' % self.new,
                       '  Updated Descriptors: %d' % self.updates])
    if unused:
      self.lines.append('  Unused Descriptors: %d' % unused)
    if self.warnings:
      self.lines.append('  Warnings: %d' % self.warnings)

    self.output(options, '\n'.join(self.lines))
    if self.errors:
      raise ValueError('Encountered %d errors' % self.errors)


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

    if self.accepts_content_type(request, 'text/html'):
      html = self.descriptors_to_html(descriptor_list)
      html_doc = http_server.build_html_document(
          html, title='Custom Descriptors')
      request.respond(200, {'ContentType': 'text/html'}, html_doc)
    elif self.accepts_content_type(request, 'application/json'):
      json_doc = json.JSONEncoder(indent=2).encode(descriptor_list)
      request.respond(200, {'ContentType': 'application/json'}, json_doc)
    else:
      text = self.descriptors_to_text(descriptor_list)
      request.respond(200, {'ContentType': 'text/plain'}, text)

  def collect_rows(self, descriptor_list):
    rows = []
    for elem in descriptor_list:
      type_name = elem['type'][len(StackdriverMetricsService.CUSTOM_PREFIX):]
      labels = elem.get('labels', [])
      label_names = [k['key'] for k in labels]
      rows.append((type_name, label_names))
    return rows

  def descriptors_to_html(self, descriptor_list):
    rows = self.collect_rows(descriptor_list)

    html = ['<table>', '<tr><th>Custom Type</th><th>Labels</th></tr>']
    html.extend(['<tr><td><b>{0}</b></td><td><code>{1}</code></td></tr>'
                 .format(row[0], ', '.join(row[1]))
                 for row in rows])
    html.append('</table>')
    html.append('<p>Found {0} Custom Metrics</p>'
                .format(len(descriptor_list)))
    return '\n'.join(html)

  def descriptors_to_text(self, descriptor_list):
    rows = self.collect_rows(descriptor_list)

    text = []
    for row in rows:
      text.append('{0}\n  Tags={1}'.format(row[0], ','.join(row[1])))
    text.append('Found {0} Custom Metrics'.format(len(descriptor_list)))
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


class AuditCustomDescriptorsHandler(BaseStackdriverCommandHandler):
  """Administrative handler to distinguish in-use from unused descriptors."""

  def delete_unused(self, options, surveyor, survey):
    descriptor_name_prefix = 'projects/{project}/metricDescriptors/'.format(
        project=surveyor.project)
    to_delete = []
    for info in survey.values():
      if info.days_ago == info.UNKNOWN_DAYS_AGO:
        to_delete.append({'name': descriptor_name_prefix + info.type_name,
                          'type': info.type_name})

    processor = ClearCustomDescriptorsHandler.clear_descriptors(
        options, to_delete)
    batch_response = processor.batch_response
    for index, response in enumerate(batch_response):
      type_name = to_delete[index]['type']
      # The response and 'OK' here are our own batch response strings,
      # not the original http response from the server.
      if response.startswith('OK'):
        survey[type_name] = SurveyInfo.make_deleted(type_name)
      else:
        survey[type_name] = SurveyInfo.make_error(type_name, response)

  def add_argparser(self, subparsers):
    parser = super(AuditCustomDescriptorsHandler, self).add_argparser(
        subparsers)
    parser.add_argument('--delete_unused', default=False, action='store_true',
                        help='Delete the unused spinnaker metric descriptors.')
    parser.add_argument('--days_since', default=1, type=int,
                        help='How many days back to look for metric activity.')

  def process_commandline_request(self, options):
    surveyor = StackdriverSurveyor(options)
    descriptor_list = get_descriptor_list(options)
    survey = surveyor.build_survey_from_descriptor_list(descriptor_list)
    if str(options.get('delete_unused')).lower() == 'true':
      self.delete_unused(options, surveyor, survey)
    info_list = surveyor.survey_to_sorted_list(survey)
    json_text = json.JSONEncoder(indent=2).encode(info_list)
    self.output(options, json_text)

  def process_web_request(self, request, path, params, fragment):
    options = dict(get_global_options())
    options.update(params)

    surveyor = StackdriverSurveyor(options)
    descriptor_list = get_descriptor_list(options)

    begin_time = time.time()
    survey = surveyor.build_survey_from_descriptor_list(descriptor_list)
    survey_secs = time.time() - begin_time
    if str(params.get('delete_unused')).lower() == 'true':
      self.delete_unused(options, surveyor, survey)
    info_list = surveyor.survey_to_sorted_list(survey)

    footer = 'Survey Time = %.1f s' % survey_secs
    header = 'Activity during %s ... %s (%s)' % (
        surveyor.start_time, surveyor.end_time,
        SurveyInfo.to_days_since(surveyor.days_since))

    if self.accepts_content_type(request, 'text/html'):
      html = header + '<p>'
      html += self.survey_to_html(surveyor, info_list)
      html += '<br/>' + footer
      html_doc = http_server.build_html_document(
          html, title='Last Custom Descriptor Use')
      request.respond(200, {'ContentType': 'text/html'}, html_doc)
    elif self.accepts_content_type(request, 'application/json'):
      json_doc = json.JSONEncoder(indent=2).encode(info_list)
      request.respond(200, {'ContentType': 'application/json'}, json_doc)
    else:
      text = self.survey_to_text(info_list)
      text += '\n\n' + footer
      request.respond(200, {'ContentType': 'text/plain'}, text)

  def survey_to_html(self, surveyor, info_list):
    survey_html = ['<table><tr>'
                   '<th>Last Time</th>'
                   '<th>Days</th>'
                   '<th>Type Name</th></tr>']
    num_ok = 0
    num_warning = 0
    num_deleted = 0
    num_error = 0

    for info in info_list:
      literal_str = info.iso_time if info.iso_time else ''
      if info.deleted:
        literal_str = 'DELETED'
        css = 'deleted'
        num_deleted += 1
      elif info.error:
        literal_str = info.error
        css = 'error'
        num_error += 1
      elif info.iso_time:
        css = 'ok'
        num_ok += 1
      else:
        css = 'warning'
        num_warning += 1

      survey_html.append(
          '<tr><td{css}>{literal}</td>'
          '<td{css}>{days}</td>'
          '<td{css}>{what}</td></tr>'.format(
              css=' class="%s"' % css,
              literal=literal_str,
              days=info.days_ago_str(),
              what=info.type_name))
    survey_html.append('</table>\n')

    # pylint: disable=bad-whitespace
    table = [('In Use',     'ok',      num_ok),
             ('Not In Use', 'warning', num_warning),
             ('Deleted',    'deleted', num_deleted),
             ('Error',      'error',   num_error)]
    html = textwrap.dedent("""\
       <h2>Summary</h2>
       <table>
       {summary}
       <tr><th>Total</th><td>{total}</td></tr>
       </table>
       <h2>Survey</h2>
       {survey}
    """.format(
        summary='\n'.join(
            ['<tr><th>{title}</th><td class={css}>{count}</td></tr>'
             .format(title=elem[0], css=elem[1], count=elem[2])
             for elem in table if elem[2] > 0]),
        total=num_ok + num_warning + num_deleted + num_error,
        survey='\n'.join(survey_html)))
    return html

  def survey_to_text(self, info_list):
    text = ['Found {0} Custom Metrics'.format(len(info_list))]
    for info in info_list:
      when = ('DELETED'
              if info.deleted
              else info.error if info.error
              else info.iso_time)
      text.append('{when}: {what}'.format(when=when, what=info.type_name))
    return '\n\n'.join(text)


class ClearCustomDescriptorsHandler(BaseStackdriverCommandHandler):
  """Administrative handler to clear all the known descriptors.

  This clears all the TimeSeries history as well.
  """

  @staticmethod
  def clear_descriptors(options, descriptor_list):
    stackdriver = stackdriver_service.make_service(options)
    project = stackdriver.project
    delete_method = (stackdriver.stub.projects().metricDescriptors().delete)
    def delete_invocation(descriptor):
      name = descriptor['name']
      logging.info('batch DELETE %s', name)
      return delete_method(name=name)
    get_descriptor_name = lambda descriptor: descriptor['name']

    processor = BatchProcessor(
        project, stackdriver,
        descriptor_list, delete_invocation, get_descriptor_name)
    processor.process()
    return processor

  def __do_clear(self, options):
    """Deletes exsiting custom metric descriptors."""
    descriptor_list = get_descriptor_list(options)
    return descriptor_list, self.clear_descriptors(options, descriptor_list)

  def process_commandline_request(self, options):
    """Implements CommandHandler."""
    copy_options = dict(options)
    copy_options['clear_all'] = True
    _, processor = self.__do_clear(copy_options)
    headers, body = processor.make_response(
        None, False,
        'Deleted', 'Cleared Time Series')
    self.output(options, body)

  def process_web_request(self, request, path, params, fragment):
    """Implements CommandHandler."""
    if str(params.get('clear_all')).lower() != 'true':
      html = textwrap.dedent("""\
          Clearing descriptors requires query parameter
          <code>clear_all=true</code>.
          <p/>
          <a href="{path}?clear_all=true">Yes, delete everything!</a>
      """.format(path=path))
      html_doc = http_server.build_html_document(
          html, title='Missing Parameters')
      request.respond(
          400, {'ContentType': 'text/html'}, html_doc)
      return

    options = dict(get_global_options())
    options.update(params)
    descriptor_list, processor = self.__do_clear(options)
    response_code = (httplib.OK if processor.num_ok == len(descriptor_list)
                     else httplib.INTERNAL_SERVER_ERROR)
    headers, body = processor.make_response(
        request, self.accepts_content_type(request, 'text/html'),
        'Deleted', 'Cleared Time Series')
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
      specification = json.JSONDecoder().decode(infile.read())

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
      AuditCustomDescriptorsHandler(
          '/stackdriver/audit_descriptors',
          'audit_stackdriver',
          'Determine which stackdriver descriptors are in use.'),
      ClearCustomDescriptorsHandler(
          '/stackdriver/clear_descriptors',
          'clear_stackdriver',
          'Clear all the Stackdriver Custom Metrics'),
      UpsertCustomDescriptorsHandler(
          None,
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
