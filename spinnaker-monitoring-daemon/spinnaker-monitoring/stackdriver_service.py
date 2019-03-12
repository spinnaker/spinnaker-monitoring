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
import copy
import json
import logging
import re
import time
import traceback

import google_service
import spectator_client
import stackdriver_descriptors
import httplib2

try:
  from urllib2 import (
      Request as urllibRequest,
      urlopen as urllibUrlopen)

except ImportError:
  from urllib.request import (
      Request as urllibRequest,
      urlopen as urllibUrlopen)

try:
  from googleapiclient.errors import HttpError
  STACKDRIVER_AVAILABLE = True
except ImportError:
  STACKDRIVER_AVAILABLE = False


class StackdriverMetricsService(google_service.GoogleMonitoringService):
  """Helper class for interacting with Stackdriver."""
  SERVICE_SCOPE = 'https://www.googleapis.com/auth/monitoring'
  SERVICE_KEY = 'stackdriver'
  SERVICE_NAME = 'monitoring'
  SERVICE_VERSION = 'v3'

  MAX_BATCH = 200
  JANITOR_PERIOD = 600

  @property
  def stackdriver_options(self):
    return self.service_options

  @property
  def descriptor_manager(self):
    """Return MetricDescriptorManager."""
    return self.__descriptor_manager

  def __init__(self, stub_factory, options):
    """Constructor.

    Args:
      stub_factory: [callable that creates stub for stackdriver]
          This is passed as a callable to defer initialization because
          we create the handlers before we process commandline args.
    """
    super(StackdriverMetricsService, self).__init__(
        stub_factory, options)

    # The janitor prepares metric descriptors before first write.
    self.__janitor_func = lambda: self.__auto_audit_metric_descriptors()
    self.__next_janitor_time = time.time()
    self.__good_janitor_count = 0

    self.__distributions_also_have_count = self.service_options.get(
        'distributions_also_have_count')
    self.__fix_custom_metrics_unsafe = self.service_options.get(
        'fix_custom_metrics_unsafe', False)
    self.__log_400_data = self.service_options.get('log_400_data', False)

    manager_options = dict(options)
    manager_options['spectator'] = self.spectator_helper.options
    manager = stackdriver_descriptors.MetricDescriptorManager(
        self, spectator_client.ResponseProcessor(manager_options))
    self.__descriptor_manager = manager

  @staticmethod
  def add_parser_arguments(parser):
    """Add arguments for configuring stackdriver."""
    parser.add_argument('--project', default='')
    parser.add_argument('--zone', default='')
    parser.add_argument('--instance_id', default=0, type=int)
    parser.add_argument('--credentials_path', default=None)
    parser.add_argument(
        '--stackdriver_generic_task_resources',
        default=False,
        action='store_true',
        help='Use stackdriver "generic_task" monitored resources'
        ' rather than the container or VM.')
    parser.add_argument(
        '--manage_stackdriver_descriptors',
        choices=['none', 'full', 'create', 'delete'],
        help='Specifies how to maintain stackdriver descriptors on startup.'
             '\n  none: Do nothing.'
             '\n  create: Only create new descriptors seen in the'
             ' metric filter default.yml'
             '\n  delete: Only delete existing descriptors no longer'
             ' mentioned in filter default.yml'
             '\n  full: Both create and delete.')


  def __auto_audit_metric_descriptors(self):
    """The janitor function attempts to bring Stackdriver into compliance.

    If the metric descriptors are already as expected then we'll disable
    the janitor for the rest of the process' lifetime. Otherwise we'll
    continue to call it and try again around every JANITOR_PERIOD seconds
    to give time for the system to settle down.

    The reason we expect to have problems is that old replicas are still
    running and recreating the descriptors we are trying to delete when
    stackdriver automatically creates metrics they are attempting to write.
    If this is the case, we'll keep trying to clear them out until, eventually,
    the old processes are no longer around to overwrite us.

    Should something re-emerge then we'll be messed up until the next restart.
    Note that each replica of each service is probably trying to create all
    the descriptors so there is a lot of activity here. Since the descriptors
    are all the same, there should not be a problem with these replicas
    conflicting or needing coordination.

    Note if management is disabled then this will be in a stable state
    though still inconsistent with stackdriver because there will not
    be any errors or activity performed.
    """
    secs_remaining = self.__next_janitor_time - time.time()
    if secs_remaining > 0:
      logging.debug('Janitor skipping audit for at least another %d secs',
                    secs_remaining)
      return

    logging.info('Janitor auditing metric descriptors...')
    scoped_options = {'stackdriver': self.service_options}
    audit_results = self.descriptor_manager.audit_descriptors(scoped_options)
    stable = (audit_results.errors == 0
              and audit_results.num_fixed_issues == 0)
    now = time.time()
    self.__next_janitor_time = now + self.JANITOR_PERIOD

    if stable:
      self.__good_janitor_count += 1
      if self.__good_janitor_count > 1:
        logging.info('Metric descriptors appear stable. Disabling janitor.')
        self.__janitor_func = lambda: None
      else:
        logging.info('Keeping janitor around to build confidence.')
    else:
      self.__good_janitor_count = 0
      logging.debug('Metric descriptors are not yet stable.'
                    ' There may be some errors writing metrics.'
                    ' Check again in %d secs.',
                    self.JANITOR_PERIOD)

  def add_metric_to_timeseries(self, service, name, instance,
                               metric_metadata, service_metadata, result):
    data_list = [
        google_service.GoogleMeasurementData.make_from_measurement(
            self, service_metadata, metric_metadata, measurement)
        for measurement in instance['values']
    ]
    if not data_list:
      return

    sample = data_list[0]
    points = [{'interval': {'endTime': data.endTime}, 'value': data.valueData}
              for data in data_list]
    if sample.metricKind == 'CUMULATIVE':
      for elem in points:
        elem['interval']['startTime'] = sample.startTime

    name, tags = self.spectator_helper.normalize_name_and_tags(
        service, name, instance, metric_metadata)
    metric = {
        'type': self.descriptor_manager.name_to_type(name),
        'labels': {tag['key']: tag['value'] for tag in tags}
    }
    monitored_resource = self.get_monitored_resource(service, service_metadata)


    if (sample.valueType == 'DISTRIBUTION'
        and self.__distributions_also_have_count):
      # Add an implied metric which is just a counter.
      # This is to workaround a temporary shortcoming querying the counts.
      # Eventually this will be deprecated.
      counter_points = copy.deepcopy(points)
      for elem in counter_points:
        elem['value'] = {
            'int64Value': int(sample.valueData['distributionValue']['count'])
        }

      counter_metric = copy.deepcopy(metric)
      counter_metric['type'] = self.__descriptor_manager.distribution_to_counter(
          counter_metric['type'])
      result.append({
          'metric': counter_metric,
          'resource': monitored_resource,
          'metricKind': 'CUMULATIVE',
          'valueType': 'INT64',
          'points': counter_points})

    result.append({
        'metric': metric,
        'resource': monitored_resource,
        'metricKind': sample.metricKind,
        'valueType': sample.valueType,
        'points': points})

  def publish_metrics(self, service_metrics):
    self.__janitor_func()

    time_series = []
    self._update_monitored_resources(service_metrics)
    spectator_client.foreach_metric_in_service_map(
        service_metrics, self.add_metric_to_timeseries, time_series)
    offset = 0
    method = self.stub.projects().timeSeries().create

    while offset < len(time_series):
      last = min(offset + self.MAX_BATCH, len(time_series))
      chunk = time_series[offset:last]
      try:
        (method(name=self.project_to_resource(self.project),
                body={'timeSeries': chunk})
         .execute())
      except HttpError as err:
        self.handle_time_series_http_error(err, chunk)
      offset = last
    return len(time_series)

  def find_problematic_elements(self, error, batch):
    try:
      content = json.JSONDecoder().decode(error.content.decode('utf-8'))
      message = content['error']['message']
    except KeyError:
      return []

    if self.__log_400_data:
      time_series_index_pattern = r'timeSeries\[(\d+?)\]'
      log_count = 0
      for match in re.finditer(time_series_index_pattern, message):
        ts_index = int(match.group(1))
        log_count += 1
        if log_count > 3:
          break
        logging.info('timeSeries[%d] -> %r', ts_index,batch[ts_index])

      time_series_range_pattern = r'timeSeries\[(\d+?)\-(\d+?)\]'
      for match in re.finditer(time_series_range_pattern, message):
        ts_start_index = int(match.group(1))
        ts_end_index = int(match.group(2))
        text = []
        for index in range(ts_start_index, ts_end_index):
          text.append('[%d] -> %r' % (index, batch[index]))
        logging.info('\n%s', '\n'.join(text))
        break
      

    found = []
    counter_to_gauge_pattern = (
        r'timeSeries\[(\d+?)\]\.metricKind'
        r' had an invalid value of \"(CUMULATIVE|GAUGE)\"'
        r'.* must be (CUMULATIVE|GAUGE).')
    for match in re.finditer(counter_to_gauge_pattern, message):
      ts_index = int(match.group(1))
      metric = batch[ts_index]['metric']
      metric_type = metric['type']
      found.append((self.delete_descriptor_and_retry,
                    metric_type, batch[ts_index]))

    return found

  def delete_descriptor_and_retry(self, metric_type, ts_request):
    metric_name_param = '/'.join([
        self.project_to_resource(self.project),
        'metricDescriptors', metric_type])
    api = self.stub.projects().metricDescriptors()

    try:
      logging.info('Deleting existing descriptor %s', metric_name_param)
      response = api.delete(name=metric_name_param).execute()
      logging.info('Delete response: %s', repr(response))
    except HttpError as err:
      logging.error('Could not delete descriptor %s', err)
      if err.resp.status != 404:
        return
      else:
        logging.info("Ignore error.")

    logging.info('Retrying create timeseries %s', ts_request)
    (self.stub.projects().timeSeries().create(
        name=self.project_to_resource(self.project),
        body={'timeSeries': ts_request})
     .execute())

  def handle_time_series_http_error(self, error, batch):
    logging.error('Caught %s', error)

    if error.resp.status == 400:
      problems = self.find_problematic_elements(error, batch)
      logging.info('PROBLEMS %r', problems)
      if problems and not self.__fix_custom_metrics_unsafe:
        logging.info(
            'Fixing this problem would wipe stackdriver data.'
            ' Doing so was not enabled. To enable, add:\n\n'
            'stackdriver:\n  fix_custom_metrics_unsafe: true\n'
            'to your spinnaker-monitoring-local.yml')
      elif problems:
        logging.info('Attempting to fix these problems. This may lose'
                     ' stackdriver data for these metrics.')
        for elem in problems:
          try:
            elem[0](*elem[1:])
          except BaseException as bex:
            traceback.print_exc()
            logging.error('Failed %s(%s): %s', elem[0], elem[1:], bex)


class StackdriverServiceFactory(google_service.GoogleMonitoringServiceFactory):
  SERVICE_CLASS = StackdriverMetricsService

  def add_argparser(self, parser):
    """Implements server_handlers.MonitorCommandHandler interface."""
    StackdriverMetricsService.add_parser_arguments(parser)
    parser.add_argument('--stackdriver', default=False, action='store_true',
                        dest='monitor_stackdriver',
                        help='Publish metrics to Stackdriver.')

    parser.add_argument(
        '--fix_stackdriver_labels_unsafe', default=True,
        action='store_true', help='DEPRECATED')
    parser.add_argument(
        '--nofix_stackdriver_labels_unsafe',
        dest='fix_stackdriver_labels_unsafe',
        action='store_false', help='DEPRECATED')


def make_service(options, factory=StackdriverServiceFactory):
  return factory()(options, None)
