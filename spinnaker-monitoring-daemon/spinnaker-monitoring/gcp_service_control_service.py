# Copyright 2019 Google Inc. All Rights Reserved.
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

import logging
import time

import spectator_client
import google_service

try:
  from googleapiclient.errors import HttpError
  GCP_SERVICE_CONTROL_AVAILABLE = True
except ImportError:
  GCP_SERVICE_CONTROL_AVAILABLE = False


class GcpServiceControlService(google_service.GoogleMonitoringService):
  """Helper class for interacting with Stackdriver."""
  SERVICE_SCOPE = 'https://www.googleapis.com/auth/servicecontrol'
  SERVICE_KEY = 'gcp_service_control'
  SERVICE_NAME = 'servicecontrol'
  SERVICE_VERSION = 'v1'

  def __init__(self, stub_factory, options):
    """Constructor.

    Args:
      stub_factory: [callable that creates stub for stackdriver]
          This is passed as a callable to defer initialization because
          we create the handlers before we process commandline args.
    """
    super(GcpServiceControlService, self).__init__(
        stub_factory, options)
    self.__consumer_id = google_service.determine_local_project()

  def publish_metrics(self, service_metrics):
    self._update_monitored_resources(service_metrics)

    operation_map = {}
    spectator_client.foreach_metric_in_service_map(
        service_metrics, self.add_metric_operation, operation_map)

    total_count = 0
    try:
      (self.stub.services().report(
          name=self.project_to_resource(self.project),
          body={'operations': operation_map.values()})
       .execute())
      for service, operation in operation_map.items():
        total_count += len(operation.get('metricValueSets', []))
    except HttpError as err:
        logging.error(err)

    return total_count

  def add_metric_operation(self, service, name, instance,
                           metric_metadata, service_metadata, operation_map):
    data_list = [
        google_service.GoogleMeasurementData.make_from_measurement(
            self, service_metadata, metric_metadata, measurement)
        for measurement in instance['values']
    ]
    if not data_list:
      return

    name, tags = self.spectator_helper.normalize_name_and_tags(
        service, name, instance, metric_metadata)
    labels = {tag['key']: tag['value'] for tag in tags}

    value_list = []
    for data in data_list:
      metric_value = dict(data.valueData)
      if labels:
        metric_value['labels'] = labels
      metric_value['startTime'] = data.startTime,
      metric_value['endTime'] = data.endTime
      value_list.append(metric_value)

    operation = operation_map.get(service)
    if operation is None:
      # This is the first metric for this service 
      # so we need to create an operation. The operation
      # will have a metric value set containing each metric,
      # including this first one.
      monitored_resource = self.get_monitored_resource(service, service_metadata)
      operation = {
          'operationName': 'spinnaker-monitoring-daemon-aggregate-dump',
          'consumerId': self.__consumer_id,
          'startTime': self.millis_to_time(service_metadata['startTime']),
          'endTime': self.millis_to_time(service_metadata['__collectEndTime']),
          'labels': monitored_resource['labels'],
          'metricValueSets': []
      }
      operation_map[service] = operation

    # Add this metric to the operation's value set,
    # including if this is the first one.
    value_sets = operation['metricValueSets']
    value_sets.append({
        'metricName': name,
        'metricValues': value_list
    })



class ReportRequest(object):
  @property
  def labels(self):
    return __labels
  @property
  def start_time(self):
    return self.__start_time
  @property
  def end_time(self):
    return self.__end_time
  @property
  def metrics(self):
    return [{"metricName": key, "metricValues": values}
            for key, values in self.__metrics.items()]

  def __init__(self, start_time, end_time, labels):
      self.__start_time = start_time
      self.__end_time = end_time
      self.__labels = labels
      self.__metrics = {}

class GcpServiceControlServiceFactory(
    google_service.GoogleMonitoringServiceFactory):
  SERVICE_CLASS = GcpServiceControlService

  def add_argparser(self, parser):
    """Implements server_handlers.MonitorCommandHandler interface."""
    parser.add_argument(
        '--gcp_service_control', default=False, action='store_true',
        dest='monitor_gcp_service_control',
        help='Publish metrics to GCP Service Control.')
