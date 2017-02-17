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

"""Implements metric service for interacting with Datadog."""


# pip install datadog
import logging
import os
import re
import socket
import datadog

import spectator_client


class DatadogMetricsService(object):
  """A metrics service for interacting with Datadog."""

  @property
  def api(self):
    """The Datadog API stub for interacting with Datadog."""
    if self.__api is None:
      datadog.initialize(api_key=self.__api_key, app_key=self.__app_key,
                         host_name=self.__host)
      self.__api = datadog.api
    return self.__api


  def __init__(self, api_key, app_key, host=None):
    """Constructs the object."""
    self.__api = None
    self.__host = host
    self.__api_key = api_key
    self.__app_key = app_key

  def __append_timeseries_point(
        self, service, name,
        instance, metric_metadata, service_metadata, result):
    """Creates a post payload for a DataDog time series data point.

       See http://docs.datadoghq.com/api/?lang=python#metrics-post.

    Args:
      service: [string] The name of the service that the metric is from.
      name: [string] The name of the metric coming from the service.
      instance: [dict] The spectator entry for a specific metric value
         for a specific tag binding instance that we're going to append.
      metric_metadata: [dict] The spectator JSON object for the metric
         is used to get the kind and possibly other metadata.
      result: [list] The result list to append all the time series messages to.
    """
    # In practice this converts a Spinnaker Timer into either
    # <name>__count or <name>__totalTime and removes the "statistic" tag.
    name, tags = spectator_client.normalize_name_and_tags(
        name, instance, metric_metadata)
    if tags is None:
      return  # ignore metrics that had no tags because these are bogus.

    result.append({
        'metric': '{service}.{name}'.format(service=service, name=name),
        'host': service_metadata['__host'],
        'points': [(elem['t'] / 1000, elem['v'])
                   for elem in instance['values']],
        'tags': ['{0}:{1}'.format(tag['key'], tag['value']) for tag in tags]
    })

  def publish_metrics(self, service_metrics):
    """Writes time series data to Datadog for a metric snapshot."""
    points = []
    spectator_client.foreach_metric_in_service_map(
        service_metrics, self.__append_timeseries_point, points)

    try:
      if points:
        self.api.Metric.send(points)
    except IOError as ioerr:
      logging.error('Error sending to datadog: %s', ioerr)
      raise

    return len(points)


def make_datadog_service(options):
  def read_param(param_name, config_text):
    """Read configuration parameter from Datadog config_text."""
    match = re.search('^{0}:(.*)$'.format(param_name),
                      config_text, re.MULTILINE)
    if not match:
      return None

    return match.group(1).strip()

  app_key = None
  api_key = None
  host = None
  config_path = options['dd_agent_config']

  try:
    with open(config_path, 'r') as stream:
      logging.info('Reading Datadog config from %s', config_path)
      text = stream.read()
      app_key = read_param('app_key', text)
      api_key = read_param('api_key', text)
      host = read_param('hostname', text)

  # pylint: disable=bare-except
  except:
    logging.warning('Could not read config from "%s"', config_path)

  api_key = api_key or os.environ.get('DATADOG_API_KEY')
  if api_key is None:
    raise ValueError('DATADOG_API_KEY is not defined')

  app_key = app_key or os.environ.get('DATADOG_APP_KEY')
  host = host or socket.getfqdn(options['datadog_host'] or '')

  return DatadogMetricsService(api_key=api_key, app_key=app_key, host=host)


def add_standard_parser_arguments(parser):
  """Adds common arguments for all Datadog operations."""
  parser.add_argument(
      '--datadog_host', default='', required=False,
      help='Specify the host to report back to datadog with.'
           ' The default will be the hostname in the --dd_agent_config file'
           ' or localhost if not found. This will be resolved to a fqdn.')

  parser.add_argument(
      '--dd_agent_config', default='/etc/dd-agent/datadog.conf',
      help='Path to datadog agent config file (to read keys from).'
           ' This is not user-readable so you may need to use environment'
           ' variables for DATADOG_API_KEY and DATADOG_APP_KEY instead.')


class DatadogServiceFactory(object):
  """For plugging Datadog into the monitoring server."""
  def enabled(self, options):
    """Implements server_handlers.MonitorCommandHandler interface."""
    return options.get('datadog', False)

  def add_argparser(self, parser):
    """Implements server_handlers.MonitorCommandHandler interface."""
    parser.add_argument('--datadog', default=False, action='store_true',
                        help='Publish metrics to Datadog.')

    add_standard_parser_arguments(parser)

  def __call__(self, options, command_handlers):
    """Create a datadog service instance for interacting with Datadog."""
    return make_datadog_service(options)
