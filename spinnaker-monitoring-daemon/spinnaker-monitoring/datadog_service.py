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
import socket

try:
  from ConfigParser import ConfigParser
except ImportError:
  from configparser import ConfigParser

try:
  import datadog
  datadog_available = True
except ImportError:
  datadog_available = False

import spectator_client

class DatadogArgumentsGenerator(object):
  """
  Generates the correct Datadog parameters to pass in to
  DatadogMetricsService from the slew of options passed in.
  """

  def __init__(self, options):

    self.options = options

    assert 'datadog' in self.options, \
      'Key "datadog" is mandatory in supplied options'
    assert 'dd_agent_config' in self.options, \
      'Key "dd_agent_config" is mandatory in supplied options'

    self.datadog_config = ConfigParser()
    self.datadog_config.read(options['dd_agent_config'])

    if not self.datadog_config.sections():
      logging.warn('Could not read config from datadog: {}'
                   .format(options['dd_agent_config']))

  def generate_arguments(self):

    required_options = {
      'api_key': self.__resolve_value(identifier='Datadog API key',
                                      key='api_key'),
    }

    nonessential_options = {

      # we only need Datadog write access, for which an api key is
      # sufficient, hence this is not required
      'app_key': self.__resolve_value(identifier='Datadog app key',
                                      key='app_key', required=False),

      'tags': self.__convert_to_list_of_strings(
                self.__resolve_value(identifier='Datadog static tags',
                                     key='tags',
                                     required=False
                                     )
              ),

      'host': socket.getfqdn(
                self.__resolve_value(identifier='host',
                                     key='host',
                                     required=False) or
                self.__lookup_in_agent_config('hostname') or
                ''
              ),
    }

    required_options.update(nonessential_options)

    return required_options

  def __contains_value(self, key, dictionary):
    return key in dictionary and dictionary[key] is not None

  def __resolve_value(self, identifier, key, required=True):
    """
    Resolve to a value set in either an environment variable,
    in the outer section of spinnaker-monitoring.yml, within the
    datadog field of spinnaker-monitoring.yml, in the datadog
    agent configuration file, all in that order, or error out.
    Whichever source provides a non-None value first wins.

    Order of lookup is as as follows:

    1. Check for string 'DATADOG_%s' % key.toupper() as
       environment variable.
    2. Check for string 'datadog_%s' % key in the
       spinnaker-monitoring.yaml.
    3. Check for key as just '%s' % key in the datadog
       section in the spinnaker-monitoring.yaml
    4. Check for key as just '%s' % key in the Datadog
       agent configuration.

    If, after this, `required` is False, don't throw an error
    but return None instead.

    Parameter:
      identifier: String. If value could not be found,
                  use this parameter in the error message
                  to refer to what you were actually trying to find.
      key: String. Look for this key.
      required: Bool. If the value is not required and
                could not be found, return None.
    """

    environment_key = 'DATADOG_{0}'.format(key.upper())
    yaml_key = 'datadog_{0}'.format(key)

    # check if value is set as an environment variable
    if self.__contains_value(environment_key, os.environ):
      return os.environ[environment_key]

    # check if value is set in spinnaker-monitoring.yml as a high-level key
    if self.__contains_value(yaml_key, self.options):
      return self.options[yaml_key]

    # check if value is set in spinnaker-monitoring.yml as a key under the datadog
    # section.
    if self.__contains_value(key, self.options['datadog']):
      return self.options['datadog'][key]

    # check finally if value is set in Datadog agent configuration.
    configuration_value = self.__lookup_in_agent_config(key)
    if configuration_value is not None:
      return configuration_value

    if not required:
      return None

    raise ValueError('{0} could not be found as environment '
                     'variable {1}, or read from spinnaker-monitoring.yml file as '
                     '{2} as an outer value, or found as {3} under section datadog '
                     'and could not be read from datadog agent configuration using'
                     'key {3}'
                     .format(identifier, environment_key, yaml_key, key)
                     )

  def __convert_to_list_of_strings(self, argument, default=None):
    """
    This function takes a parameter and attempts
    to convert it to a list of strings
    if it looks like a list of strings.

    Parameter should look like
    https://github.com/DataDog/dd-agent/blob/master/datadog.conf.example#L37
    to be correctly parsed.

    Otherwise return default. """

    if isinstance(argument, str):
      argument = [str(item) for item in argument.replace(' ', '').split(',')]

    # if, despite everything, we could not parse as list of strings, give up.
    if not (isinstance(argument, list) and all(isinstance(item, str) for item in argument)):
      logging.debug('Argument {0} was not parsable as a list.'
                    'Returning as supplied default value.'.format(argument))
      return default or []

    return argument

  def __lookup_in_agent_config(self, key):
    """ Look for a value in the Datadog agent configuration """

    for section in self.datadog_config.sections():
      if self.datadog_config.has_option(section, key):
        return self.datadog_config.get(section, key)

    return None

class DatadogMetricsService(object):
  """A metrics service for interacting with Datadog."""

  # 20170218(ewiseblatt)
  # I dont know the actual limit.
  # This is a guess while I wait to hear back from datadog support.
  # Large deployments for clouddriver are seeing 413, but nothing else.
  # I've sent batches larger than this that have been fine.
  MAX_BATCH = 2000

  @property
  def api(self):
    """The Datadog API stub for interacting with Datadog."""
    if self.__api is None:
      datadog.initialize(api_key=self.__arguments['api_key'],
                         app_key=self.__arguments['app_key'],
                         host_name=self.__arguments['host'])
      self.__api = datadog.api
    return self.__api


  def __init__(self, options, spectator_helper, **arguments):
    """Constructs the object."""
    if not datadog_available:
      raise ImportError(
          'You must "pip install datadog" to get the datadog client library.')
    self.__spectator_helper = spectator_helper
    self.__api = None
    self.__arguments = arguments
    self.__use_types = options.get('datadog', {}).get('use_types')

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
    name, tags = self.__spectator_helper.normalize_name_and_tags(
        service, name, instance, metric_metadata)

    if tags is None and not self.__arguments['tags']:
      return  # ignore metrics that had no tags because these are bogus.

    # counters, timers, distribution summaries, etc are counters.
    # only "Gauge" is a gauge.
    if self.__use_types:
      primitive_kind = self.__spectator_helper.determine_primitive_kind(
          metric_metadata['kind'])
      metric_type = ('gauge'
                     if primitive_kind == spectator_client.GAUGE_PRIMITIVE_KIND
                     else 'count')
    else:
      metric_type = 'gauge'

    name = name.replace('/', '.')
    result.append({
        'metric': '{service}.{name}'.format(service=service, name=name),
        'host': service_metadata['__host'],
        'type': metric_type,
        'points': [(elem['t'] / 1000, elem['v'])
                   for elem in instance['values']],
        'tags': (['{0}:{1}'.format(tag['key'], tag['value']) for tag in
                 tags] + self.__arguments['tags'])
    })

  def publish_metrics(self, service_metrics):
    """Writes time series data to Datadog for a metric snapshot."""
    points = []
    spectator_client.foreach_metric_in_service_map(
        service_metrics, self.__append_timeseries_point, points)

    offset = 0
    while offset < len(points):
      last = min(offset + self.MAX_BATCH, len(points))
      chunk = points[offset:last]
      try:
        self.api.Metric.send(chunk)
      except IOError as ioerr:
        logging.error('Error sending to datadog: %s', ioerr)
      offset = last
    return len(points)


def make_datadog_service(options, spectator_helper=None):

  arguments = DatadogArgumentsGenerator(options).generate_arguments()
  spectator_helper = (spectator_helper
                      or spectator_client.SpectatorClientHelper(options))

  return DatadogMetricsService(options, spectator_helper, **arguments)


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
    return 'datadog' in options.get('monitor', {}).get('metric_store', [])

  def add_argparser(self, parser):
    """Implements server_handlers.MonitorCommandHandler interface."""
    parser.add_argument('--datadog', default=False, action='store_true',
                        dest='monitor_datadog',
                        help='Publish metrics to Datadog.')

    add_standard_parser_arguments(parser)

  def __call__(self, options, command_handlers):
    """Create a datadog service instance for interacting with Datadog."""
    return make_datadog_service(options)
