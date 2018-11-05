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
# pylint: disable=global-statement

import base64
import copy
import glob
import json
import logging
import os
import socket
import sys
import threading
import time
import traceback
import urllib2
import urlparse
import yaml

from metric_filter import MetricFilter
from spectator_metric_transformer import SpectatorMetricTransformer

DEFAULT_REGISTRY_DIR = '/opt/spinnaker-monitoring/registry'
DEFAULT_FILTER_DIR = '/opt/spinnaker-monitoring/filters'


# pylint: disable=invalid-name
_cached_registry_catalog = None
_cached_registry_timestamp = None


# Spinnaker has lots of different kinds, but they all boil down
# to either a gauge or type of counter. Ultimately when these are
# written to an external storage system, the adaptor will want to
# know if it is dealing with a counter or a gauge.
COUNTER_PRIMITIVE_KIND = 'Counter'
GAUGE_PRIMITIVE_KIND = 'Gauge'


class ResponseProcessor(object):
  def __init__(self, options):
    self.__disable_filter = options.get('disable_metric_filter', False)
    self.__disable_transform = options.get('disable_metric_transform', False)
    self.__filter_dir = options['metric_filter_dir']
    if self.__filter_dir:
      logging.info('Using explicit --metric_filter_dir=%s', self.__filter_dir)
    else:
      path = os.path.abspath(
          os.path.join(os.path.dirname(os.path.dirname(__file__)), 'filters'))
      if os.path.exists(path):
        self.__filter_dir = path
        logging.info('Using implicit --metric_filter_dir=%s', self.__filter_dir)
      elif os.path.exists(DEFAULT_FILTER_DIR):
        self.__filter_dir = DEFAULT_FILTER_DIR
        logging.info('Using implicit --metric_filter_dir=%s', self.__filter_dir)
    # responses are filtered with only highest precedence filter found.
    #   service comes from daemon configuration for instrumented service
    #   default comes from daemon global config
    self.__service_metric_filter = {}
    self.__service_metric_transformer = {}

    # These are bootstrap values so we can reference them in the
    # __load_service_filter_and_transform in general. We'll set
    # these real values later after we load the 'default'.
    self.__default_metric_filter = None
    self.__default_metric_transformer = None

    default_metric_filter, default_metric_transformer = (
        self.__load_service_filter_and_transform('default'))
    if default_metric_filter is None:
      logging.info('default_metric_filter will be IDENTITY')
      default_metric_filter = lambda all: all

    if default_metric_transformer is None:
      logging.info('default_metric_transformer will be IDENTITY')
      default_metric_transformer = SpectatorMetricTransformer(
          {}, default_is_identity=True)

    self.__default_metric_filter = default_metric_filter
    self.__default_metric_transformer = default_metric_transformer

  def extract_spectator_response_metrics(
      self, params, service, original_response):
    transformer = self.determine_service_metric_transformer(service)
    if transformer:
      result_metrics = transformer.process_response(
          original_response['metrics'])
    else:
      result_metrics = original_response['metrics']

    if str(params.get('disable_metric_filter', False)).lower() != 'true':
      transformed_response = dict(original_response)
      transformed_response['metrics'] = result_metrics
      result_metrics = self.__filter_response(service, transformed_response)

    return result_metrics

  def __load_service_filter_and_transform(self, service):
    metric_filter = None
    metric_transformer = None
    if self.__filter_dir:
      path = os.path.join(self.__filter_dir, service + '.yml')
      if os.path.exists(path):
        default_path = os.path.join(self.__filter_dir, 'default.yml')
        default_spec = {}
        if default_path != path and os.path.exists(default_path):
          with open(default_path) as fd:
            default_spec = yaml.safe_load(fd)

        # pylint: disable=invalid-name
        with open(path) as fd:
          whole_spec = yaml.safe_load(fd)
          filter_spec = whole_spec.get('monitoring', {}).get('filters')
          if self.__disable_filter:
            logging.info('Filtering is disabled -- no filter on %s.', service)
          elif filter_spec is not None:
            logging.info('Loading metric filter from "%s"', path)
            if default_spec:
              logging.info('Adding baseline filters from "default.yml"')
              default_spec.update(filter_spec)  # filter_spec overwrites
              filter_spec = default_spec
            metric_filter = MetricFilter(service, filter_spec)
          else:
            logging.info('"%s" has no monitoring.filters entry -- ignoring',
                         path)

          transform_spec = whole_spec.get('monitoring', {}).get('transforms')
          if self.__disable_transform:
            logging.info('Transforming is disabled -- no transform on %s.',
                         service)
          elif transform_spec is not None:
            logging.info('Loading metric transformer from "%s"', path)
            metric_transformer = SpectatorMetricTransformer(
                transform_spec,
                default_is_identity=False)
          else:
            logging.info('"%s" has no monitoring.transforms entry -- ignoring',
                         path)
    if metric_filter is None:
      logging.info('Using default metric filter for "%s"', service)
      metric_filter = self.__default_metric_filter

    if metric_transformer is None:
      logging.info('Using default metric transformer for "%s"', service)
      metric_transformer = self.__default_metric_transformer

    self.__service_metric_filter[service] = metric_filter
    self.__service_metric_transformer[service] = metric_transformer

    return metric_filter, metric_transformer

  def determine_service_metric_transformer(self, service):
    if service not in self.__service_metric_transformer:
      self.__load_service_filter_and_transform(service)
    return self.__service_metric_transformer[service]

  def determine_service_metric_filter(self, service):
    if service not in self.__service_metric_filter:
      self.__load_service_filter_and_transform(service)
    return self.__service_metric_filter[service]

  def __filter_response(self, service, spectator_response):
    metric_filter = self.determine_service_metric_filter(service)
    return metric_filter(spectator_response['metrics'])


def determine_primitive_kind(kind):
  if kind in (
      'Counter', 'Timer', 'Distribution', 'DistributionSummary',
      'PercentileCounter', 'PercentileTimer',
      'PercentileDistributionSummary'
  ):
    return COUNTER_PRIMITIVE_KIND
  return GAUGE_PRIMITIVE_KIND


def get_source_catalog(options):
  """Returns a dictionary of metric source name to configuration document.

  Args:
    options: [dict] Specifies where the catalog is.
       If 'registry_dir' is specified use that.
       Otherwise default to the DEFAULT_REGISTRY_DIR

  Returns:
    Dictionary keyed by the root name of the config file in the registry
       directory whose value is the dictionary of the YAML file content.
  """
  registry_dir = options.get('registry_dir') or DEFAULT_REGISTRY_DIR
  global _cached_registry_catalog
  global _cached_registry_timestamp
  try:
    timestamp = os.path.getmtime(registry_dir)
  except OSError as err:
    logging.error(err)
    return _cached_registry_catalog or {}

  if _cached_registry_timestamp == timestamp:
    return _cached_registry_catalog

  logging.info('Updating catalog from %s at %ld', registry_dir, timestamp)
  catalog = {}
  for source in glob.glob(os.path.join(registry_dir, '*.yml')):
    name = os.path.splitext(os.path.basename(source))[0]
    logging.info('loading %s', source)
    with open(source) as stream:
      doc = yaml.safe_load(stream)
      url = doc.get('metrics_url')
      if url is None:
        logging.error('%s is missing "metrics_url"', source)
        continue
      doc['metrics_url'] = url if isinstance(url, list) else [url]
      catalog[name] = doc

  _cached_registry_catalog = catalog
  _cached_registry_timestamp = timestamp
  return catalog


def __foreach_metric_tag_binding(
    service, metric_name, metric_data, service_data,
    visitor, visitor_pos_args, visitor_kwargs):
  for metric_instance in metric_data['values']:
    visitor(service, metric_name, metric_instance, metric_data, service_data,
            *visitor_pos_args, **visitor_kwargs)


def foreach_metric_in_service_map(
    service_map, visitor, *visitor_pos_args, **visitor_kwargs):
  for service, service_metric_list in service_map.items():
    if not service_metric_list:
      continue
    for service_metrics in service_metric_list:
      for metric_name, metric_data in service_metrics['metrics'].items():
        __foreach_metric_tag_binding(
            service, metric_name, metric_data, service_metrics,
            visitor, visitor_pos_args, visitor_kwargs)


def normalize_name_and_tags(name, metric_instance, metric_metadata):
  tags = list(metric_instance.get('tags', []))
  for index, tag in enumerate(tags):
    if tag['key'] == 'statistic':
      name = name + '__{0}'.format(tag['value'])
      del tags[index]
      break
  return name, tags


class SpectatorClient(object):
  """Helper class for pulling data from Spectator servers."""

  @property
  def response_processor(self):
    return self.__response_processor

  @staticmethod
  def add_standard_parser_arguments(parser):
    parser.add_argument('--metric_filter_dir', default='',
                        help='Optional filter to restrict metrics of interest.')
    parser.add_argument(
        '--log_metric_diff',
        default=False, action='store_true',
        help='Keep track of the last set of metrics/bindings were'
             ' and show the differences with the current metric/bindings.'
             ' This is to show a change in what metrics are available, not'
             ' the values of the metrics themselves.')
    parser.add_argument('--registry_dir', default=None,
                        help='The directory containing the *.yml files'
                             ' specifying each of the URLs to collect'
                             ' metrics from.')
    parser.add_argument('--disable_metric_filter',
                        default=False, action='store_true',
                        help='Dont use configured metric filter.')

  def __init__(self, options, transformer=None):
    self.__response_processor = ResponseProcessor(options)
    self.__default_scan_params = {'tagNameRegex': '.*'}
    self.__previous_scan_lock = threading.Lock()
    self.__previous_scan = {} if options.get('log_metric_diff') else None

  def __log_scan_diff(self, host, port, metrics):
    """Diff this scan with the previous one for debugging purposes."""
    if self.__previous_scan is None:
      return

    key = '{0}:{1}'.format(host, port)
    with self.__previous_scan_lock:
      previous_metrics = self.__previous_scan.get(key, {})
      self.__previous_scan[key] = copy.deepcopy(metrics)
    if not previous_metrics:
      return

    previous_keys = set(previous_metrics.keys())
    keys = set(metrics.keys())
    new_keys = keys.difference(previous_keys)
    same_keys = keys.intersection(previous_keys)
    lost_keys = previous_keys.difference(keys)
    lines = []

    if lost_keys:
      lines.append('Stopped metrics for:\n  - {0}\n'
                   .format('\n  - '.join(lost_keys)))
    if new_keys:
      lines.append('Started metrics for:\n  - {0}\n'
                   .format('\n  - '.join(new_keys)))

    def normalize_tags(tag_list):
      result = set([])
      for item in sorted(tag_list):
        result.add('{0}={1}'.format(item['key'], item['value']))

      return ', '.join(result)

    for check_key in same_keys:
      tag_sets = set(
          [normalize_tags(item.get('tags', []))
           for item in metrics[check_key].get('values', [])])
      prev_tag_sets = set(
          [normalize_tags(item.get('tags', []))
           for item in previous_metrics[check_key].get('values', [])])
      added_tags = tag_sets.difference(prev_tag_sets)
      lost_tags = prev_tag_sets.difference(tag_sets)

      if added_tags:
        lines.append('"{0}" started data points for\n  - {1}\n'
                     .format(check_key, '\n  - '.join(added_tags)))
      if lost_tags:
        lines.append('"{0}" stopped data points for\n  - {1}\n'
                     .format(check_key, '\n  - '.join(lost_tags)))
    if lines:
      logging.info('==== DIFF %s ===\n%s\n', key, '\n'.join(lines))

  def create_request(self, url, authorization):
    """Helper function to create a request to facilitate testing.

    Wrapper around creating a Request because Request does not implement
    equals so it's difficult to test directly.

    Args:
      url: [string] The url for the request.
      authorization: [string] None or the base64 encoded authorization string.

    Returns:
      urllib2.Request instance
    """
    request = urllib2.Request(url)
    if authorization:
      request.add_header('Authorization', 'Basic %s' % authorization)
    return request

  def collect_metrics(self, service, base_url, params=None):
    """Return JSON metrics from the given server."""
    info = urlparse.urlsplit(base_url)
    host = info.hostname
    port = info.port or 80
    netloc = host

    if info.port:
      netloc += ':{0}'.format(info.port)
    base_url = '{scheme}://{netloc}{path}'.format(
        scheme=info.scheme, netloc=netloc, path=info.path)

    authorization = None
    if info.username or info.password:
      authorization = base64.encodestring(
          '%s:%s' % (info.username, info.password)).replace('\n', '')

    query = '?' + info.query if info.query else ''
    sep = '&' if info.query else '?'
    query_params = dict(self.__default_scan_params)
    if params is None:
      params = {}
    keys_to_copy = [key
                    for key in ['tagNameRegex', 'tagValueRegex',
                                'meterNameRegex']
                    if key in params]
    for key in keys_to_copy:
      query_params[key] = params[key]

    for key, value in query_params.items():
      query += sep + key + "=" + urllib2.quote(value)
      sep = "&"

    url = '{base_url}{query}'.format(base_url=base_url, query=query)
    response = urllib2.urlopen(self.create_request(url, authorization))

    json_text = response.read()
    try:
      spectator_response = json.JSONDecoder(encoding='utf-8').decode(json_text)
    except ValueError:
      if len(json_text) > 200:
        snippet = '%s ... %s' % (json_text[:100], json_text[:-100])
      else:
        snippet = json_text
      logging.error('Invalid JSON len=%d excerpt:\n%s', len(json_text), snippet)
      raise

    try:
      self.__log_scan_diff(host, port + 1012,
                           spectator_response.get('metrics', {}))
    except:
      extype, exvalue, _ = sys.exc_info()
      logging.error(traceback.format_exception_only(extype, exvalue))

    spectator_response['__port'] = port
    spectator_response['__host'] = (
        socket.getfqdn()
        if host in ['localhost', '127.0.0.1', None, '']
        else host)

    available_metrics = (
        self.__response_processor.extract_spectator_response_metrics(
            params, service, spectator_response)
    )

    # NOTE: 20180614
    # There have been occasional bugs in spinnaker
    # where gauges are returned as 'NaN'.
    #
    # This string value is causing prometheus errors
    # which prevent any metrics from being stored.
    num_metrics = 0
    for metric_name, metric_data in available_metrics.items():
      meter_values = metric_data.get('values', [])
      num_metrics += len(meter_values)
      empty_value_list_indexes = []
      for index, values_list in enumerate(meter_values):
        # Ensure the value of each measurement is a float
        # If jackson encountered NaN or Inf values then
        # it will make them strings by default.
        # These should probably not be present, but if they are
        # This will convert NaN or Inf into a float
        for elem in values_list['values']:
          if elem['v'] == 'NaN':
            logging.warn('Removing illegal NaN from "%s.%s"',
                         service, metric_name)
            values_list['values'] = [e for e in values_list['values']
                                     if e['v'] != 'NaN']
            if not values_list['values']:
              empty_value_list_indexes.append(index)
            break

      # If there are metrics that only had NaN values,
      # delete them in reverse order so list indexes are still valid.
      # This could still leave meters with no metrics.
      while empty_value_list_indexes:
        del meter_values[empty_value_list_indexes.pop()]

    spectator_response['metrics'] = available_metrics
    return spectator_response

  def scan_by_service(self, service_catalog, params=None):
    result = {}

    start = time.time()
    service_time = {service: 0 for service in service_catalog.keys()}
    result = {service: None for service in service_catalog.keys()}
    threads = {}

    def timed_collect(self, service, url_endpoints):
      now = time.time()
      endpoint_data_list = []
      for service_url in url_endpoints:
        try:
          endpoint_data_list.append(self.collect_metrics(
              service, service_url, params=params))
        except IOError as ioex:
          logging.getLogger(__name__).error(
              '%s failed %s with %s',
              service, service_url, ioex)

      result[service] = endpoint_data_list
      service_time[service] = int((time.time() - now) * 1000)

    for service, config in service_catalog.items():
      threads[service] = threading.Thread(
          target=timed_collect,
          args=(self, service, config['metrics_url']))
      threads[service].start()
    for service in service_catalog.keys():
      threads[service].join()

    logging.info('Collection times %d (ms): %s',
                 (time.time() - start) * 1000, service_time)
    return result

  def scan_by_type(self, service_catalog, params=None):
    service_map = self.scan_by_service(service_catalog, params=params)
    return self.service_map_to_type_map(service_map)

  @staticmethod
  def ingest_metrics(service, response_data, type_map):
    """Add JSON |metric_data| from |service| name and add to |type_map|"""
    metric_data = response_data.get('metrics', {})
    for key, value in metric_data.items():
      if key in type_map:
        have = type_map[key].get(service, [])
        have.append(value)
        type_map[key][service] = have
      else:
        type_map[key] = {service: [value]}

  @staticmethod
  def service_map_to_type_map(service_map):
    type_map = {}
    for service, got_from_each_endpoint in service_map.items():
      for got in got_from_each_endpoint or []:
        SpectatorClient.ingest_metrics(service, got, type_map)
    return type_map
