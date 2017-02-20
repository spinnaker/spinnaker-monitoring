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
# pylint: disable=star-args
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


CONFIG_DIR = '/opt/spinnaker-monitoring/config'

# pylint: disable=invalid-name
_cached_source_catalog = None
_cached_source_timestamp = None


def get_source_catalog(config_dir=None):
  """Returns a dictionary of source name to source configuration document.

  Args:
    config_dir: [string] The base config directory to load from.
        The source configurations are expected to be in a 'sources' subdir.

  Returns:
    Dictionary keyed by the root name of the config file in <config_dir>
       whose value is the dictionary of the YAML file content.
  """
  config_dir = config_dir or CONFIG_DIR
  source_dir = os.path.join(config_dir, 'sources')

  global _cached_source_catalog
  global _cached_source_timestamp
  try:
    timestamp = os.path.getmtime(source_dir)
  except OSError as err:
    logging.error(err)
    return _cached_source_catalog or {}

  if _cached_source_timestamp == timestamp:
    return _cached_source_catalog

  logging.info('Updating catalog from %s at %ld', source_dir, timestamp)
  catalog = {}
  for source in glob.glob(os.path.join(source_dir, '*.yml')):
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

  _cached_source_catalog = catalog
  _cached_source_timestamp = timestamp
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
  tags = metric_instance.get('tags', None)
  if not tags:
    return name, None   # signal this metric had no tags so we can ignore it.

  is_timer = metric_metadata['kind'] == 'Timer'
  if is_timer:
    tags = list(tags)
    for index, tag in enumerate(tags):
      if tag['key'] == 'statistic':
        name = name + '__{0}'.format(tag['value'])
        del tags[index]
        break
  return name, tags


class SpectatorClient(object):
  """Helper class for pulling data from Spectator servers."""

  @staticmethod
  def add_standard_parser_arguments(parser):
    parser.add_argument('--prototype_path', default='',
                        help='Optional filter to restrict metrics of interest.')
    parser.add_argument(
        '--log_metric_diff',
        default=False, action='store_true',
        help='Keep track of the last set of metrics/bindings were'
             ' and show the differences with the current metric/bindings.'
             ' This is to show a change in what metrics are available, not'
             ' the values of the metrics themselves.')


  def __init__(self, options):
    self.__prototype = None
    self.__default_scan_params = {'tagNameRegex': '.+'}
    self.__previous_scan_lock = threading.Lock()
    self.__previous_scan = {} if options.get('log_metric_diff') else None

    if options['prototype_path']:
      # pylint: disable=invalid-name
      with open(options['prototype_path']) as fd:
        self.__prototype = json.JSONDecoder().decode(fd.read())

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

  def collect_metrics(self, base_url, params=None):
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

    all_metrics = json.JSONDecoder(encoding='utf-8').decode(response.read())
    try:
      self.__log_scan_diff(host, port + 1012, all_metrics.get('metrics', {}))
    except:
      extype, exvalue, ignore_tb = sys.exc_info()
      logging.error(traceback.format_exception_only(extype, exvalue))

    # Record how many data values we collected.
    # Add success tag so we have a tag and dont get filtered out.
    num_metrics = 0
    for metric_data in all_metrics.get('metrics', {}).values():
      num_metrics += len(metric_data.get('values', []))

    all_metrics['__port'] = port
    all_metrics['__host'] = (socket.getfqdn()
                             if host in ['localhost', '127.0.0.1', None, '']
                             else host)
    all_metrics['metrics']['spectator.datapoints'] = {
        'kind': 'Gauge',
        'values': [{
            'tags': [{'key': 'success', 'value': "true"}],
            'values': [{'v': num_metrics, 't': int(time.time() * 1000)}]
        }]
    }

    return (self.filter_metrics(all_metrics, self.__prototype)
            if self.__prototype else all_metrics)

  def filter_metrics(self, instance, prototype):
    """Filter metrics entries in |instance| to those that match |prototype|.

    Only the names and tags are checked. The instance must contain a
    tag binding found in the prototype, but may also contain additional tags.
    The prototype is the same format as the json of the metrics returned.
    """
    filtered = {}

    metrics = instance.get('metrics') or {}
    for key, expect in prototype.get('metrics', {}).items():
      got = metrics.get(key)
      if not got:
        continue
      expect_values = expect.get('values')
      if not expect_values:
        filtered[key] = got
        continue

      expect_tags = [elem.get('tags') for elem in expect_values]

      # Clone the dict because we are going to modify it to remove values
      # we dont care about
      keep_values = []
      def have_tags(expect_tags, got_tags):
        for wanted_set in expect_tags:
          # pylint: disable=invalid-name
          ok = True
          for want in wanted_set:
            if want not in got_tags:
              ok = False
              break
          if ok:
            return True

        return expect_tags == []

      for got_value in got.get('values', []):
        got_tags = got_value.get('tags')
        if have_tags(expect_tags, got_tags):
          keep_values.append(got_value)
      if not keep_values:
        continue

      keep = dict(got)
      keep['values'] = keep_values
      filtered[key] = keep

    result = dict(instance)
    result['metrics'] = filtered
    return result

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
              service_url, params=params))
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
