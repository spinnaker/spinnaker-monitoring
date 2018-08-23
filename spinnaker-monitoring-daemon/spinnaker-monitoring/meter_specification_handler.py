# Copyright 2018 Google Inc. All Rights Reserved.
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

"""
EXPERIMENTAL

This module contains some handlers for manipulating meter specifications.
Meter specifications are experimental and not yet in use.
"""

import logging
import os
import re
import yaml

import command_processor
import http_server
import spectator_client
from spectator_handlers import BaseSpectatorCommandHandler


METER_SPEC_FILENAME_DECORATOR = '-meter-specification.yml'

def union_keys(*pos_args):
  """Return a union of all the keys in multiple dicts.

  Args:
    pos_args: [list of dict]
  """
  return set().union(*pos_args)


def encode_yaml(yaml_dict):
  """Return dictionary as yaml string."""
  return yaml.safe_dump(yaml_dict, allow_unicode=True,
                        default_flow_style=False,
                        encoding='utf-8')


def compute_meter_diff(original, final, key_path=''):
  """Log differences between two meter specs."""
  changes = []
  for key in union_keys(original, final):
    abs_key = key_path + key
    original_value = original.get(key)
    final_value = final.get(key)
    if original_value == final_value:
      continue
    if original_value is None:
      changes.append('Added %s=%r' % (abs_key, final_value))
    elif final_value is None:
      changes.append('Removed %s' % abs_key)
    elif isinstance(final_value, dict) and isinstance(original_value, dict):
      changes.extend(
          compute_meter_diff(original_value, final_value,
                             key_path=abs_key + '.'))
    elif isinstance(final_value, list) and isinstance(original_value, list):
      original_set = set(original_value)
      final_set = set(final_value)
      added = final_set - original_set
      removed = original_set - final_set
      if added:
        changes.append('Added %r to %s' % (added, abs_key))
      if removed:
        changes.append('Removed %r from %s' % (removed, abs_key))
    elif final_value.__class__ != original_value.__class__:
      changes.append('Changed type of "%s" from %s to %s with value=%r' % (
          abs_key,
          original_value.__class__.__name__, 
          final_value.__class__.__name__,
          final_value))
    else:
      changes.append('Modified %s=%r' % (abs_key, final_value))
  return changes


def load_all_service_meter_specs(input_source):
  """Load all the service meter-spec.yml files found in input_dir.

  Return:
    dict keyed by service with loaded content.
  """
  if not input_source:
    return {}

  logging.info('Loading all service meter specifications from %s',
               input_source)
  if os.path.isfile(input_source):
    with open(input_source, 'r') as stream:
      return yaml.safe_load(stream)

  all_specs = {}
  for filename in os.listdir(input_source):
    if not filename.endswith(METER_SPEC_FILENAME_DECORATOR):
      continue

    service = filename[:-len(METER_SPEC_FILENAME_DECORATOR)]
    path = os.path.join(input_source, filename)
    logging.info('Reading meter specs from "%s"', path)
    with open(path, 'r') as stream:
      all_specs[service] = yaml.safe_load(stream)

  return all_specs


def dump_all_meter_spec(per_service_dir, all_service_specs):
  """Write each meter spec to a file in the per_service_dir."""
  if not per_service_dir:
    return

  if not os.path.exists(per_service_dir):
    os.makedirs(per_service_dir)

  logging.info('Writing meter specs to "%s"', per_service_dir)
  for service, spec in all_service_specs.items():
    path = os.path.join(per_service_dir,
                        service + METER_SPEC_FILENAME_DECORATOR)
    with open(path, 'w') as fd:
      yaml.safe_dump(spec, fd, encoding='utf-8',
                     default_flow_style=False)


class ViewpointAugmenter(object):
  """Adds viewpoint attribute to meter specs."""

  def __init__(self, options):
    self.__prometheus_dir = options.get('prometheus_dashboard_dir')

  def augment(self, service, all_specs):
    """Attempt to add viewpoints to meter specs.

    Args:
      all_specs: [map of spec keyed by meter name]
    """
    changes = []
    for meter, spec in all_specs.items():
      viewpoints = set([])
      if self.__prometheus_dir:
        viewpoints.update(self.collect_prometheus_viewpoints(service, meter))
      have = set(spec.get('viewpoints', []))
      viewpoints.update(have)
      if viewpoints:
        spec['viewpoints'] = sorted(list(viewpoints))
        if viewpoints != have:
          added = sorted(list(viewpoints - have))
          removed = sorted(list(have - viewpoints))
          if removed:
            changes.append('"%s" lost %s' % (meter, removed))
          if added:
            changes.append('"%s" added %s' % (meter, added))

    if changes:
      logging.warn('service=%s changed viewpoints:\n  * %s',
                   service, '\n  * '.join(changes))

  def collect_prometheus_viewpoints(self, service, meter):
    """Helper function to guess at what perspectives to give a meter.

    This heuristic uses the curated prometheus dashboards for the hint.
    """
    prometheus_dir = self.__prometheus_dir
    if not prometheus_dir:
      return []
    minimal = os.path.join(prometheus_dir, 'minimal-spinnaker-dashboard.json')
    microservice = os.path.join(prometheus_dir,
                                service + '-microservice-dashboard.json')
    viewpoints = set([])
    if self.__has_prometheus_meter(minimal, service, meter):
      viewpoints.add('system')
    if self.__has_prometheus_meter(microservice, service, meter):
      viewpoints.add('microservice')

    for platform in ['aws', 'google', 'kubernetes']:
      if self.__has_prometheus_meter(
          os.path.join(prometheus_dir, platform + '-platform-dashboard.json'),
          service, meter):
        viewpoints.add(platform)

    return viewpoints

  def __has_prometheus_meter(self, path, service, meter):
    """Helper function to see if a given dashboard references a given meter."""
    if not os.path.exists(path):
      return None

    with open(path, 'r') as fd:
      data = fd.read()
      regex = service + ':' + meter.replace('.', ':')
      regex += '(?:__count|__totalTime|__totalAmount)?'
      regex += '{'
      return re.search(regex, data)


class DiffMeterSpecificationsHandler(BaseSpectatorCommandHandler):
  """Show differences among two collections of meter specifications."""

  def add_argparser(self, subparsers):
    parser = super(DiffMeterSpecificationsHandler, self).add_argparser(
        subparsers)
    parser.add_argument(
        '--baseline', default=None, required=True,
        help='The service meters acting as the diff baseline.'
             ' Either a single yaml file with outer service keys.'
             ' or a directory of files <service>-meter-specification.yml')
    parser.add_argument(
        '--input', default=None, required=True,
        help='The service meters acting as the diff comparision.'
             ' Either a single yaml file with outer service keys.'
             ' or a directory of files <service>-meter-specification.yml')

  def compute_service_diff(self, all_baseline, all_changes):
    service_diff  = {}
    for service in union_keys(all_baseline, all_changes):
      logging.info('Diffing meters for "%s"', service)
      baseline_meters = all_baseline.get(service, {})
      change_meters = all_changes.get(service, {})

      service_diff[service] = {}
      for meter in union_keys(baseline_meters, change_meters):
        diff = compute_meter_diff(
            baseline_meters.get(meter, {}), change_meters.get(meter, {}))
        if diff:
          service_diff[service][meter] = diff
    return service_diff

  def process_commandline_request(self, options):
    all_baseline = load_all_service_meter_specs(
        options.get('baseline'))
    all_changes = load_all_service_meter_specs(
        options.get('input'))
    service_diff = self.compute_service_diff(all_baseline, all_changes)

    def service_remarks_to_string(service, meter_diff):
      """Helper functions to render diff for a given service."""
      result = ['\nSERVICE: "%s"' % service]
      for meter, remarks in meter_diff.items():
        result.append('  "%s"' % meter)
        result.append('    * %s' % ('\n    * '.join(remarks)))
        result.append('')  # for separator between meter entries
      return '\n'.join(result)

    text = '\n'.join([
        service_remarks_to_string(service, meter_diff)
      for service, meter_diff in service_diff.items()
        if meter_diff
    ])
    self.output(options, text)


class AugmentMeterSpecificationsHandler(BaseSpectatorCommandHandler):
  """Various heuristics to augment meter specs with more info."""

  def add_argparser(self, subparsers):
    abspath = os.path.abspath(__file__)
    prometheus_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(abspath))),
        'spinnaker-monitoring-third-party',
        'third_party',
        'prometheus')

    parser = super(AugmentMeterSpecificationsHandler, self).add_argparser(
        subparsers)
    parser.add_argument(
        '--baseline', default=None,
        help='If specified, is either a single yaml file keyed by service,'
             ' or a directory with yaml files named'
             ' <service>-meter-specification.yml')
    parser.add_argument(
        '--input', default=None, required=True,
        help='Provides then meter specification attributes to augment.'
             ' Either a single yaml file keyed by service,'
             ' or a directory with yaml files named'
             ' <service>-meter-specification.yml')
    parser.add_argument(
        '--per_service_output_dir', default=None,
        help='Write a yaml file for each service'
             ' named <service>-meter-specification.yml')
    parser.add_argument(
        '--prometheus_dashboard_dir', default=prometheus_dir,
        help='If specified infer viewpoints from prometheus dashboards.')
    return parser

  def process_commandline_request(self, options):
    all_baseline = load_all_service_meter_specs(
        options.get('baseline'))
    all_changes = load_all_service_meter_specs(
        options.get('input'))

    viewpoint_augmenter = ViewpointAugmenter(options)
    yaml_dict = {}
    for service in union_keys(all_baseline, all_changes):
      logging.info('Processing service="%s"', service)
      baseline = all_baseline.get(service)
      changes = all_changes.get(service)
      yaml_dict[service] = self.fuse_all(baseline, changes)
      viewpoint_augmenter.augment(service, yaml_dict[service])

    dump_all_meter_spec(options.get('per_service_output_dir'), yaml_dict)
    self.output(options, encode_yaml(yaml_dict))

  def fuse(self, baseline, current):
    """Fuse the meter spec from current into baseline."""
    spec = dict(baseline)
    for key, value in current.items():
      if not key in baseline:
        spec[key] = value
        continue
      if isinstance(value, dict):
        spec[key].update(value)
        continue
      if isinstance(value, list):
        for elem in value:
          if elem not in baseline[key]:
            spec[key].append(elem)
            if key in ['tags']:
              spec[key] = sorted(spec[key])
        continue
      spec[key] = value

    return spec

  def fuse_all(self, all_baseline, all_current):
    """Fuse the meter specs from current into baseline."""
    if not all_current:
      return all_baseline
    if not all_baseline:
      return all_current

    all_meters = union_keys(all_baseline, all_current)
    all_specs = {}
    for meter in all_meters:
      baseline = all_baseline.get(meter)
      current = all_current.get(meter)
      if baseline is None:
        logging.info('Adding meter spec for "%s"', meter)
        all_specs[meter] = current
      elif current is None:
        all_specs[meter] = baseline
      else:
        all_specs[meter] = self.fuse(baseline, current)
        self.log_meter_diff(meter, baseline, all_specs[meter])

    return all_specs

  @staticmethod
  def log_meter_diff(meter, original, final):
    changes = compute_meter_diff(original, final)
    if changes:
      logging.info('Changed "%s":\n  * %s',
                   meter, '\n  * '.join(changes))


class InferMeterSpecificationsHandler(BaseSpectatorCommandHandler):
  """Show all the current descriptors in use, and who is using them."""

  def add_argparser(self, subparsers):
    parser = super(InferMeterSpecificationsHandler, self).add_argparser(
        subparsers)
    parser.add_argument('--per_service_output_dir', default=None,
                        help='If specified, write a yaml file for each service'
                        ' in the specified directory.')
    return parser

  def process_commandline_request(self, options):
    scan_options = dict(options)
    scan_options['disable_metric_filter'] = True
    spectator = self.make_spectator_client(scan_options)
    catalog = spectator_client.get_source_catalog(scan_options)
    service_map = spectator.scan_by_service(catalog, scan_options)

    yaml_dict = self.process_service_map(service_map)
    dump_all_meter_spec(options.get('per_service_output_dir'), yaml_dict)
    self.output(options, encode_yaml(yaml_dict))

  def process_web_request(self, request, path, params, fragment):
    options = dict(command_processor.get_global_options())
    options['disable_metric_filter'] = True
    options.update(params)
    spectator = self.make_spectator_client(options)
    catalog = spectator_client.get_source_catalog(options)
    service_map = spectator.scan_by_service(catalog, options)

    yaml_dict = self.process_service_map(service_map)
    html = '<pre>%s</pre>' % encode_yaml(yaml_dict)
    html_doc = http_server.build_html_document(
        html, title='Inferred Meter Specs')
    request.respond(200, {'ContentType': 'application/html'}, html_doc)

  @staticmethod
  def __extract_meter_info_list_map(instances):
    """Get all instances of all meters.

    Returns:
      map of [list of meter_info] keyed by meter name
      for all the meters and meter_info found across instances.
    """
    result = {}
    for instance in instances:
      metrics = instance.get('metrics', {})
      for name, meter_info in metrics.iteritems():
        info_list = result.get(name, [])
        info_list.append(meter_info)
        result[name] = info_list
    return result

  @staticmethod
  def derive_spec(service, name, meter_info_list):
    """Derive a spec definition given all the instance data.

    Args:
      service: [string] The service metrics are from.
      name: [string] The meter name.
      meter_info_list: [list of meter_info] all sampled values.
    """
    all_tags = set([])
    statistic_values = set([])
    kinds = set([])
    for meter_info in meter_info_list:
      kinds.add(meter_info['kind'])
      for value in meter_info.get('values', []):
        value_tags = value.get('tags', [])
        for tag in value_tags:
          all_tags.add(tag['key'])
          if tag['key'] == 'statistic':
            statistic_values.add(tag['value'])

    if len(kinds) != 1:
      raise ValueError(
          'Inconsistent kinds for service="{service}"'
          ' meter="{meter}": {kinds}'.format(
              service=service, meter=name, kinds=kinds))

    kind = kinds.pop()
    if statistic_values:
      all_tags.remove('statistic')
      if kind == 'Counter':
        if statistic_values == set(['count', 'totalTime', 'percentile']):
          kind = 'PercentileTimer'
        elif statistic_values == set(['count', 'totalAmount', 'percentile']):
          kind = 'PercentileDistributionSummary'
        else:
          raise ValueError(
              'Unknown type for service="{service}" meter="{meter}"'
              ' statistic_values={statistics!r}'.format(
                  service=service, meter=name, statistics=statistic_values))

    spec = {'kind': kind}
    if all_tags:
      spec['tags'] = sorted(list(all_tags))
    return spec

  @staticmethod
  def infer_meters(service, name_to_meter_info_list):
    """Determine all the specs found throughout a service.

    Args:
      service: [string] The name of the service meters were from
      name_to_meter_info_list: map of [meter_info] keyed by meter name.
    """
    infered = {}
    for name, meter_info_list in sorted(name_to_meter_info_list.iteritems()):
      infered[name] = InferMeterSpecificationsHandler.derive_spec(
          service, name, meter_info_list)

    return infered

  def process_service_map(self, service_map):
    """Convert metrics into dictionary of service meter specifications."""
    yaml_dict = {}
    for service, instances in sorted(service_map.iteritems()):
      name_to_meter_info_list = self.__extract_meter_info_list_map(instances)
      spec = self.infer_meters(service, name_to_meter_info_list)
      if spec:
        yaml_dict[service] = spec

    return yaml_dict


def add_handlers(handler_list, subparsers):
  command_handlers = [
      InferMeterSpecificationsHandler(
          '/infer_meter_specifications', 'infer_meter_specifications',
          'EXPERIMENTAL: Show meter specifications.'),
      AugmentMeterSpecificationsHandler(
          None, 'augment_meter_specifications',
          'EXPERIMENTAL: Augment meter specifications.'),
      DiffMeterSpecificationsHandler(
          None, 'diff_meter_specifications',
          'EXPERIMENTAL: Diff meter specifications.')
  ]
  for handler in command_handlers:
    handler.add_argparser(subparsers)
    handler_list.append(handler)
