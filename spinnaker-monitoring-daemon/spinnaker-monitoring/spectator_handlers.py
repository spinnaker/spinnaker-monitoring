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

from datetime import datetime
import json

import command_processor
import http_server
import spectator_client


def millis_to_time(millis):
  """Convert milliseconds to a time string."""
  return datetime.fromtimestamp(millis / 1000).isoformat('T') + 'Z'


def strip_non_html_params(options):
  """Return a copy of options with only those that are query parameters.

  This is to propagate options in web response URLs.
  """
  params = {}
  for key in ['tagNameRegex', 'tagValueRegex', 'metricNameRegex']:
    if key in options:
      params[key] = options[key]
  return params


class BaseSpectatorCommandHandler(command_processor.CommandHandler):
  def make_spectator_client(self, options):
    return spectator_client.SpectatorClient(options)

  def add_argparser(self, subparsers):
    parser = super(BaseSpectatorCommandHandler, self).add_argparser(subparsers)
    parser.add_argument('--by', default='service',
                        help='Organize by "service" or by "metric" name.')
    spectator_client.SpectatorClient.add_standard_parser_arguments(parser)
    return parser

  def _get_data_map(self, catalog, options):
    restrict_services = options.get('services', None)
    if restrict_services:
      catalog = {service: config
                 for service, config in catalog.items()
                 if service in restrict_services.split(',')}
    spectator = self.make_spectator_client(options)

    by = options.get('by', 'service')
    if by == 'service':
      data_map = spectator.scan_by_service(catalog, params=options)
    else:
      data_map = spectator.scan_by_type(catalog, params=options)
    return data_map


class DumpMetricsHandler(BaseSpectatorCommandHandler):
  def process_commandline_request(self, options):
    catalog = spectator_client.get_source_catalog(options)
    data_map = self._get_data_map(catalog, options)
    json_text = json.JSONEncoder(indent=2).encode(data_map)
    self.output(options, json_text)

  def process_web_request(self, request, path, params, fragment):
    options = dict(command_processor.get_global_options())
    options.update(params)
    catalog = spectator_client.get_source_catalog(options)
    param_services = params.get('services', 'all').split(',')
    if param_services == ['all']:
      restricted_catalog = catalog
    else:
      restricted_catalog = {key: value
                            for key, value in catalog.items()
                            if key in param_services}
    data_map = self._get_data_map(restricted_catalog, options)
    body = json.JSONEncoder(indent=2).encode(data_map)
    request.respond(200, {'ContentType': 'application/json'}, body)


class ExploreCustomDescriptorsHandler(BaseSpectatorCommandHandler):
  """Show all the current descriptors in use, and who is using them."""

  def __init__(self, *pos_args, **kwargs):
    self.__service_map = None
    self.__spectator = None
    super(ExploreCustomDescriptorsHandler, self).__init__(*pos_args, **kwargs)

  def __get_type_and_tag_map_and_active_services(self, catalog, options):
    spectator = self.make_spectator_client(options)
    self.__spectator = spectator

    scan_options = dict(options)
    scan_options['disable_metric_filter'] = True
    self.__service_map = spectator.scan_by_service(catalog, params=scan_options)
    type_map = spectator.service_map_to_type_map(self.__service_map)
    service_tag_map, active_services = self.to_service_tag_map(type_map)
    return type_map, service_tag_map, active_services

  def process_commandline_request(self, options):
    catalog = spectator_client.get_source_catalog(options)
    type_map, service_tag_map, active_services = (
        self.__get_type_and_tag_map_and_active_services(
            catalog, options))

    params = strip_non_html_params(options)
    html = self.to_html(type_map, service_tag_map, active_services, params)
    html_doc = http_server.build_html_document(
        html, title='Metric Usage')
    self.output(options, html_doc)

  def process_web_request(self, request, path, params, fragment):
    options = dict(command_processor.get_global_options())
    options.update(params)
    catalog = spectator_client.get_source_catalog(options)

    type_map, service_tag_map, active_services = (
        self.__get_type_and_tag_map_and_active_services(catalog, options))

    params = strip_non_html_params(options)
    html = self.to_html(type_map, service_tag_map, active_services, params)
    html_doc = http_server.build_html_document(
        html, title='Metric Usage')
    request.respond(200, {'ContentType': 'text/html'}, html_doc)

  @staticmethod
  def to_service_tag_map(type_map):
    service_tag_map = {}
    active_services = set()

    def process_endpoint_values_helper(key, service, values):
      if not isinstance(values, dict):
        return
      tagged_data = values.get('values', [])
      for tagged_point in tagged_data:
        tag_map = {tag['key']: tag['value']
                   for tag in tagged_point.get('tags')}
        if not tag_map:
          tag_map = {None: None}
        if key not in service_tag_map:
          service_tag_map[key] = {service: [tag_map]}
        else:
          service_map = service_tag_map[key]
          if service in service_map:
            service_map[service].append(tag_map)
          else:
            service_map[service] = [tag_map]

    for key, entry in sorted(type_map.items()):
      # pylint: disable=bad-indentation
      for service, value_list in sorted(entry.items()):
        active_services.add(service)
        for value in value_list:
          process_endpoint_values_helper(key, service, value)

    return service_tag_map, active_services

  @staticmethod
  def to_tag_service_map(columns, service_tag_map):
    tag_service_map = {}
    for service, tags in service_tag_map.items():
      service_index = columns[service]

      for tag_group in tags:
        for tag_name, tag_value in tag_group.items():
          if tag_name not in tag_service_map:
            tag_service_map[tag_name] = [set() for ignore in columns]
          # tag_value is None if there is no tag.
          # This is still different from the service not having the meter.
          # because above we added an empty set to every service column
          # so that we have a square table. A None here means that we
          # have a meter without any tags, as opposed to the empty set
          # which means we dont even have a meter in that service.
          tag_service_map[tag_name][service_index].add(tag_value)

    return tag_service_map

  def __determine_filtered_meters(self, service_name):
    """Return set of filtered [discarded] meter names within service."""
    filter = self.__spectator.determine_service_metric_filter(service_name)
    missing_keys = set([])
    service_map_list = self.__service_map[service_name]
    for replica in service_map_list:
      metrics = replica['metrics']
      filtered = filter(metrics)
      all_keys = set(metrics.keys())
      filtered_keys = set(filtered.keys())
      missing_keys.update(all_keys - filtered_keys)

    return missing_keys

  def __service_labels_to_html_td(self, is_filtered, service_labels):
    """Given a meter name and list of label values, produce the cell html.

    This is for an individual service column which contains the labels used.
    """
    row_html = []
    if is_filtered and service_labels:
      css = ' class=\"warning\"'
    else:
      css = ' class=\"ok\"'

    # The [None] here means we have a meter but no tags.
    if service_labels == set([None]):
      row_html.append('<td><i{css}>no tags</i>'.format(css=css))
    else:
      row_html.append(
          '<td>{values}</td>'.format(
              values=', '.join(
                  ['<A{css} href="/explore?tagValueRegex={v}">{v}</A>'.format(
                      css=css, v=value)
                   for value in sorted(service_labels)]))
      )
    return ''.join(row_html)

  def __service_label_columns_html(
      self, meter_name, service_values, service_filtered_metrics):
    """Produce all columns html for each service and values for given label.

    Returns:
      (html for all the columns, num services used, num services unused)
      where used indicates it is present and not filtered out
            unused indicates it is present but being filtered out
      services that do not used the labels are not included in any of the counts
      and are rendered as empty columns.
    """
    num_used = 0
    num_unused = 0
    num_ignored = 0
    html = []
    for index, label_values in enumerate(service_values):
      is_filtered = meter_name in service_filtered_metrics[index]
      html_snippet = self.__service_labels_to_html_td(
          is_filtered, label_values)
      html.append(html_snippet)
      if not label_values:
        num_ignored += 1
      elif is_filtered:
        num_unused += 1
      else:
        num_used += 1
    return ''.join(html), num_used, num_unused

  def __all_label_columns_html(
      self, meter_name, tag_service_map, service_filtered_metrics):
    """Returns the html for all the label columns.

    This includes the label column containing the label name
    and each service column with the label values used by the service.

    Note that if there are multiple labels, then there will be multiple rows
    with one row per label. This assumes that the initial row had a rowspan.
    In practice the initial row also contains a meter name column which is
    rowspaned such that all the individual labels are enumerated within it.

    Returns:
       num used labels used, num unused labels, column html
       where used and unused indicate filter activity only.
    """
    num_used_labels = 0
    num_unused_labels = 0
    result_html = []
    row_html = []
    for label_name, service_values in tag_service_map.items():
      service_label_columns_html, num_used, num_unused = (
          self.__service_label_columns_html(meter_name, service_values,
                                            service_filtered_metrics))
      if num_used:
        if num_unused:
          css = ''
        else:
          css = ' class="ok"'
      else:
        css = ' class="warning"'

      if label_name is None:
        row_html.append('<td{css}/>'.format(css=css))
      else:
        row_html.append(
            '<td{css}>'
            '<A href="/explore?tagNameRegex={label}"{css}>{label}</A>'
            '</td>'.format(label=label_name, css=css))
      row_html.append(service_label_columns_html)
      num_used_labels += num_used
      num_unused_labels += num_unused
      row_html.append('</tr>')
      result_html.append(''.join(row_html))
      row_html = ['<tr>']  # prepare for next row if needed
    return num_used_labels, num_unused_labels, '\n'.join(result_html)

  def to_html(self, type_map, service_tag_map, active_services, params=None):
    """Produce HTML table with row per meter/label and column per service.

    Cells will be colored ok or warning depending on whether the service
    will store the meter values or not. The meters and labels themselves
    are colored if all the services using the metric show or ignore them.
    If some show but not others then the name wont be colored. If services
    do not even report the metric, then they do not influence coloring and
    their cells will be empty.
    """
    header_html = ['<tr>', '<th>Metric</th>', '<th>Label</th>']
    columns = {}
    service_filtered_metrics = []

    for service_name in sorted(active_services):
      columns[service_name] = len(columns)
      header_html.append('<th><A href="/show?services={0}">{0}</A></th>'.format(
          service_name))
      service_filtered_metrics.append(
          self.__determine_filtered_meters(service_name))
    header_html.append('</tr>')

    html = ['<table border=1>']
    html.extend(header_html)

    for meter_name, service_tag_map in sorted(service_tag_map.items()):
      tag_service_map = self.to_tag_service_map(columns, service_tag_map)
      num_labels = len(tag_service_map)
      _, info = type_map[meter_name].items()[0]
      kind = info[0].get('kind')
      row_html = ['<tr>']
      row_span = ' rowspan={0}'.format(num_labels) if num_labels > 1 else ''
      query_params = dict(params or {})
      query_params['meterNameRegex'] = meter_name
      metric_url = '/show{0}'.format(self.params_to_query(query_params))

      num_used, num_unused, column_html = self.__all_label_columns_html(
          meter_name, tag_service_map, service_filtered_metrics)

      if num_used:
        if num_unused:
          css = ''
        else:
          css = ' class="ok"'
      else:
        css = ' class="warning"'

      row_html.append(
          '<td{row_span}{css}>'
          '<A href="{url}"{css}>{meter_name}</A>'
          '<br/>{kind}</td>'.format(
              row_span=row_span, css=css,
              url=metric_url, meter_name=meter_name,
              kind=kind))

      html.append(''.join(row_html) + column_html)

    html.append('</table>')
    return '\n'.join(html)


class TagValue(object):
  def __init__(self, tag):
    self.key = tag['key']
    self.value = tag['value']

  def __hash__(self):
    return hash((self.key, self.value))

  def __eq__(self, value):
    return self.key == value.key and self.value == value.value

  def __repr__(self):
    return self.__str__()

  def __str__(self):
    return '{0}={1}'.format(self.key, self.value)

  def as_html(self):
    return '<code><b>{0}</b>={1}</code>'.format(self.key, self.value)


class ShowCurrentMetricsHandler(BaseSpectatorCommandHandler):
  """Show all the current metric values."""

  def process_commandline_request(self, options):
    catalog = spectator_client.get_source_catalog(options)
    data_map = self._get_data_map(catalog, options)
    by = options.get('by', 'service')
    if by == 'service':
      content_data = self.service_map_to_text(data_map, params=options)
    else:
      content_data = self.type_map_to_text(data_map, params=options)
    self.output(options, content_data)

  def process_web_request(self, request, path, params, fragment):
    options = dict(command_processor.get_global_options())
    options.update(params)
    catalog = spectator_client.get_source_catalog(options)
    data_map = self._get_data_map(catalog, options)

    if self.accepts_content_type(request, 'text/html'):
      content_type = 'text/html'
      by_service = self.service_map_to_html
      by_type = self.type_map_to_html
    else:
      content_type = 'text/plain'
      by_service = self.service_map_to_text
      by_type = self.type_map_to_text

    by = options.get('by', 'service')
    if by == 'service':
      content_data = by_service(data_map, params=params)
    else:
      content_data = by_type(data_map, params=params)

    if content_type == 'text/html':
      body = http_server.build_html_document(
          content_data, title='Current Metrics')
    else:
      body = content_data
    request.respond(200, {'ContentType': content_type}, body)

  def all_tagged_values(self, value_list):
    all_values = []
    for data in value_list:
      tags = [TagValue(tag) for tag in data.get('tags', [])]
      all_values.append((tags, data['values']))
    return all_values

  def data_points_to_td(self, data_points):
    if len(data_points) == 1:
      point = data_points[0]
      return '<td>{time}</td><td>{value}</td>'.format(
          time=millis_to_time(point['t']), value=point['v'])

  def data_points_to_text(self, data_points):
    text = []
    for point in data_points:
      text.append('{time}  {value}'.format(
          time=millis_to_time(point['t']),
          value=point['v']))
    return ', '.join(text)

  def service_map_to_text(self, service_map, params=None):
    lines = []
    def process_metrics_helper(metrics):
      for key, value in metrics.items():
        tagged_values = self.all_tagged_values(value.get('values'))
        parts = ['Service "{0}"'.format(service)]
        parts.append('  {0}  [{1}]'.format(key, value.get('kind')))

        for one in tagged_values:
          tag_list = one[0]
          tag_text = ', '.join([str(elem) for elem in tag_list])
          time_values = self.data_points_to_text(one[1])
          parts.append('    Tags={0}'.format(tag_text))
          parts.append('    Values={0}'.format(time_values))
        lines.append('\n'.join(parts))

    for service, entry_list in sorted(service_map.items()):
      for entry in entry_list or []:
        process_metrics_helper(entry.get('metrics', {}))

    return '\n\n'.join(lines)

  def service_map_to_html(self, service_map, params=None):
    result = ['<table>',
              '<tr><th>Service</th><th>Metric</th>'
              '<th>Timestamp</th><th>Values</th><th>Labels</th></tr>']
    def process_metrics_helper(metrics):
      for key, value in sorted(metrics.items()):
          # pylint: disable=bad-indentation
          tagged_values = self.all_tagged_values(value.get('values'))
          service_url = '/show{0}'.format(
              self.params_to_query({'services': service}))
          metric_url = '/show{0}'.format(
              self.params_to_query({'meterNameRegex': key}))
          html = (
              '<tr>'
              '<th rowspan={rowspan}><A href="{service_url}">{service}</A></th>'
              '<th rowspan={rowspan}><A href="{metric_url}">{key}</A><br/>{kind}</th>'
              .format(rowspan=len(tagged_values),
                      service_url=service_url,
                      service=service,
                      metric_url=metric_url,
                      key=key,
                      kind=value.get('kind')))
          for one in tagged_values:
            tag_list = one[0]
            tag_html = '<br/>'.join([elem.as_html() for elem in tag_list])
            time_value_td = self.data_points_to_td(one[1])
            html += '{time_value_td}<td>{tag_list}</td></tr>'.format(
                time_value_td=time_value_td, tag_list=tag_html)
            result.append(html)
            html = '<tr>'

    for service, entry_list in sorted(service_map.items()):
      for entry in entry_list or []:
        process_metrics_helper(entry.get('metrics', {}))
    result.append('</table>')
    return '\n'.join(result)

  def type_map_to_text(self, type_map, params=None):
    lines = []
    def process_values_helper(values):
      tagged_values = self.all_tagged_values(values)
      for tag_value in tagged_values:
        text_key = ', '.join([str(tag) for tag in tag_value[0]])
        tag_to_service_values[text_key] = (service, tag_value[1])

    for key, entry in sorted(type_map.items()):
      tag_to_service_values = {}
      for service, value_list in sorted(entry.items()):
        for value in value_list:
          process_values_helper(value.get('values'))

      parts = ['Metric "{0}"'.format(key)]
      for tags_text, values in sorted(tag_to_service_values.items()):
        parts.append('  Service "{0}"'.format(values[0]))
        parts.append('    Value: {0}'.format(
            self.data_points_to_text(values[1])))
        parts.append('    Tags: {0}'.format(tags_text))
      lines.append('\n'.join(parts))
    return '\n\n'.join(lines)

  def type_map_to_html(self, type_map, params=None):
    """Helper function to render descriptor usage into text."""

    column_headers_html = ('<tr><th>Key</th><th>Timestamp</th><th>Value</th>'
                           '<th>Service</th><th>Tags</th></tr>')
    row_html = []
    def process_values_helper(values):
      tagged_values = self.all_tagged_values(values)
      for tag_value in tagged_values:
        html_key = '<br/>'.join([tag.as_html() for tag in tag_value[0]])
        tag_to_service_values[html_key] = (service, tag_value[1])

    for key, entry in sorted(type_map.items()):
      tag_to_service_values = {}
      for service, value_list in sorted(entry.items()):
        for value in value_list or []:
          process_values_helper(value.get('values'))

      row_html.append('<tr><td rowspan={rowspan}><b>{key}</b></td>'.format(
          rowspan=len(tag_to_service_values), key=key))

      sep = ''
      for tags_html, values in sorted(tag_to_service_values.items()):
        time_value_td = self.data_points_to_td(values[1])
        row_html.append('{sep}{time_value_td}'
                        '<td><i>{service}</i></td><td>{tags}</td></tr>'
                        .format(sep=sep, time_value_td=time_value_td,
                                service=values[0], tags=tags_html))
        sep = '<tr>'

    return '<table>\n{header}\n{rows}\n</table>'.format(
        header=column_headers_html, rows='\n'.join(row_html))


def add_handlers(handler_list, subparsers):
  command_handlers = [
      ShowCurrentMetricsHandler(
          '/show', 'show', 'Show current metric JSON for all Spinnaker.'),
      DumpMetricsHandler(
          '/dump', 'dump',
          'Show current raw metric JSON from all the servers.'),
      ExploreCustomDescriptorsHandler(
          '/explore', 'explore',
          'Explore metric type usage across Spinnaker microservices.')
  ]
  for handler in command_handlers:
    handler.add_argparser(subparsers)
    handler_list.append(handler)
