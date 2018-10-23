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

"""Transform spectator metrics so they appear different than produced.

This is to allow them to be written into a metric store in a predictable
way if needed or desired. It also allows letting the metrics appear different
to refactor the data model without having to make global code changes.
"""

import collections
import logging
import re
import yaml

class TimestampedMetricValue(
    collections.namedtuple('TimedstampedMetricValue', ['timestamp', 'value'])):
  """Represents a value of a particular metric and the time for it.

  This is used to facilite aggregating when we drop tags.
  """
  @staticmethod
  def from_json(data):
    """Construct TimestampedMetricValue from dictionary in json response."""
    return TimestampedMetricValue(data['t'], data['v'])

  def aggregate_json(self, data):
    """Aggregate this value with another value from json response.

    This is used when dropping tags to combine values together.
    """
    return TimestampedMetricValue(max(self.timestamp, data['t']),
                                  self.value + data['v'])


class MetricInfo(object):
  """Manages the value for a specific spectator measurement.
  """
  def __init__(self, value_json, sorted_tags):
    self.__timestamp = value_json['t']
    self.__value = value_json['v']
    self.__tags = sorted_tags

  def aggregate_value(self, value_json):
    """Aggregate another value into this metric."""
    self.__value += value_json['v']
    self.__timestamp = max(self.__timestamp, value_json['t'])

  def encode_as_spectator_response(self):
    """Encode this metric info as a spectator response measurement."""
    response = {'values': [{'t': self.__timestamp, 'v': self.__value}]}
    if self.__tags:
      response['tags'] = self.__tags
    return response


class AggregatedMetricsBuilder(object):
  """Re-aggregates a collection of metrics to accumulate similar instances.

  This is used to aggregate multiple similar metric samples if tags
  were removed. Where there used to be multiple distinct metrics from
  different tag values, there is now a single metric value for the
  aggregate of what had been partitioned by the removed tag(s).

  The builder will rebuild the collection of metrics based on the
  unique tag combinations and each combinations aggregate value.
  The timestamp for each metric will be the most recent timestamp from
  the individual partitions that went into the aggregate.
  """

  def __init__(self, discard_tag_values):
    self.__tags_to_metric = {}
    self.__discard_tag_values = discard_tag_values

  def add(self, value_json, tags):
    """Add a measurement to the builder."""
    def find_tag_value(tag):
      """Find value for the specified tag, or None."""
      for elem in tags:
        if elem['key'] == tag:
          return elem['value']
      return None

    if tags:
      for key, compiled_re in self.__discard_tag_values.items():
        if compiled_re.match(str(find_tag_value(key))):
          # ignore this value because it has undesirable tag value.
          return

    tags = sorted(tags) if tags else None
    key = str(tags)
    metric = self.__tags_to_metric.get(key)
    if not metric:
      metric = MetricInfo(value_json, tags)
      self.__tags_to_metric[key] = metric
    else:
      metric.aggregate_value(value_json)

  def build(self):
    """Encode all the measurements for the meter."""
    return [info.encode_as_spectator_response()
            for info in self.__tags_to_metric.values()]


class SpectatorMetricTransformer(object):
  """Transform Spectator measurement responses.

  This transforms responses so that the metrics appear to have different
  definitions than they really did. Typically this means changing
  the metric name and/or tags, perhaps adding or removing some.

  The transformer applies rules to encoded spectator metrics to produce
  alternative encodings as if the original spectator metric was the
  intended metric produced by the rule. This allows the transformer to
  be easily injected into the processing pipeline from the scrape.

  Rules are keyed by the spectator meter name that they apply to. Therefore,
  every kept meter needs a distinct rule entry even if the rule is otherwise
  the same as another.

  Each entry in a rule is optional. Missing entries means "the identity".
  However the omission of a rule entirely means take the default action
  on the transformer which is either to discard the metric (default)
  or keep it as is.

  Transformation rules are as follows:
    'transform_name': <transform_name_map>
    'tags': <tag_list>
    'transform_tags': <tag_transform_list>
    'add_tags' <added_tag_bindings>
    'discard_values': <discard_tag_value_list>
    'per_account': <per_account>
    'per_application': <per_application>

  where:
    * <transform_name_map> is a map of <target>: <target_name>
      which allows the rule to support multiple monitoring systems,
      where each is given a different name to follow that particular
      systems naming conventions. The rest of the transform is the same.
      The <target> is an arbitrary key but should be the system name for
      readability. The target will be specified by the caller as part of
      the transform request.

      If the <target_name> is not present but "default" is, then "default"
      will be used. If a name key is present but empty then the metric will
      be ignored for that name key. For example if the "default" value is
      "my-metric" and a "stackdriver" key is empty and you ask for stackdriver,
      the metric would be ignored, but if you ask for "prometheus" then the
      name would become the default, "my-metric".

   * <tag_list> is a list of tag names to keep as is. An empty list
     means none of the tag names will be kept by default. If the
     'tags' is not specified at all, and no 'transform_tags' are
     specified then all the tags will be kept by default.
     The 'statistic' tag is implicitly in this list if present because
     it is required to interpret the values.

   * <tag_transform_list> is a list of <tag_transform> where <tag_transform> is:
        'from': <source_tag_name>
        'to': <target_tag_name_or_names>
        'type': <type_name_or_names>
        'compare_value': <compare_string_value>
        'extract_regex': <extract_regex>
     where:
        * <source_tag_name> is the tag in the spectator metric for the value(s)
        * <target_tag_name_or_names> is either a string or list of strings
          that specify one or more tags to produce. This can be/include the
          same <source_tag_name> but the value will be rewritten.

          if the value is a list, then multiple tags will be produced. In this
          case the <extract_regex> should have a capture group for each
          element.
        * <type_name_or_names> is the type for the <target_tag_name_or_names>.
          This should match the structure of <target_tag_name_or_names>.
          types are as follows:
             STRING: the original string value
             INT: convert the original string value into an integer
             BOOL: true if it matches the 'compare_value' else false.
        * <compare_string_value> a string value used to compare against
          the tag value when converting into a BOOL.
        * <extract_regex> a regular expression used to extract substrings
          from the original tag value to produce the new desired tag values.
   * <added_tag_bindings> is a dictionary of key/value pairs for tags
     that should be added. The tag values are constants. This is intended
     to consolidate multiple spectator metrics into a single one using
     an additional tag to discriminate the value.

   * <discard_tag_value_list> is a list of [transformed] tag values to ignore
     as if they never happened. The main motivation for this is to strip out
     certain "statistic" dimensions if they arent needed since these ultimately
     become other metrics which might not be wanted. The list is dictionary of
         <tag>: <regex>
       where
         <tag> is the target tag name
         <regex> is a regular expression to match for undesired values.

   * If <per_account> is true, then keep the 'account' tag if present.
     It is intended that downstream processors on these measurements may
     break off the account and use it some other way in consideration of
     its potentially high cardinality.

   * If <per_application> is analogous to <per_account> but for the
     'application' tag if present.

  When the rule is instantiated in the transformer, it is pre-processed
  and some additional tags are entered into it for internal use. These
  internal tags begin with '_'.

  Rules may have additional fields in them for purposes of specifying the
  target metrics. However these are ignored by the transformer. Some of these
  in practice are:
       * 'kind' describes the type of metric (e.g. "Timer")
       * 'unit' names what is being counted -- the units for the value.
         Timers are always nanoseconds so the unit is for the "count" part.
       * 'description' provides documentation on what the metric captures.
       * 'aggregatable' denotes whether the values can be aggregated across
         replicas. This is a hint suggesting a value is global so should
         not be summed across replicas.
  """

  @staticmethod
  def new_from_yaml_path(path, **kwargs):
    """Create new instance using specification in YAML file."""
    with open(path, 'r') as stream:
      transform_spec = yaml.load(stream)
    return SpectatorMetricTransformer(transform_spec, **kwargs)

  @property
  def default_namespace(self):
    """Returns the default namespace to use when transforming names."""
    return self.__default_transform_key

  @property
  def specification(self):
    """Returns the specification used to derive the transformer."""
    return self.__spec

  def __init__(self, spec,
               default_namespace=None,
               default_is_identity=False):
    """Constructor.

    Args:
      spec: [dict] Transformation specification entry from YAML.
      default_namespace: [string] The default key to use for transform_name.
      default_is_identity: [bool] If true and a spec is not
          found when transforming a metric then assume the identity.
          otherwise assume the metric should be discarded.
    """
    self.__default_transform_key = default_namespace
    self.__default_rule = ({}                      # identity
                           if default_is_identity
                           else None)              # discard
    self.__spec = spec
    for rule in spec.values():
      if rule is None:
        continue

      # 'statistic' will always be kept implicitly
      # because it's value affects the semantics of the measurement.
      # It will ultimately get stripped out when the metrics are
      # exported into a monitoring system.
      # Dont explicitly add it to avoid duplication of the implicit add.
      rule_tags = rule.get('tags', [])
      if rule_tags:
        try:
          del rule_tags[rule_tags.index('statistic')]
        except ValueError:
          pass

        if rule.get('per_application'):
          try:
            del rule_tags[rule_tags.index('application')]
          except ValueError:
            pass
        if rule.get('per_account'):
          try:
            del rule_tags[rule_tags.index('account')]
          except ValueError:
            pass

      transform_tags = rule.get('transform_tags', [])
      rule['_identity_tags'] = (
          'tags' not in rule and 'transform_tags' not in rule)
      rule['_added_tags'] = [
          {'key': key, 'value': value}
          for key, value in rule.get('add_tags', {}).items()
      ]
      for transformation in transform_tags:
        self.__prepare_transformation(transformation)

      discard_tag_values = rule.get('discard_tag_values', [])
      if discard_tag_values:
        rule['_discard_tag_values'] = {
            key: re.compile(value) for key, value in discard_tag_values.items()
        }

  def __prepare_transformation(self, transformation):
    """Update the transformation entry from the YAML to contain functions.

    Args:
      transformation: [dict] The YAML entry will be augmented with with a
        '_xform_func' entry that takes the received tag value and returns
        list of tags. Also an '_identity_tags' that precomputes whether to
        keep the tags as originally presented.

    Raises:
      ValueError if the specification was not valid.
    """
    from_tag = transformation['from']
    to_tag = transformation['to']
    tag_type = transformation['type']
    if tag_type == 'BOOL':
      compare = transformation.get('compare_value')
      if compare:
        transformation['_xform_func'] = lambda value: {to_tag: value == compare}
      else:
        transformation['_xform_func'] = lambda value: {to_tag: value == 'true'}
      return

    extract_regex = transformation.get('extract_regex')
    if not extract_regex:
      if tag_type == 'INT':
        transformation['_xform_func'] = lambda value: {to_tag: int(value)}
      elif tag_type == 'STRING':
        transformation['_xform_func'] = lambda value: {to_tag: value}
      else:
        raise ValueError('Unknown tag_type "%s"' % tag_type)
      return

    extractor = re.compile(extract_regex)
    to_tags = to_tag if isinstance(to_tag, list) else [to_tag]

    def composite_func(value):
      """Handle transforming a single tag value into multiple tag values."""
      matched = extractor.match(value)
      if not matched:
        error = ('{tag}: "{pattern}" did not match "{value}"'
                 .format(tag=from_tag, pattern=extract_regex, value=value))
        matched_values = transformation.get('default_value')
        if matched_values:
          if not isinstance(matched_values, list):
            matched_values = [matched_values]
          logging.error(error)
          logging.warning('Using default value %r', matched_values)
        else:
          raise ValueError(error)
      else:
        matched_values = matched.groups()

      if len(matched_values) != len(to_tags):
        raise ValueError('Wrong number of matches: {got} for {tags}'
                         .format(got=matched_values, tags=to_tags))
      return {
          to_tags[index]: matched_values[index] or ''
          for index in range(len(to_tags))
      }
    transformation['_xform_func'] = composite_func

  def process_response(self, metric_response, transform_namespace=None):
    """Transform the spectator response metrics per the spec."""
    result = {}
    for meter_name, spectator_metric in metric_response.items():
      to_name, to_value = self.process_metric(
          meter_name, spectator_metric,
          transform_namespace=transform_namespace)
      if to_name is None != to_value is None:
        raise ValueError('Metric "%s" transformed inconsistently'
                         ' name=%s, value=%s'
                         % (meter_name, to_name, to_value))

      if to_name is not None:
        if to_name in result:
          result[to_name]['values'].extend(to_value['values'])
        else:
          result[to_name] = to_value
    return result

  def process_metric(self, meter_name, spectator_metric,
                     transform_namespace=None):
    """Produce the desired Spectator metric from existing one.

    Args:
      meter_name: [string] The name of the metric
      spectator_metric: [dict] Individual metric response entry from
          spectator web endpoint.

    Returns:
      None if the meter should be ignored
      Otherwise the transformed metric instance from the spec.
    """
    rule = self.__spec.get(meter_name, self.__default_rule)
    if not rule:
      if rule is None and not meter_name in self.__spec:
        # discard if not mentioned and default rule was discard
        return None, None
      # identity if not mentioned and default rule was identity
      # or if was mentioned but no transformations given.
      return meter_name, spectator_metric

    transformed_name = meter_name
    name_transform_dict = rule.get('transform_name')
    if name_transform_dict:
      transform_namespace = transform_namespace or self.default_namespace
      if transform_namespace not in name_transform_dict:
        transform_namespace = 'default'
      transformed_name = name_transform_dict.get(transform_namespace)
      if not transformed_name:
        return None, None

    transformed = {
        'kind': spectator_metric['kind'],
        'values': self.__apply_transform_rule(rule, spectator_metric)
    }
    return transformed_name, transformed

  def __apply_transform_rule(self, rule, spectator_metric):
    metric_builder = AggregatedMetricsBuilder(
        rule.get('_discard_tag_values', {}))

    for source_metric in spectator_metric.get('values', []):
      source_tags = source_metric.get('tags', [])
      target_metric = {'values': source_metric['values']}
      if rule.get('_identity_tags'):
        target_tags = source_tags + rule['_added_tags']
      else:
        tag_dict = {entry['key']: entry['value'] for entry in source_tags}
        target_tags = list(rule['_added_tags'])

        def add_if_present(key, tag_dict, target_tags):
          """Add if there is a tag_dict[key] then add it to target_tags."""
          value = tag_dict.get(key)
          if value is not None:
            target_tags.append({'key': key, 'value': value})

        # "statistic" is required to be preserved while transforming.
        # It will be removed later when the metrics are exported.
        add_if_present('statistic', tag_dict, target_tags)
        if rule.get('per_account'):
          add_if_present('account', tag_dict, target_tags)
        if rule.get('per_application'):
          add_if_present('application', tag_dict, target_tags)

        for tag_name in rule.get('tags') or []:
          target_tags.append({'key': tag_name,
                              'value': tag_dict.get(tag_name, '')})

        for transformation in rule.get('transform_tags', []):
          from_tag = transformation['from']
          value = tag_dict.get(from_tag, '')
          target_tags.extend(
              [{'key': key, 'value': value}
               for key, value in transformation['_xform_func'](value).items()])

      if target_tags:
        target_metric['tags'] = sorted(target_tags)

      metric_builder.add(target_metric['values'][-1],
                         target_metric.get('tags'))
    return metric_builder.build()
