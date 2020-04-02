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
import sys
import yaml

# This is a cache for the _snakeify function to increase performance on the
#    conversion of CamelCase to snake_case
SNAKEIFY_CACHE = {}

def _snakeify(text):
  if text not in SNAKEIFY_CACHE:
    result = []
    result.append(text[0].lower())
    for position in range(1, len(text)):
      if text[position].isupper():
        if text[position - 1].islower():
          result.append('_')
        elif position < (len(text) - 1) and text[position + 1].islower() and text[position - 1] is not '_':
          result.append('_')
      result.append(text[position].lower())
    SNAKEIFY_CACHE[text] =  ''.join(result)
  return SNAKEIFY_CACHE[text]


class PercentileDecoder(object):
  """Interprets the implied value ranges for Spectator Percentile* meters.

  When Spectator writes a Percentile* measurement it sets the followign tags:
      "statistic" = "percentile"
      "percentile" = <type><hex> where:
                     <type> is some character indicating the measurement type
                            ('T' for timer, 'D' for distribution)
                     <hex> is a hex encoded number indicating the bucket
  The value of these measurements are the number of items in the bucket.

  The problem is, the ranges denoted by the buckets are implied.
  This class provides the knowledge of what the implied value ranges are
  for each bucket. These value ranges are hard coded into the
  spectator PercentileBucket class

   https://github.com/Netflix/spectator/blob/master/spectator-api/src
         /main/java/com/netflix/spectator/api/histogram/PercentileBuckets.java

  """

  # We'll use a singelton. This coudl all be static but if we dont need it
  # then there is no point of computing and storing the tables involved.
  __SINGLETON = None

  @staticmethod
  def singleton():
    """Returns the decoder instance."""
    if not PercentileDecoder.__SINGLETON:
      PercentileDecoder.__SINGLETON = PercentileDecoder()
    return PercentileDecoder.__SINGLETON

  def __init_buckets(self):
    """Initialize the bucket mappings.

    Returns a list of integers denoting the max value in the bucket
    keyed by the bucket index.
    """

    # Based on static initialization in
    # https://github.com/Netflix/spectator/blob/master/spectator-api/src
    #        /main/java/com/netflix/spectator/api/histogram/PercentileBuckets.java
    # It doesnt really matter what the algorithm is here. We are not
    # making this decision. Rather we are decoding the decision already
    # made and given to us.
    buckets = [1, 2, 3]

    digits = 2
    exp = digits
    while (exp < 64):
      current = 1 << exp
      delta = current / 3
      next = (current << digits) - delta

      while current < next:
        buckets.append(current)
        current += delta
      exp += digits

    buckets.append(sys.maxsize)
    return buckets

  def __init__(self):
    self.__bucket_values = self.__init_buckets()

  def percentile_label_to_bucket(self, percentile_label):
    """Given the value of a "percentile" tag, return the bucket index.

    Recall the tag value is in the form <type><hex>.
    """
    return int(percentile_label[1:], 16)

  def bucket_to_min_max(self, bucket):
    """Given a bucket index, return the min, max value range for the bucket."""
    prev = bucket - 1 if bucket > 0 else 0
    return self.__bucket_values[prev], self.__bucket_values[bucket]


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
  @property
  def tags(self):
    """Returns the tag bindings for this metric info."""
    return self.__tags

  @property
  def timestamp(self):
    """Returns the timestamp for this metric info."""
    return self.__timestamp

  @property
  def value(self):
    """Returns the value for this metric info."""
    return self.__value

  def __init__(self, value_json, sorted_tags, rule):
    self.__timestamp = value_json['t']
    self.__value = value_json['v']
    self.__tags = sorted_tags
    self.__rule = rule

    # NOTE(20181203):
    # This extra field here is experimental, but we're always going
    # to incur the runtime overhead to maintain the data model for simplicity.
    #
    # This is for another map 'per_tag_values' which is meant to capture
    # the breakout (group by) of "per_<account|application>" tags that were
    # dropped and aggregated to the tags list. The values here is a dictionary
    # keyed by the tag name (e.g. account) with entries for each of the tag
    # values along with the standard tags above (eg. add 'account': 'MyAccount')
    #
    # This allows the standard interface using the tags to see the redacted view
    # (remove the "per_*" tags) while having visibility to those extra tags
    # using the "per_tag_values" view. The intent is to allow the metric store
    # to handle these values with high cardinality tags differently. It isnt
    # yet definitive how to do that or even if we want to.
    self.__per_tag_values = {}

  def __eq__(self, info):
    """Equality is used for testing."""
    return (info.__class__ == self.__class__
            and info.timestamp == self.__timestamp
            and info.tags == self.__tags
            and info.value == self.__value
            and info.__rule == self.__rule)

  def __repr__(self):
    return repr({'t': self.__timestamp,
                 'v': self.__value,
                 'tags': self.__tags})

  def __str__(self):
    return str({'t': self.__timestamp,
                'v': self.__value,
                'tags': self.__tags})

  def add_per_tags(self, value_json, sorted_tags, per_tags):
    if not per_tags:
      return

    for tag in per_tags:
      tag_container = self.__per_tag_values.get(tag['key'])
      if tag_container is None:
        tag_container = {}
        self.__per_tag_values[tag['key']] = tag_container

      augmented_tags = list(sorted_tags)
      augmented_tags.append(tag)
      sorted_augmented_tags = sorted(augmented_tags, key=lambda tag: tag['key'])
      normalized_key = str(sorted_augmented_tags)
      info = tag_container.get(normalized_key)
      if not info:
        info = MetricInfo(value_json, sorted_augmented_tags, self.__rule)
        tag_container[normalized_key] = info
      else:
        info.aggregate_value(value_json)

  def aggregate_value(self, value_json):
    """Aggregate another value into this metric."""
    self.__value = self.__rule.combine_values(
        self.__value, value_json['v'])
    self.__timestamp = max(self.__timestamp, value_json['t'])

  def encode_as_spectator_response(self):
    """Encode this metric info as a spectator response measurement."""
    response = {'values': [{'t': self.__timestamp, 'v': self.__value}]}
    if self.__tags:
      response['tags'] = self.__tags
    if self.__per_tag_values:
      response['__per_tag_values'] = {
          key: sorted([v.encode_as_spectator_response()
                       for v in value.values()],
                      key=lambda d: (d['values'][0]['t'], d['values'][0]['v']))
          for key, value in self.__per_tag_values.items()
      }
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

  @property
  def rule(self):
    """The rule bound to this builder."""
    return self.__rule

  def __init__(self, rule):
    self.__tags_to_metric = {}
    self.__rule = rule
    self.__discard_tag_values = rule.discard_tag_value_expressions

  def add(self, value_json, tags, per_tags=None):
    """Add a measurement to the builder."""
    def find_tag_value(tag):
      """Find value for the specified tag, or None."""
      for elem in tags:
        if elem['key'] == tag:
          return elem['value']
      return None

    if tags:
      for key, compiled_re in self.__discard_tag_values.items():
        if self.__rule.discard_tag_value(key, find_tag_value(key)):
          return

    sorted_tags = sorted(tags, key=lambda tag: tag['key']) if tags else None
    normalized_key = str(sorted_tags)

    metric = self.__tags_to_metric.get(normalized_key)
    if not metric:
      metric = MetricInfo(value_json, sorted_tags, self.__rule)
      self.__tags_to_metric[normalized_key] = metric
    else:
      metric.aggregate_value(value_json)
    metric.add_per_tags(value_json, sorted_tags, per_tags)

  def _collate_metric_values(self):
    """Collate the values in the builder to produce composite values
       for all meters.

       See _collate_measurements for more info on collating individual meters.
    """
    collated_measurement_values = {}
    for info in self.__tags_to_metric.values():
      self._collate_metric_info(info, collated_measurement_values)
    return collated_measurement_values

  def _collate_metric_info(
      self, metric_info, collated_metric_infos):
    """Collate the metric_info for a given meter.

    Collated metric_info are a composite value replacing a collection
    of metric_info related through different "statistic" tag values.
    For example a timer with tag bindings including "statistic=count"
    whose value is COUNT and "statistic=totalTime" whose value is TOTAL
    will result in a single composite value {count:COUNT, totalTime:TOTAL}
    whose tag bindings were the original minus the "statistic" tag.

    To collate into a composite metric, two measurements must have the
    same tag bindings (other than statistic) and each composite value must
    have values from the same timestamp.

    Args:
      metric_info: MetricInfo we wish to collate into the collated metrics
      collated_metric_infos: map keyed by normalized tag bindings
         whose values are the [collated] MetricInfo for a given composite meter.
    """
    def get_tag_value_and_remove_from_list(name, tags):
      for index, key_value in enumerate(tags):
        # For this particular binding, find the statistic tag
        if key_value['key'] == name:
          value = key_value['value']
          del(tags[index])
          return value
      logging.error('Expected to find %s in %r', name, tags)
      return None

    # Iterate over all the metric tag binding combinations
    key = None
    tags = list(metric_info.tags)
    key = get_tag_value_and_remove_from_list('statistic', tags)

    bucket_key = None
    if key == 'percentile':
      percentile = get_tag_value_and_remove_from_list('percentile', tags)
      bucket_key = PercentileDecoder.singleton().percentile_label_to_bucket(
          percentile)

    # Produce our normalized metric instance without the 'statistic' tag
    # but with a composite value adding the statistic value mapped to
    # instance value (e.g. count: <value> or mean: <value>).
    # If this is a percentile based metric then there will be
    # a 'buckets' key whose <value> is a dict of bucket counts keyed by
    # bucket num. The bucket num denotes a range of values as returned by
    # PercentileDecoder.bucket_to_min_max(bucket_num)
    #
    # We'll need to align the timestamps across the different statistic values
    # to correlate their composite elements correctly.
    normalized_key = str(tags)
    normalized_info = collated_metric_infos.get(normalized_key)

    if not normalized_info:
      the_value = ({key: metric_info.value}
                   if bucket_key is None
                   else {'buckets': {bucket_key: metric_info.value}})
      json_value = {'t': metric_info.timestamp,
                    'v': the_value}
      normalized_info = MetricInfo(json_value, tags, self.__rule)
      collated_metric_infos[normalized_key] = normalized_info
      return
    if bucket_key is None:
      normalized_info.value[key] = metric_info.value
    else:
      if 'buckets' not in normalized_info.value:
        normalized_info.value['buckets'] = {bucket_key: metric_info.value}
      else:
        normalized_info.value['buckets'][bucket_key] = metric_info.value

  def build(self):
    """Encode all the measurements for the meter."""
    kind = self.__rule.rule_specification.get('kind', '')
    if (self.__rule.transformer.options.get('summarize_compound_kinds', False)
        and (kind.endswith('Timer') or kind.endswith('Summary'))):
      collated_values = self._collate_metric_values()
      return self.__encode_all_metric_info(collated_values.values())

    return self.__encode_all_metric_info(self.__tags_to_metric.values())

  def __encode_all_metric_info(self, metric_info_list):
    """Encode all the measurements for the meter."""
    return [info.encode_as_spectator_response()
            for info in metric_info_list]


class TransformationRule(object):
  """Encapsulates transformation rule.

  Transformation rules are as follows:
    'rename': <target_name>
    'tags': <tag_list>
    'change_tags': <tag_transform_list>
    'add_tags' <added_tag_bindings>
    'discard_tag_values': <discard_tag_value_list>
    'per_account': <per_account>
    'per_application': <per_application>

  where:
    * <target_name> is the new metric name to use.

   * <tag_list> is a list of tag names to keep as is. An empty list
     means none of the tag names will be kept by default. If the
     'tags' is not specified at all, and no 'change_tags' are
     specified then all the tags will be kept by default.
     The 'statistic' tag is implicitly in this list if present because
     it is required to interpret the values.

   * <tag_transform_list> is a list of <tag_transform> where <tag_transform> is:
        'from': <source_tag_name>
        'to': <target_tag_name_or_names>
        'type': <type_name_or_names>
        'compare_value': <compare_string_value>
        'oneof_regex': <extract_regex>
        'extract_regex': <extract_regex>
     where:
        * <source_tag_name> is the tag in the spectator metric for the value(s)
        * <target_tag_name_or_names> is either a string or list of strings
          that specify one or more tags to produce. This can be/include the
          same <source_tag_name> but the value will be rewritten.

          if the value is a list, then multiple tags will be produced. In this
          case the <extract_regex> should have a capture group for each
          element. The <oneof_regex> offers multiple capture group
          possibilities, and uses whichever value was matched.

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
        * <oneof_regex> similar to extract_regex but allows for multiple
          capture groups and assumes only one will produce a value.

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

  @property
  def discard_tag_value_expressions(self):
    """Map of tag name to value regex to discard when matching."""
    return self.__discard_tag_values

  @property
  def per_account(self):
    """Should this rule break out "account" tags if present."""
    return self.__per_account

  @property
  def per_application(self):
    """Should this rule break out "application" tags if present."""
    return self.__per_application

  @property
  def value_type(self):
    """Returns the value type for the specified metric."""
    return self.__rule_spec.get('value_type', 'REAL')

  @property
  def rule_specification(self):
    """The underlying rule specification dict."""
    return self.__rule_spec

  @property
  def transformer(self):
    """Return transformer that this rule belongs to."""
    return self.__transformer

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
    if isinstance(transformation['to'], list):
      to_tag = [self.__transformer.normalize_label_name(t)
                for t in transformation['to']]
    else:
      to_tag = self.__transformer.normalize_label_name(transformation['to'])
    transformation['to'] = to_tag

    if not 'type' in transformation:
      # Set the type in the original spec to be explicit to other consumers
      # looking at the raw spec.
      transformation['type'] = 'STRING'

    tags_are_string = self.__transformer.options.get('tags_are_typed_string')
    tags_are_typed = self.__transformer.options.get('tags_are_typed') or tags_are_string
    tag_type = transformation['type']
    if tag_type == 'BOOL':
      compare = transformation.get('compare_value')
      if compare:
        compare_func = lambda value: value == compare
      else:
        compare_func = lambda value: value == 'true' or value == ''

      if tags_are_string or not tags_are_typed:
        transformation['_xform_func'] = lambda value: {
            to_tag: str(compare_func(value)).lower()
        }
      else:
        transformation['_xform_func'] = lambda value: {
            to_tag: compare_func(value)
        }
      return

    use_regex = (transformation.get('extract_regex')
                 or transformation.get('oneof_regex'))
    if not use_regex:
      if not tags_are_typed or tag_type == 'STRING':
        transformation['_xform_func'] = lambda value: {to_tag: value}
      elif tag_type == 'INT':
        value_func = lambda value: int(0 if value in ('', 'UNKNOWN') else value)
        if tags_are_string:
          transformation['_xform_func'] = lambda value: {
              to_tag: str(value_func(value))
          }
        else:
          transformation['_xform_func'] = lambda value: {
              to_tag: value_func(value)
          }
      else:
        raise ValueError('Unknown tag_type "%s"' % tag_type)
      return

    extractor = re.compile(use_regex)
    allof = 'extract_regex' in transformation
    to_tags = to_tag if isinstance(to_tag, list) else [to_tag]

    def composite_func(value):
      """Handle transforming a single tag value into multiple tag values."""
      matched = extractor.match(value)
      if not matched:
        error = ('{tag}: "{pattern}" did not match "{value}"'
                 .format(tag=from_tag, pattern=use_regex, value=value))
        matched_values = transformation.get('default_value')
        if matched_values:
          if not isinstance(matched_values, list):
            matched_values = [matched_values]
        else:
          raise ValueError(error)
      else:
        matched_values = matched.groups()

      if not allof:
        # Reduce oneof_regex to a single matched value
        matched_values = [value for value in matched_values
                          if value is not None]

      if len(matched_values) != len(to_tags):
        raise ValueError('Wrong number of matches: {got} for {tags}'
                         .format(got=matched_values, tags=to_tags))
      return {
          to_tags[index]: matched_values[index] or ''
          for index in range(len(to_tags))
      }
    transformation['_xform_func'] = composite_func

  @staticmethod
  def make_rule_list(transformer, rule_spec_or_list):
    if rule_spec_or_list is None:
      return []
    rule_spec_list = (rule_spec_or_list
                      if isinstance(rule_spec_or_list, list)
                      else [rule_spec_or_list])
    return [TransformationRule(transformer, elem) for elem in rule_spec_list]

  def __init__(self, transformer, rule_spec):
    """Construct new transformation rule

    While the rule_spec can specify the transforms, in practice it is desired
    for this to be standardized for a particular monitoring strategy
    independent of deployments so it can be shared among a community.

    However there may be some tweaks that an individual deployment may
    desire or require. Those options can be communicated through the
    transformer. The intent is that the TransformRule can apply those
    deployment options to the origianl rule spec as if the original rule
    spec was written explicitly using those deployment options. The benefit
    is that the deployment policy is contained here, and the rules can
    be standardized.

    Args:
      transformer: [SpectatorMetricTransformer] The owning transformer
         is used for configuration options for any deployment-oriented
         transform configuration policy applied on top of the generic rules.
      rule_spec: [dict] The rule specification loaded from the json file.
    """
    if transformer.options.get('transform_values', False):
      self.__value_transform = {
          None: lambda x: x,
          'BOOL': lambda x: bool(x),
          'REAL': lambda x: x,
          'SCALAR': lambda x: int(x)
      }[rule_spec.get('value_type')]
    else:
      self.__value_transform = lambda x: x

    # If we need to aggregate values of this type
    # (e.g. because we remove a tag in the transform)
    # then by default we'll add the values together.
    # However if it is a boolean type then it isnt obvious
    # whether combining True and False should be True or False.
    # It depends on the individual metric, so use a config option
    # to disambiguate.
    #   (e.g. if the value indicates success we'd probably want AND
    #    but if the value indicates a failure we'd probably want OR)
    self.combine_values = lambda x, y: x + y
    if rule_spec.get('value_type') == 'BOOL':
      self.combine_values = {
          True: lambda x, y: x or y,    # Any are true
          False: lambda x, y: x and y,  # All are true
          None: lambda x, y: x + y      # Scalar sum of true values
      }[rule_spec.get('default_value')]

    self.__transformer = transformer
    self.__rule_spec = rule_spec if rule_spec else None
    if rule_spec is None:
      rule_spec = {}

    # Indicates whether we should look for percentile tags
    self.__is_percentile = rule_spec.get('kind', '').startswith('Percentile')

    per_tags = []

    # 'statistic' will always be kept implicitly
    # because it's value affects the semantics of the measurement.
    # It will ultimately get stripped out when the metrics are
    # exported into a monitoring system.
    # Dont explicitly add it to avoid duplication of the implicit add.
    rule_tags = rule_spec.get('tags') or []
    if rule_tags:
      try:
        del rule_tags[rule_tags.index('statistic')]
      except ValueError:
        pass

      # Force change if label normalization has an effect
      keep_tags = []
      for check_tag in rule_tags:
        normalized_tag = self.__transformer.normalize_label_name(check_tag)
        if normalized_tag == check_tag:
          keep_tags.append(check_tag)
          continue
        change_tags = rule_spec.get('change_tags', [])
        change_tags.append({'from': check_tag, 'to': normalized_tag})
        rule_spec['change_tags'] = change_tags
      rule_tags = keep_tags
      rule_spec['tags'] = rule_tags

    self.__per_application = rule_spec.get('per_application')
    if self.__per_application:
      per_tags.append('application')
      try:
        del rule_tags[rule_tags.index('application')]
      except ValueError:
        pass

    self.__per_account = rule_spec.get('per_account')
    if self.__per_account:
      per_tags.append('account')
      try:
        del rule_tags[rule_tags.index('account')]
      except ValueError:
        pass

    if per_tags:
      self.is_per_tag = lambda t: t in per_tags
    else:
      self.is_per_tag = lambda t: False

    if self.__transformer.options.get('tags_are_typed'):
      normalize_tag_value = lambda x: x
    else:
      normalize_tag_value = lambda x: (
          str(x).lower()
          if isinstance(x, bool)
          else str(x)
      )

    change_tags = rule_spec.get('change_tags', [])
    self.__identity_tags = (
        'tags' not in rule_spec and 'change_tags' not in rule_spec)
    self.__added_tags = [
        {'key': self.__transformer.normalize_label_name(key),
         'value': normalize_tag_value(value)}
        for key, value in rule_spec.get('add_tags', {}).items()
    ]
    for transformation in change_tags:
      self.__prepare_transformation(transformation)

    discard_tag_values = rule_spec.get('discard_tag_values', {})
    self.__discard_tag_values = {
        key: re.compile(value) for key, value in discard_tag_values.items()
    }

  def __nonzero__(self):
    return self.__rule_spec is not None

  def __bool__(self):
    return self.__rule_spec is not None

  def discard_tag_value(self, tag, value):
    """Determine if a given tag value should be discarded."""
    compiled_re = self.__discard_tag_values.get(tag)
    return compiled_re and compiled_re.match(str(value))

  def determine_measurement(self, measurement):
    """Convert the measurement value according to the rule.

    Args:
      measurement: [dict]  A {'t', 'v'} timestamp value pair.
    """
    try:
      value = self.__value_transform(measurement['v'])
    except TypeError as err:
      logging.error('TypeError %s transforming %r',
                    str(err), measurement['v'])
      raise
    return {'t': measurement['t'], 'v': value}

  def determine_meter_name(self, meter_name):
    """Get transformed meter name (or original).

    Args:
      meter_name: [string] The original meter name

    Returns:
      The name, possibly original meter_name, or None to disregard this meter.
    """
    return self.__transformer.normalize_meter_name(
        self.__rule_spec.get('rename', meter_name),
        self.__rule_spec.get('kind'))

  def apply(self, spectator_metric):
    """Apply the rule to the given metric instance."""
    metric_builder = AggregatedMetricsBuilder(self)

    for source_metric in spectator_metric.get('values', []):
      source_tags = source_metric.get('tags', [])
      target_metric = {'values': source_metric['values']}
      per_tags = []
      if self.__identity_tags:
        target_tags = source_tags + self.__added_tags
      else:
        tag_dict = {entry['key']: entry['value'] for entry in source_tags}
        target_tags = list(self.__added_tags)

        def add_if_present(key, tag_dict, target_tags):
          """Add if there is a tag_dict[key] then add it to target_tags."""
          value = tag_dict.get(key)
          if value is not None:
            target_tags.append({'key': key, 'value': value})

        # "statistic" is required to be preserved while transforming.
        # It will be removed later when the metrics are exported.
        add_if_present('statistic', tag_dict, target_tags)
        if self.__is_percentile:
          # also keep the "percentile" tag, which indicates bucket counts
          add_if_present('percentile', tag_dict, target_tags)

        # NOTE(ewiseblatt): 20181123
        # We're not handling per-* attributes yet.
        # It is quite complicated and probably high overhead
        # plus still needs to be implemented in the writers.
        #
        # if self.__per_account:
        #   add_if_present('account', tag_dict, per_tags)
        # if self.__per_application:
        #   add_if_present('application', tag_dict, per_tags)

        for tag_name in self.__rule_spec.get('tags') or []:
          target_tags.append({'key': tag_name,
                              'value': tag_dict.get(tag_name, '')})

        for transformation in self.__rule_spec.get('change_tags', []):
          from_tag = transformation['from']
          value = tag_dict.get(from_tag, '')
          try:
            xform_tags = transformation['_xform_func'](value)
          except Exception as ex:
            logging.error('%s transforming value=%r with rule=%r',
                          ex, value, self.__rule_spec)
            continue

          for key, value in xform_tags.items():
            encoded_tag = {'key': key, 'value': value}
            if self.is_per_tag(key):
              per_tags.append(encoded_tag)
            else:
              target_tags.append(encoded_tag)

       # NOTE(ewiseblatt): 20181123
       # We're currently disregarding the per_tags here.
       # If you said "per_application" then specified an application
       # extraction above, then that application tag will be dropped.

      if target_tags:
        target_metric['tags'] = sorted(target_tags, key=lambda tag: tag['key'])

      metric_builder.add(
          self.determine_measurement(target_metric['values'][-1]),
          target_metric.get('tags'),
          per_tags=per_tags)
    return metric_builder.build()


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
  """

  @staticmethod
  def new_from_yaml_path(path, options=None):
    """Create new instance using specification in YAML file."""
    with open(path, 'r') as stream:
      transform_spec = yaml.load(stream)
    return SpectatorMetricTransformer(options, transform_spec)

  @property
  def rulebase(self):
    """Maps an original meter name to a list of TransformRules for it."""
    return self.__rulebase

  @property
  def options(self):
    """Return bound options."""
    return self.__options

  def __normalize_stackdriver_label(self, label):
    """This is a hack for internal stackdriver policy compliance."""
    if label == 'status':
      return 'status_code_class'
    return _snakeify(label)

  def __normalize_stackdriver_name(self, name, kind):
    """This is a hack for internal stackdriver policy compliance."""
    name = _snakeify(name)
    if kind.endswith('Timer'):
      if not name.endswith('_latencies'):
        if name[-1] == 's':
          name = name[:-1]
        name += '_latencies'
    if kind.endswith('Summary'):
      if not name.endswith('_distribution'):
        name += '_distribution'

    return name

  def __init__(self, options, spec):
    """Constructor.

    Args:
      options: [dict] Configuration options for the transformer.
          - default_is_identity: [bool] If true and a spec is not
                found when transforming a metric then assume the identity.
                Otherwise assume the metric should be discarded.
          - tags_are_typed: [bool] If true then tag values should have
                their specified native types. Otherwise they are strings.
          - use_snake_case: [bool] If true then names and labels should
                use snake-case. Otherwise leave as is.
          - enforce_stackdriver_names: [bool] Hack for internal google use
                to workaround historical policy constraints.
          - summarize_compound_kinds: [bool] If true then convert
                Timer and DistributionSummary metrics into a Summary by
                creating a single compound metric from the individual
                count/totalTime measurements rather than reporting out as
                separate component measurements.
      spec: [dict] Transformation specification entry from YAML.
    """
    self.__options = dict(options)
    if options.get('use_snake_case', False):
      self.normalize_text_case = _snakeify
    else:
      self.normalize_text_case = lambda x: x

    if options.get('enforce_stackdriver_names'):
      self.normalize_meter_name = self.__normalize_stackdriver_name
      self.normalize_label_name = self.__normalize_stackdriver_label
    else:
      self.normalize_meter_name = lambda x, _: self.normalize_text_case(x)
      self.normalize_label_name = lambda x: self.normalize_text_case(x)

    default_is_identity = options.get('default_is_identity', False)
    self.__default_rule_list = ([]                      # identity
                                if default_is_identity
                                else None)              # discard
    self.__rulebase = {key: TransformationRule.make_rule_list(self, value)
                       for key, value in spec.items()}
    for meter_name, rule in spec.items():
      if not rule:
        logging.debug(
            'Meter "%s" configured with None so will be %s',
            meter_name,
            'the identity' if default_is_identity else 'discarded')
        continue

  def process_response(self, metric_response):
    """Transform the spectator response metrics per the spec."""
    result = {}
    for meter_name, spectator_metric in metric_response.items():
      self.process_metric(meter_name, spectator_metric, result)
    return result

  def process_metric(self, meter_name, spectator_metric, response):
    """Produce the desired Spectator metric from existing one.

    Args:
      meter_name: [string] The name of the metric
      spectator_metric: [dict] Individual metric response entry from
          spectator web endpoint.
    response: [dict] The spectator response being built

    Returns:
      None if the meter should be ignored
      Otherwise the transformed metric instance from the spec.
    """
    def add_meter_mapping(meter_name, spectator_metric, response):
      if meter_name in response:
        response[meter_name]['values'].extend(spectator_metric['values'])
      else:
        response[meter_name] = spectator_metric

    rule_list = self.__rulebase.get(meter_name, self.__default_rule_list)
    if not rule_list:
      # if None then discard if not mentioned and default rule was discard
      # otherwise the default rule was the identity
      if rule_list is not None:
        add_meter_mapping(meter_name, spectator_metric, response)
      return

    for rule in rule_list:
      transformed_name = rule.determine_meter_name(meter_name)
      if not transformed_name:
        continue

      transformed = {
          'kind': rule.rule_specification.get('kind') or spectator_metric['kind'],
          'values': rule.apply(spectator_metric)
      }
      add_meter_mapping(transformed_name, transformed, response)
