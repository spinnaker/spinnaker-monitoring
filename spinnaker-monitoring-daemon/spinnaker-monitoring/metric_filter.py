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

"""Filter spectator metrics

This filter is specified with a yaml file.

There are three ways to filter, in the following order

meters:
  # If this section is empty, then all meters are assumed to match.
  #
  # names in byLiteralName has highest precedence.
  # Otherwise, the metric will not be included if it matches excludeNameRegex.
  # Otherwise, the metric will be included if it matches byNameRegex.
  #    If the name matches multiple byNameRegex then a random entry is taken.
  byLiteralName:
    # If the name appears here, it will be included
    - <explicit metric name>:
       # If includeTags is specified then only those tags explicitly listed
       # are included. Otherwise include all that do not appear in excludeTags.
       includeTagRegex:
         - <tag name regex>
       excludeTagRegex:
         - <tag name regex>

  byNameRegex:
    # If the name matches a regex here, it will be included.
    - <metric name regex>:
       # If includeTags is specified then only those tags explicitly listed
       # are included. Otherwise include all that do not appear in excludeTags.
       includeTagRegex:
         - <tag name regex>
       excludeTagRegex:
         - <tag name regex>

  excludeNameRegex:
    # If the name matches a regex here, it will not be included,
    # unless it also appears in byLiteralName.
    - <metric name regex>

tags:
  # By default include or exclude the following tags.
  # Individual meter specs have precedence. So if we
  # say to include something here but a meter says exclude
  # then it is excluded.

  includeTagRegex:
    - <tag name regex>

  excludeTagRegex:
    - <tag name regex>
"""

import logging
import re


def get_as_list(container, key):
  """Helper function for getting key value from container.

  If the value is a string, return it as a list containing the string.
  This way we can allow for either single values or lists of values.
  """
  regex_list = container.get(key, [])
  if isinstance(regex_list, basestring):
    return [regex_list]
  return regex_list


class MeterSpec(object):
  """Specifies the tags to make visible for an individual meter.

  The constructor adds a "has_tag" method.
  """
  # pylint: disable=too-few-public-methods

  def __init__(self, include_tag_regex, exclude_tag_regex):
    if not include_tag_regex and not exclude_tag_regex:
      self.has_tag = self.__identity_has_tag
    else:
      self.has_tag = self.__determine_has_tag

    if isinstance(include_tag_regex, basestring):
      include_tag_regex = [include_tag_regex]
    if isinstance(exclude_tag_regex, basestring):
      exclude_tag_regex = [exclude_tag_regex]

    self.__include_tag_regex = [re.compile(regex)
                                for regex in include_tag_regex]
    self.__exclude_tag_regex = [re.compile(regex)
                                for regex in exclude_tag_regex]
    self.__include_tag_literal = set()
    self.__exclude_tag_literal = set()

  def __identity_has_tag(self, _, default_value=True):
    return default_value

  def __determine_has_tag(self, tag, default_value=True):
    # Determine from the regular expressions.
    # Cache the results for future reference.
    if tag in self.__include_tag_literal:
      return True
    if tag in self.__exclude_tag_literal:
      return False

    for regex in self.__exclude_tag_regex:
      if regex.match(tag):
        self.__exclude_tag_literal.add(tag)
        return False

    for regex in self.__include_tag_regex:
      if regex.match(tag):
        self.__include_tag_literal.add(tag)
        return True

    if self.__include_tag_regex:
      # Not among those for selective inclusion
      self.__exclude_tag_literal.add(tag)
      return False

    # Default is True unless we said to exclude it,
    # which apparently we did not.
    self.__include_tag_literal.add(tag)
    return default_value


class MetricFilter(object):
  """Determines which meters and tags should be visible.

  Attributes:
    __exclude_name_literal: Set of names known to be excluded.
    __exclude_name_regexes: List of regexes of names to exclude.

    __name_literal_to_meter_spec: Dictionary of known names to include
                            and their MeterSpec specifying tags.
    __include_name_regexes: List of tuples of the name regular expression
                            and their MeterSpec specifying tags.
  """

  def __init__(self, name, filter_spec, **kwargs):
    """Initialize a new metric filter using the given specification."""
    self.__init_tags(filter_spec)
    self.__init_meters(filter_spec)
    self.__filter_name = name
    self.__log_meters_found = kwargs.pop('log_meters', True)
    self.__log_labels_found = kwargs.pop('log_labels', True)

  def __init_tags(self, filter_spec):
    tags = filter_spec.get('tags', {})
    self.__default_tag_map = {}  # True indicates Maybe

    regex_list = get_as_list(tags, 'includeTagRegex')
    self.__include_tag_regexes = [
        re.compile(regex) for regex in regex_list]

    regex_list = get_as_list(tags, 'excludeTagRegex')
    self.__exclude_tag_regexes = [
        re.compile(regex) for regex in regex_list]

    # Keep tags by default unless we specify include regexes.
    self.__default_keep_tag = not self.__include_tag_regexes

  def keep_tag_by_default(self, tag):
    """Determine whether or not to keep the tag by default.

    The default can be overwriden by the specific MeterSpec.
    """
    result = self.__default_tag_map.get(tag)
    if result is not None:
      return result
    for regex in self.__exclude_tag_regexes:
      if regex.match(tag):
        self.__default_tag_map[tag] = False
        return False
    for regex in self.__include_tag_regexes:
      if regex.match(tag):
        self.__default_tag_map[tag] = True
        return True
    self.__default_tag_map[tag] = self.__default_keep_tag
    return self.__default_keep_tag

  def __init_meters(self, filter_spec):
    meters = filter_spec.get('meters', {})

    # Exclude
    self.__exclude_name_literal = set()
    regex_list = get_as_list(meters, 'excludeNameRegex')
    self.__exclude_name_regexes = [re.compile(regex) for regex in regex_list]

    # Include
    literal_name_spec = get_as_list(meters, 'byLiteralName')
    if isinstance(literal_name_spec, list):
      self.__name_literal_to_meter_spec = {
          name: MeterSpec([], [])
          for name in literal_name_spec}
    else:
      self.__name_literal_to_meter_spec = {
          name: MeterSpec(get_as_list((spec or {}), 'includeTagRegex'),
                          get_as_list((spec or {}), 'excludeTagRegex'))
          for name, spec in literal_name_spec.items()}

    # Regex name
    regex_name_spec = get_as_list(meters, 'byNameRegex')
    if isinstance(regex_name_spec, list):
      self.__include_name_regexes = [
          (re.compile(name), MeterSpec([], []))
          for name in regex_name_spec]
    else:
      self.__include_name_regexes = [
          (re.compile(name),
           MeterSpec(
               get_as_list(spec, 'includeTagRegex'),
               get_as_list(spec, 'excludeTagRegex')))
          for name, spec in regex_name_spec.items()]

    self.__default_spec = self.__determine_default_spec()

  def __determine_default_spec(self):
    if not (self.__include_name_regexes or self.__name_literal_to_meter_spec):
      return MeterSpec([], [])
    return None

  def combine_values(self, first, second):
    """Combine the value lists by common timestamps."""
    result = first
    for record in second:
      t = record['t']
      v = record['v']
      have = False
      for check in result:
        if check['t'] == t:
          have = True
          check['v'] += v
          break
      if not have:
        result.append(record)
        # Ensure values are in timestamp order
        result = sorted(result, key=lambda x: x['t'])

    return result

  def filter_tags(self, metric_spec, data):
    """Mutate data to only keep tags of interest.

    If tags are dropped, we'll need to aggregate the data.
    For example if we had a values with:
       {A='a', X='x'}=10
       {A='a', X='y'}=5
       {A='b', X='x'}=20
    And we remove the tag X, then we have
       {A='a'}=15
       {A='b'}=20
    """
    metrics = data['values']
    tags_hash_to_values = {}
    hash_to_tags = {}
    for metric in metrics:
      values = metric['values']
      tags = sorted([tag for tag in metric['tags']
                     if metric_spec.has_tag(
                         tag['key'],
                         default_value=self.keep_tag_by_default(tag['key']))],
                    key=lambda entry: entry['key'])
      key = str(tags)
      hash_to_tags[key] = tags
      old_values = tags_hash_to_values.get(key)
      if old_values:
        values = self.combine_values(values, old_values)
      tags_hash_to_values[key] = values

    result = dict(data)
    result['values'] = [
        {'tags': hash_to_tags[key], 'values': values}
        for key, values in tags_hash_to_values.items()]

    return result

  def __call__(self, all_metrics):
    def regex_is_excluded(name):
      """Helper function for managing excluded name cache.

      Real point is to allow us to break from inner loop.
      """
      for regex in self.__exclude_name_regexes:
        if regex.match(name):
          self.__exclude_name_literal.add(name)
          if self.__log_meters_found:
            logging.info('Found %s meter "%s": EXCLUDE from pattern "%s"',
                         self.__filter_name, name, regex.pattern)
          return True
      return False

    result = {}
    for name, data in all_metrics.items():
      if name in self.__exclude_name_literal:
        continue
      spec = self.__name_literal_to_meter_spec.get(name, None)
      if spec is None:
        if regex_is_excluded(name):
          continue

        for info in self.__include_name_regexes:
          if info[0].match(name):
            spec = info[1]
            self.__name_literal_to_meter_spec[name] = spec
            if self.__log_meters_found:
              logging.info('Found %s meter "%s": INCLUDE from pattern "%s"',
                           self.__filter_name, name, info[0].pattern)
            break

      if spec is None:
        # Did not match any of the regular expressions
        spec = self.__default_spec
        if not spec:
          self.__exclude_name_literal.add(name)
          continue
        self.__name_literal_to_meter_spec[name] = spec

      # At this point we want to keep name, using spec
      result[name] = self.filter_tags(spec, data)

    return result
