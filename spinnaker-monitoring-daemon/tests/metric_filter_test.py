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

import copy
import unittest

from metric_filter import MetricFilter

 
ORIGINAL_METRICS = {
  'test.meterOne' : {
    'kind': 'Gauge',
    'values': [{
        'tags': [{'key': 'id', 'value': 'mapped'}],
        'values': [{'t': 1471917869670, 'v': 100.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'direct'}],
        'values': [{'t': 1471917869670, 'v': 200.0}]
     }]
  },
  'test.meterTwo.sameTime' : {
    'kind': 'Counter',
    'values': [{
        'tags': [{'key': 'id', 'value': 'mapped'},
                 {'key': 'deleteMe', 'value': 'X'}],
        'values': [{'t': 1471917869670, 'v': 50.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'mapped'},
                 {'key': 'deleteMe', 'value': 'Y'}],
        'values': [{'t': 1471917869670, 'v': 100.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'direct'},
                 {'key': 'deleteMe', 'value': 'X'}],
        'values': [{'t': 1471917869670, 'v': 200.0}]
     }]
  },
  'test.meterTwo.differentTime' : {
    'kind': 'Counter',
    'values': [{
        'tags': [{'key': 'id', 'value': 'mapped'},
                 {'key': 'deleteMe', 'value': 'X'}],
        'values': [{'t': 1471917869670, 'v': 50.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'mapped'},
                 {'key': 'deleteMe', 'value': 'Y'}],
        'values': [{'t': 1471917869671, 'v': 100.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'direct'},
                 {'key': 'deleteMe', 'value': 'X'}],
        'values': [{'t': 1471917869670, 'v': 200.0}]
     }]
  },
}


FILTERED_METRICS = {
  'test.meterOne' : {
    'kind': 'Gauge',
    'values': [{
        'tags': [{'key': 'id', 'value': 'mapped'}],
        'values': [{'t': 1471917869670, 'v': 100.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'direct'}],
        'values': [{'t': 1471917869670, 'v': 200.0}]
     }]
  },
  'test.meterTwo.sameTime' : {
    'kind': 'Counter',
    'values': [{
        'tags': [{'key': 'id', 'value': 'mapped'}],
        'values': [{'t': 1471917869670, 'v': 150.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'direct'}],
        'values': [{'t': 1471917869670, 'v': 200.0}]
     }]
  },
  'test.meterTwo.differentTime' : {
    'kind': 'Counter',
    'values': [{
        'tags': [{'key': 'id', 'value': 'mapped'}],
        'values': [{'t': 1471917869670, 'v': 50.0},
                   {'t': 1471917869671, 'v': 100.0}]
     }, {
        'tags': [{'key': 'id', 'value': 'direct'}],
        'values': [{'t': 1471917869670, 'v': 200.0}]
     }]
  },
}

TAGLESS_METRICS = {
  'test.meterOne' : {
    'kind': 'Gauge',
    'values': [{
        'tags': [],
        'values': [{'t': 1471917869670, 'v': 300.0}]
     }]
  },
  'test.meterTwo.sameTime' : {
    'kind': 'Counter',
    'values': [{
        'tags': [],
        'values': [{'t': 1471917869670, 'v': 350.0}]
     }]
  },
  'test.meterTwo.differentTime' : {
    'kind': 'Counter',
    'values': [{
        'tags': [],
        'values': [{'t': 1471917869670, 'v': 250.0},
                   {'t': 1471917869671, 'v': 100.0}]
    }]
  },
}


class MetricFilterTest(unittest.TestCase):
  def assertMeterListsEqual(self, expect, got):
      normalized_expect = self.normalize_all_meters(expect)
      normalized_got = self.normalize_all_meters(got)

      self.assertEquals(normalized_expect, normalized_got)

  def normalize_all_meters(self, meters):
      return {key: self.normalize_meter(entries)
              for key, entries in meters.items()}

  def normalize_meter(self, values):
    """Normalize the meter entries so we can compare them.

    Each meter is a list of metrics (tag bindings). The
    order of these must be ordered. We'll order them in the
    order of the bindings of the tag values. For purposes of the
    test this is sufficient since the values are unique. To
    sort the tag bindings, we'll join them all into a string.
    """

    result = []
    for metric in values['values']:
      tags = {tag['key']: tag['value'] for tag in metric['tags']}
      values = [{value['t']: value['v'] for value in metric['values']}]
      result.append({'tags': tags, 'values': values})

    return sorted(result, key=lambda entry: '+'.join(sorted(entry['tags'].values())))
      
  def _expect_all_without_any_tags(self, spec):
    filter = MetricFilter('test', spec)
    all_metrics = copy.deepcopy(ORIGINAL_METRICS)
    got = filter(all_metrics)
    self.assertMeterListsEqual(TAGLESS_METRICS, got)

  def _expect_all_without_delete_me_tag(self, spec):
    filter = MetricFilter('test', spec)
    all_metrics = copy.deepcopy(ORIGINAL_METRICS)
    got = filter(all_metrics)
    self.assertMeterListsEqual(FILTERED_METRICS, got)

  def _expect_all_without_meter_one(self, spec):
    filter = MetricFilter('test', spec)
    expect_metrics = copy.deepcopy(ORIGINAL_METRICS)
    del expect_metrics['test.meterOne']

    all_metrics = copy.deepcopy(ORIGINAL_METRICS)
    got = filter(all_metrics)
    
    self.assertMeterListsEqual(expect_metrics, got)
      
  def test_noop_filter(self):
    spec = {}
    filter = MetricFilter('test', spec)
    all_metrics = copy.deepcopy(ORIGINAL_METRICS)
    got = filter(all_metrics)
    self.assertMeterListsEqual(ORIGINAL_METRICS, got)

  def test_explicit_filter_by_literal_name_as_is(self):
    spec = {
        'meters': {
            'byLiteralName': [
                'test.meterTwo.sameTime',
                'test.meterTwo.differentTime'
            ]
         }
    }
    filter = MetricFilter('test', spec)
    all_metrics = copy.deepcopy(ORIGINAL_METRICS)
    expect_metrics = {
        'test.meterTwo.sameTime': copy.deepcopy(
            all_metrics['test.meterTwo.sameTime']),

        'test.meterTwo.differentTime': copy.deepcopy(
            all_metrics['test.meterTwo.differentTime'])
    }

    got = filter(all_metrics)
    self.assertMeterListsEqual(expect_metrics, got)

  def test_filter_by_literal_name_and_tag(self):
    spec = {
        'meters': {
            'byLiteralName': {
                'test.meterOne': {
                    'includeTagRegex': ['id']
                 },
                'test.meterTwo.sameTime': {
                    'includeTagRegex': ['id']
                },
                'test.meterTwo.differentTime': {
                    'excludeTagRegex': ['deleteMe']
                },
             }
         }
    }
    self._expect_all_without_delete_me_tag(spec)

  def test_filter_by_name_regex_list(self):
    spec = {
        'meters': {
            'byNameRegex': ['bogus', '.*Time']
         }
    }
    self._expect_all_without_meter_one(spec)

  def test_include_by_name_regex_string(self):
    spec = {
        'meters': {
            'byNameRegex': '.*Time'
         }
    }
    self._expect_all_without_meter_one(spec)

  def test_exclude_name_regex_string(self):
    spec = {
        'meters': {
            'excludeNameRegex': '.*meterOne'
         }
    }
    self._expect_all_without_meter_one(spec)

  def test_exclude_name_regex_list(self):
    spec = {
        'meters': {
            'excludeNameRegex': ['.*meterOne']
         }
    }
    self._expect_all_without_meter_one(spec)

  def test_full_yaml(self):
    import yaml
    import textwrap
    spec = textwrap.dedent("""
        meters:
          byLiteralName:
            test.meterTwo.sameTime:
              excudeTagRegex: bogus
            test.meterTwo.differentTime:
              includeTagRegex: .*

          byNameRegex: .*meterOne.*
          excludeNameRegex: .*meterOne.*
    """)
    self._expect_all_without_meter_one(yaml.safe_load(spec))
      
  def test_remove_tag(self):
    spec = {
        'meters': {
            'byNameRegex': {
                '.*': {
                    'excludeTagRegex': 'deleteMe'
                }
    }}}
    self._expect_all_without_delete_me_tag(spec)

  def test_only_id_tag_in_metric(self):
    spec = {
        'meters': {
            'byNameRegex': {
                '.*': {
                   'includeTagRegex': 'i.*'
                }
    }}}
    self._expect_all_without_delete_me_tag(spec)

  def test_only_id_tag_global(self):
    spec = {
        'tags': {
            'includeTagRegex': 'id'
         }
    }
    self._expect_all_without_delete_me_tag(spec)

  def test_exclude_tag_global(self):
    spec = {
        'tags': {
            'excludeTagRegex': 'delete*'
         }
    }
    self._expect_all_without_delete_me_tag(spec)

  def test_delete_tag_has_precedence_in_meter(self):
    spec = {
        'meters': {
            'byNameRegex': {
                '.*': {
                   'includeTagRegex': '.*',  # lower precedence
                   'excludeTagRegex': 'delete.*'
                }
    }}}
    self._expect_all_without_delete_me_tag(spec)

  def test_explicit_include_tag_has_precedence_over_global(self):
    spec = {
        'meters': {
            'byNameRegex': {
                '.*': {
                   'includeTagRegex': ['id']
                }
        }},
        'tags': {
           'excludeTagRegex': ['id', 'deleteMe']
        }
    }
    self._expect_all_without_delete_me_tag(spec)

  def test_explicit_exclude_tag_has_precedence_over_global(self):
    spec = {
        'meters': {
            'byNameRegex': {
                '.*': {
                   'excludeTagRegex': ['deleteMe']
                }
        }},
        'tags': {
           'includeTagRegex': ['id', 'deleteMe']
        }
    }
    self._expect_all_without_delete_me_tag(spec)

  def test_no_tags_by_meter(self):
    spec = {
        'meters': {
            'byNameRegex': {
                '.*': {
                   'excludeTagRegex': '.*'
                }
    }}}
    self._expect_all_without_any_tags(spec)

  def test_no_tags_global(self):
    spec = {
        'tags': {
           'excludeTagRegex': '.*'
        }
    }
    self._expect_all_without_any_tags(spec)


if __name__ == '__main__':
  unittest.main()
