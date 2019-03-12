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

# pylint: disable=line-too-long
# pylint: disable=missing-docstring

import copy
import textwrap
import unittest

import yaml

from spectator_metric_transformer import (
    AggregatedMetricsBuilder,
    MetricInfo,
    SpectatorMetricTransformer,
    TransformationRule)


# This is a sample spectator response containing
# a single value for a single measurmement of a 'jvm.memory.used' meter.
#
# We'll be using it in many of our tests showing how different transforms
# apply to it.
EXAMPLE_MEMORY_USED_RESPONSE = {
    'jvm.memory.used': {
        'kind': 'Gauge',
        'values': [{
            'values': [{'t': 1540224536922, 'v': 1489720024.0}],
            'tags': [
                {'key': 'id', 'value': 'PS Eden Space'},
                {'key': 'memtype', 'value': 'HEAP'},
            ]
        }]
    }
}


def sort_tag_dictionaries(list_of_dict):
  return sorted(list_of_dict, key=lambda d: d['key'])

def sort_dictionaries(list_of_dict):
  return sorted(list_of_dict, key=lambda d: str(d))


class AggregatedBuilderTest(unittest.TestCase):
  TIMESTAMP = 987654321
  def _make_values(self, count):
    return [{'v': 100 + i, 't': self.TIMESTAMP+i}
            for i in range(count)]

  def _make_tags(self, **kwargs):
    return [{'key': key, 'value': value} for key, value in kwargs.items()]

  def _make_simple_rule_builder(self, options=None):
    # transformer isnt used for these tests, but is required to construct
    options = options or {}
    transformer = SpectatorMetricTransformer(options, {})

    rule = TransformationRule(
        transformer,
        {
            'rename': 'NewName',
            'kind': 'Timer',
            'tags': ['status'],
        })
    # The builder only uses the kind part of the rule.
    # The other parts of the rule are used when it is applied
    # to preprocess the response before adding to the builder.
    return AggregatedMetricsBuilder(rule)

  def _make_timer_measurements(self, status='2xx'):
    t, v = {'2xx': (0, 0),
            '4xx': (0, 400),   # different value same time
            '5xx': (500, 500), # different value different time
            '0xx': (500, 0),   # same value different time
           }[status]
    if status == '0xx':
      status = '2xx'

    return [
        {'values': [{'v':123 + v, 't': self.TIMESTAMP + t}],
         'tags': self._make_tags(status=status, statistic='count')},
        {'values': [{'v':321 + v, 't': self.TIMESTAMP + t}],
         'tags': self._make_tags(status=status, statistic='totalTime')}
    ]

  def _determine_expected_tags(self, measurement):
    expect_tags = list(measurement['tags'])
    for i, entry in enumerate(expect_tags):
      if entry['key'] == 'statistic':
        del expect_tags[i]
        break
    return sorted(expect_tags, key=lambda d: d['key'])

  def do_test_compound_kind_as_is(self, builder):
    # This test is just showing nothing interesting happening
    # and we get out what we put in.
    for measurement in self._make_timer_measurements():
      builder.add(measurement['values'][0], measurement['tags'])
    self.assertEquals(
        sort_dictionaries([
            {
                'values': [{'v': 123, 't': self.TIMESTAMP}],
                'tags': sort_tag_dictionaries([{'key': 'status', 'value': '2xx'},
                                {'key': 'statistic', 'value': 'count'}])
            },
            {
                'values': [{'v': 321, 't': self.TIMESTAMP}],
                'tags': sort_tag_dictionaries([{'key': 'status', 'value': '2xx'},
                                {'key': 'statistic', 'value': 'totalTime'}])
            }
        ]),
        sort_dictionaries(builder.build()))

  def test_timer(self):
    builder = self._make_simple_rule_builder()
    self.do_test_compound_kind_as_is(builder)

  def test_summary_as_is(self):
    options = {}
    transformer = SpectatorMetricTransformer(options, {})
    rule = TransformationRule(
        transformer,
        {
            'rename': 'NewName',
            'kind': 'DistributionSummary',
            'tags': ['status'],
        })
    builder = AggregatedMetricsBuilder(rule)
    self.do_test_compound_kind_as_is(builder)

  def test_summary_summarize(self):
    options = {'summarize_compound_kinds': True}
    transformer = SpectatorMetricTransformer(options, {})
    rule = TransformationRule(
        transformer,
        {
            'rename': 'NewName',
            'kind': 'DistributionSummary',
            'tags': ['status'],
        })
    builder = AggregatedMetricsBuilder(rule)
    for measurement in self._make_timer_measurements():
      builder.add(measurement['values'][0], measurement['tags'])
    self.assertEquals(
        [{
            'values': [{'v': {'count': 123, 'totalTime': 321},
                        't': self.TIMESTAMP}],
            'tags': [{'key': 'status', 'value': '2xx'}]
        }],
        sort_dictionaries(builder.build())
    )

  def test_collate_one_measurement(self):
    builder = self._make_simple_rule_builder()
    rule = builder.rule
    output = {}
    measurements = self._make_timer_measurements()
    for measurement in measurements:
      builder._collate_metric_info(
          MetricInfo(measurement['values'][0],
                     sort_tag_dictionaries(measurement['tags']),
                     rule),
          output)

    self.assertEquals(
        sort_dictionaries([
            MetricInfo({'t': self.TIMESTAMP,
                        'v': {'count': 123, 'totalTime': 321}},
                       self._determine_expected_tags(measurements[0]),
                       rule)
        ]),
        sort_dictionaries(output.values()))

  def test_collate_multiple_measurements(self):
    builder = self._make_simple_rule_builder()
    rule = builder.rule
    output = {}
    measurements2xx = self._make_timer_measurements(status='2xx')
    measurements4xx = self._make_timer_measurements(status='4xx')
    measurements5xx = self._make_timer_measurements(status='5xx')
    measurements = [
        measurements2xx[0],
        measurements4xx[1],
        measurements5xx[0],
        measurements4xx[0],
        measurements2xx[1],
        measurements5xx[1],
    ]
    for measurement in measurements:
      builder._collate_metric_info(
          MetricInfo(measurement['values'][0],
                     sort_tag_dictionaries(measurement['tags']),
                     rule),
          output)

    expect_values = [
        MetricInfo({'t': self.TIMESTAMP,
                    'v': {'count': 123, 'totalTime': 321}},
                   self._determine_expected_tags(measurements2xx[0]),
                   rule),

        # different value, same time
        MetricInfo({'t': self.TIMESTAMP,
                    'v': {'count': 123 + 400, 'totalTime': 321 + 400}},
                   self._determine_expected_tags(measurements4xx[0]),
                   rule),

        # different value, different time
        MetricInfo({'t': self.TIMESTAMP + 500,
                    'v': {'count': 123 + 500, 'totalTime': 321 + 500}},
                   self._determine_expected_tags(measurements5xx[0]),
                   rule)
    ]

    for got in output.values():
      found = False
      for index, expect in enumerate(expect_values):
        if got == expect:
          del expect_values[index]
          found = True
          break
      self.assertTrue(found, msg='Missing %r' % got)
    self.assertEquals([], expect_values)

  def test_summarize_timers_and_build(self):
    options = {'summarize_compound_kinds': True}
    builder = self._make_simple_rule_builder(options=options)
    measurements2xx = self._make_timer_measurements(status='2xx')
    measurements4xx = self._make_timer_measurements(status='4xx')
    measurements5xx = self._make_timer_measurements(status='5xx')
    measurements0xx = self._make_timer_measurements(status='0xx')
    measurements = [
        measurements2xx[0],
        measurements4xx[1],
        measurements5xx[0],
        measurements0xx[0],
        measurements4xx[0],
        measurements2xx[1],
        measurements0xx[1],
        measurements5xx[1],
    ]
    for measurement in measurements:
      builder.add(measurement['values'][0], measurement['tags'])

    self.assertEquals(
        sort_dictionaries([
            # 2xx and 0xx got combined together because tags are same
            # timestamp is bumped to 0xx's which was later.
            {
                'values': [{'t': self.TIMESTAMP + 500,
                            'v': {'count': 2 * 123, 'totalTime': 2 * 321}}],
                'tags': self._determine_expected_tags(measurements2xx[0])
            },
            # different tags, same timestamp (from 2xx)
            {
                'values': [{'t': self.TIMESTAMP,
                            'v': {'count': 123 + 400, 'totalTime': 321 + 400}}],
                'tags': self._determine_expected_tags(measurements4xx[0])
            },
            # different tags, different timestamp (from 2xx)
            {
                'values': [{'t': self.TIMESTAMP + 500,
                            'v': {'count': 123 + 500, 'totalTime': 321 + 500}}],
                'tags': self._determine_expected_tags(measurements5xx[0])
            }
        ]),
        sort_dictionaries(builder.build())
    )


class SpectatorMetricTransformerTest(unittest.TestCase):
  def do_test(self, spec_yaml, spectator_response, expect_response,
              options=None):
    spec = yaml.load(spec_yaml)
    options = options or {}
    transformer = SpectatorMetricTransformer(options, spec)
    got_response = transformer.process_response(spectator_response)

    for _, got_meter_data in got_response.items():
      values = got_meter_data.get('values')
      if values:
        got_meter_data['values'] = sort_dictionaries(values)

    self.assertResponseEquals(expect_response, got_response)

  def assertResponseEquals(self, expect_response, got_response):
    if expect_response != got_response:
      print('Expected: %r\n'
            'Actual:   %r\n'
            % (expect_response, got_response))
    self.assertEquals(expect_response, got_response)

    if str(expect_response) != str(got_response):
      print('Expected: %r\n'
            'Actual:   %r\n'
            % (expect_response, got_response))
    self.assertEquals(str(expect_response), str(got_response))

  def test_discard_default(self):
    spectator_response = EXAMPLE_MEMORY_USED_RESPONSE
    spec = {}
    transformer = SpectatorMetricTransformer({}, spec)
    got_response = transformer.process_response(spectator_response)
    self.assertResponseEquals({}, got_response)

  def test_identity_default(self):
    spectator_response = EXAMPLE_MEMORY_USED_RESPONSE
    spec = {}
    options = {'default_is_identity': True}
    transformer = SpectatorMetricTransformer(options, spec)
    got_response = transformer.process_response(spectator_response)
    self.assertResponseEquals(spectator_response, got_response)

  def test_identity_explicit(self):
    spectator_response = EXAMPLE_MEMORY_USED_RESPONSE
    spec = {'jvm.memory.used': None}
    transformer = SpectatorMetricTransformer({}, spec)
    got_response = transformer.process_response(spectator_response)
    self.assertResponseEquals(spectator_response, got_response)

  def test_stackdriver_timers(self):
    spec = {}
    transformer = SpectatorMetricTransformer(
        {'enforce_stackdriver_names': True}, spec)

    do_name = transformer.normalize_meter_name
    self.assertEquals('timers', do_name('timers', 'Gauge'))
    self.assertEquals('timers', do_name('timers', 'Counter'))
    self.assertEquals('timer_latencies', do_name('timer', 'Timer'))
    self.assertEquals('timer_latencies', do_name('timers', 'Timer'))
    self.assertEquals('timer_latencies', do_name('timer_latencies', 'Timer'))
    self.assertEquals('timer_latencies', do_name('timerLatencies', 'Timer'))

    do_label = transformer.normalize_label_name
    self.assertEquals('status_code', do_label('status_code'))
    self.assertEquals('status_code', do_label('statusCode'))
    self.assertEquals('status_code_class', do_label('status'))

  def test_snakeify(self):
    spec = {}
    transformer = SpectatorMetricTransformer({'use_snake_case': True}, spec)
    snakeify = lambda name: transformer.normalize_text_case(name)
    self.assertEquals('test', snakeify('test'))
    self.assertEquals('test', snakeify('Test'))
    self.assertEquals('test', snakeify('TEST'))
    self.assertEquals('camel_case', snakeify('camelCase'))
    self.assertEquals('title_case', snakeify('TitleCase'))
    self.assertEquals('snake_case', snakeify('Snake_Case'))
    self.assertEquals('http_response', snakeify('HTTPResponse'))
    self.assertEquals('upper_case', snakeify('UPPER_CASE'))

  def test_change_meter_name_explicit(self):
    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              rename: platform/java/memory
        """),

        EXAMPLE_MEMORY_USED_RESPONSE,
        {'platform/java/memory':
             EXAMPLE_MEMORY_USED_RESPONSE['jvm.memory.used']}
    )

  def test_change_meter_name(self):
    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              rename: memoryUsed
        """),

        EXAMPLE_MEMORY_USED_RESPONSE,
        {'memoryUsed': EXAMPLE_MEMORY_USED_RESPONSE['jvm.memory.used']}
    )

  def test_change_meter_name_snakeify(self):
    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              rename: memoryUsed
        """),

        EXAMPLE_MEMORY_USED_RESPONSE,
        {'memory_used': EXAMPLE_MEMORY_USED_RESPONSE['jvm.memory.used']},
        options={'use_snake_case': True}
    )

  def test_discard_meter_by_name(self):
    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              rename:
        """),

        EXAMPLE_MEMORY_USED_RESPONSE,
        {}
    )

  def test_change_tag_names(self):
    transformed_value = copy.deepcopy(
        EXAMPLE_MEMORY_USED_RESPONSE['jvm.memory.used'])
    transformed_value['values'][0]['tags'] = sort_tag_dictionaries([
        {'key': 'segment', 'value': 'PS Eden Space'},
        {'key': 'scope', 'value': 'HEAP'},
    ])

    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              rename: platform/java/memory
              change_tags:
                - from: memtype
                  to: scope
                  type: STRING

                - from: id
                  to: segment
                  type: STRING
        """),

        EXAMPLE_MEMORY_USED_RESPONSE,
        {'platform/java/memory': transformed_value}
    )

  def _do_test_add_tags(self, tags_are_typed):
    if tags_are_typed:
      expect_true_value = True
      expect_false_value = False
      expect_num_value = 123
      options = {'tags_are_typed': True}
    else:
      expect_true_value = 'true'
      expect_false_value = 'false'
      expect_num_value = '123'
      options = {}

    transformed_value = copy.deepcopy(
        EXAMPLE_MEMORY_USED_RESPONSE['jvm.memory.used'])
    transformed_value['values'][0]['tags'] = sort_tag_dictionaries(
        transformed_value['values'][0]['tags']
        + [
            {'key': 'first', 'value': 'FIRST'},
            {'key': 'T', 'value': expect_true_value},
            {'key': 'F', 'value': expect_false_value},
            {'key': 'S', 'value': 'true'},
            {'key': 'numeric', 'value': expect_num_value},
        ])

    normalized_orig = copy.deepcopy(EXAMPLE_MEMORY_USED_RESPONSE)
    normalized_orig['jvm.memory.used']['values'][0]['tags'] = sort_tag_dictionaries(
       normalized_orig['jvm.memory.used']['values'][0]['tags'])

    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              add_tags:
                first: FIRST
                T: true
                F: false
                S: 'true'
                numeric: 123
        """),

        normalized_orig,
        {'jvm.memory.used': transformed_value},
        options=options
    )

  def test_add_tags_typed(self):
    self._do_test_add_tags(True)

  def test_add_tags_untyped(self):
    self._do_test_add_tags(False)

  def test_consolidate_metrics(self):
    self.do_test(
        textwrap.dedent("""\
          storageServiceSupport.autoRefreshTime:
            kind: Timer
            rename: front50/cache/refresh
            tags:
              - objectType
              - statistic
            add_tags:
              scheduled: false

          storageServiceSupport.scheduledRefreshTime:
            kind: Timer
            rename: front50/cache/refresh
            tags:
              - objectType
              - statistic
            add_tags:
              scheduled: true
        """),

        {
            'storageServiceSupport.autoRefreshTime': {
                'kind': 'Timer',
                'values': [{
                    'values': [{'t': 1540224536920, 'v': 10000.0}],
                    'tags': [
                        {'key': 'objectType', 'value': 'PIPELINES'},
                        {'key': 'statistic', 'value': 'totalTime'},
                    ]
                }]},
            'storageServiceSupport.scheduledRefreshTime': {
                'kind': 'Timer',
                'values': [{
                    'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                    'tags': [
                        {'key': 'objectType', 'value': 'PIPELINES'},
                        {'key': 'statistic', 'value': 'totalTime'},
                    ]
                }]}
        },


        {'front50/cache/refresh': {
            'kind': 'Timer',
            'values': [{
                'values': [{'t': 1540224536920, 'v': 10000.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'objectType', 'value': 'PIPELINES'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'scheduled', 'value': 'false'}
                ])
            }, {
                'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'objectType', 'value': 'PIPELINES'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'scheduled', 'value': 'true'}
                ])
            }
                      ]
        }}
    )

  def test_change_value_to_type_int(self):
    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              value_type: SCALAR
              tags:
                - id
        """),

        {'jvm.memory.used': {
            'kind': 'Gauge',
            'values': sort_dictionaries([
                {'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                 'tags': [
                     {'key': 'id', 'value': 'PS Eden Space'},
                 ]},
                {'values': [{'t': 1540224536923, 'v': 12345.0}],
                 'tags': [
                     {'key': 'id', 'value': 'Code Cache'},
                 ]},
            ])},
        },

        {'jvm.memory.used': {
            'kind': 'Gauge',
            'values': sort_dictionaries([
                {'values': [{'t': 1540224536922, 'v': 1489720024}],
                 'tags': sort_tag_dictionaries([
                     {'key': 'id', 'value': 'PS Eden Space'},
                 ])},
                {'values': [{'t': 1540224536923, 'v': 12345}],
                 'tags': sort_tag_dictionaries([
                     {'key': 'id', 'value': 'Code Cache'},
                 ])},
            ])},
        },
        options={'transform_values': True}
    )

  def test_change_value_to_type_bool(self):
    self.do_test(
        textwrap.dedent("""\
            is_on:
              value_type: BOOL
              tags:
                - note
        """),
        {'is_on': {
            'kind': 'Gauge',
            'values': sort_dictionaries([
                {'values': [{'t': 1540224536922, 'v': 1.0}],
                 'tags': [
                     {'key': 'note', 'value': 'on'},
                 ]},
                {'values': [{'t': 1540224536923, 'v': 0.0}],
                 'tags': [
                     {'key': 'note', 'value': 'off'},
                 ]},
            ])},
        },

        {'is_on': {
            'kind': 'Gauge',
            'values': sort_dictionaries([
                {'values': [{'t': 1540224536922, 'v': True}],
                 'tags': sort_tag_dictionaries([
                     {'key': 'note', 'value': 'on'},
                 ])},
                {'values': [{'t': 1540224536923, 'v': False}],
                 'tags': sort_tag_dictionaries([
                     {'key': 'note', 'value': 'off'},
                 ])},
            ])},
        },
        options={'transform_values': True}
    )

  def test_change_tag_to_type_bool(self):
    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              tags:
                - id
              change_tags:
                - from: memtype
                  to: heap
                  type: BOOL
                  compare_value: HEAP
        """),

        {'jvm.memory.used': {
            'kind': 'Gauge',
            'values': sort_dictionaries([
                {'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                 'tags': [
                     {'key': 'id', 'value': 'PS Eden Space'},
                     {'key': 'memtype', 'value': 'HEAP'},
                 ]},
                {'values': [{'t': 1540224536923, 'v': 12345.0}],
                 'tags': [
                     {'key': 'id', 'value': 'Code Cache'},
                     {'key': 'memtype', 'value': 'NON HEAP'},
                 ]},
            ])},
        },

        {'jvm.memory.used': {
            'kind': 'Gauge',
            'values': sort_dictionaries([
                {'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                 'tags': sort_tag_dictionaries([
                     {'key': 'id', 'value': 'PS Eden Space'},
                     {'key': 'heap', 'value': True},
                 ])},
                {'values': [{'t': 1540224536923, 'v': 12345.0}],
                 'tags': sort_tag_dictionaries([
                     {'key': 'id', 'value': 'Code Cache'},
                     {'key': 'heap', 'value': False},
                 ])},
            ])},
        },
        options={'tags_are_typed': True}
    )

  def test_change_tag_to_type_int(self):
    self.do_test(
        textwrap.dedent("""\
            controller.invocations:
              tags:
                - controller
                - method
                - statistic
                - status

              change_tags:
                - from: statusCode
                  to: statusCode
                  type: INT
        """),

        {'controller.invocations': {
            'kind': 'Timer',
            'values': [
                {'values': [{'t': 1540318956420, 'v': 300130409.0}],
                 'tags': [
                     {'key': 'controller', 'value': 'ClusterController'},
                     {'key': 'method', 'value': 'getServerGroup'},
                     {'key': 'statistic', 'value': 'totalTime'},
                     {'key': 'status', 'value': '2xx'},
                     {'key': 'statusCode', 'value': '200'},
                 ]}
            ]},
        },

        {'controller.invocations': {
            'kind': 'Timer',
            'values': [
                {'values': [{'t': 1540318956420, 'v': 300130409.0}],
                 'tags': [
                     {'key': 'controller', 'value': 'ClusterController'},
                     {'key': 'method', 'value': 'getServerGroup'},
                     {'key': 'statistic', 'value': 'totalTime'},
                     {'key': 'status', 'value': '2xx'},
                     {'key': 'statusCode', 'value': 200},
                 ]}
            ]},
        },
        options={'tags_are_typed': True}
    )

  def test_oneof_tag_values(self):
    self.do_test(
        textwrap.dedent("""\
            onDemand_count:
              change_tags:
                - from: providerName
                  to: provider
                  type: STRING
                  oneof_regex: '.*\.provider\.(.*)|(kubernetes)'
        """),

        {'onDemand_count': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 1.0}],
                'tags': [
                    {'key': 'providerName',
                     'value': 'org.spinnaker.provider.MyProvider'}
                ]
            }, {
                'values': [{'t': 1540224536923, 'v': 2.0}],
                'tags': [
                    {'key': 'providerName',
                     'value': 'kubernetes'}
                ]
            },
                             ])},
        },

        {'onDemand_count': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 1.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'provider', 'value': 'MyProvider'},
                ])
            },
            {
                'values': [{'t': 1540224536923, 'v': 2.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'provider', 'value': 'kubernetes'},
                ])
            }
                             ])}
        }
    )

  def test_oneof_tag_values(self):
    self.do_test(
        textwrap.dedent("""\
            onDemand_count:
              change_tags:
                - from: providerName
                  to: provider
                  type: STRING
                  oneof_regex: '.*\.provider\.(.*)|(kubernetes)'
        """),

        {'onDemand_count': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 1.0}],
                'tags': [
                    {'key': 'providerName',
                     'value': 'org.spinnaker.provider.MyProvider'}
                ]
            }, {
                'values': [{'t': 1540224536923, 'v': 2.0}],
                'tags': [
                    {'key': 'providerName',
                     'value': 'kubernetes'}
                ]
            },
                             ])},
        },

        {'onDemand_count': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 1.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'provider', 'value': 'MyProvider'},
                ])
            },
            {
                'values': [{'t': 1540224536923, 'v': 2.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'provider', 'value': 'kubernetes'},
                ])
            }
                             ])}
        }
    )

  def test_decompose_tag(self):
    self.do_test(
        textwrap.dedent("""\
            executionCount:
              tags:
                - status

              change_tags:
                - from: agent
                  to: [provider, account, region, agent]
                  type: [STRING, STRING, STRING, STRING]
                  extract_regex: '([^/]+)/(?:([^/]+)/(?:([^/]+)/)?)?(.+)'
        """),

        {'executionCount': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540318956422, 'v': 23258.0}],
                'tags': [
                    {'key': 'agent',
                     'value': 'com.netflix.spinnaker.clouddriver.google.provider.GoogleInfrastructureProvider/my-google-account/australia-southeast1/GoogleSubnetCachingAgent'},
                    {'key': 'status', 'value': 'success'}
                ]
            }, {
                'values': [{'t': 1540318956422, 'v': 9.0}],
                'tags': [
                    {'key': 'agent',
                     'value': 'com.netflix.spinnaker.clouddriver.appengine.provider.AppengineProvider/my-appengine-account/AppenginePlatformApplicationCachingAgent'},
                    {'key': 'status', 'value': 'failure'},
                ]
            },
                             ])},
        },

        {'executionCount': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540318956422, 'v': 23258.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'provider',
                     'value': 'com.netflix.spinnaker.clouddriver.google.provider.GoogleInfrastructureProvider'},
                    {'key': 'account', 'value': 'my-google-account'},
                    {'key': 'region', 'value': 'australia-southeast1'},
                    {'key': 'agent', 'value': 'GoogleSubnetCachingAgent'},
                    {'key': 'status', 'value': 'success'}
                ])
            }, {
                'values': [{'t': 1540318956422, 'v': 9.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'provider',
                     'value': 'com.netflix.spinnaker.clouddriver.appengine.provider.AppengineProvider'},
                    {'key': 'account', 'value': 'my-appengine-account'},
                    {'key': 'region', 'value': ''},
                    {'key': 'agent', 'value': 'AppenginePlatformApplicationCachingAgent'},
                    {'key': 'status', 'value': 'failure'},
                ])
            }
                             ])}
        }
    )

  def test_remove_tag(self):
    self.do_test(
        textwrap.dedent("""\
            controller.invocations:
              tags:
                - controller
                - method
                - status
                # "statistic" is implicit
        """),

        {'controller.invocations': {
            'kind': 'Timer',
            'values': [{
                'values': [{'t': 12345, 'v': 1111.0}],
                'tags': [
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'status', 'value': '4xx'},
                    {'key': 'statusCode', 'value': '400'},
                ]
            }, {
                'values': [{'t': 12346, 'v': 2222.0}],
                'tags': [
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'status', 'value': '2xx'},
                    {'key': 'statusCode', 'value': '200'},
                ]
            }, {
                'values': [{'t': 12347, 'v': 4444.0}],
                'tags': [
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'status', 'value': '4xx'},
                    {'key': 'statusCode', 'value': '404'},
                ]
            }, {
                'values': [{'t': 12348, 'v': 8888.0}],
                'tags': [
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'count'},
                    {'key': 'status', 'value': '4xx'},
                    {'key': 'statusCode', 'value': '404'},
                ]
            },
                      ]}
        },

        {'controller.invocations': {
            'kind': 'Timer',
            'values': sort_dictionaries([{
                'values': [{'t': 12347, 'v': 5555.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'status', 'value': '4xx'},
                ])
            }, {
                'values': [{'t': 12346, 'v': 2222.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'status', 'value': '2xx'},
                ])
            }, {
                'values': [{'t': 12348, 'v': 8888.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'count'},
                    {'key': 'status', 'value': '4xx'},
                ])
            },
                             ])},
        }
    )

  def _do_remove_tag_bool_value(self, options, expect):
    """Tests how measurements that are BOOL combine together."""
    maybe_default_value = (
        "'default_value': {expect}".format(expect=expect)
        if isinstance(expect, bool)
        else ''
    )
    self.do_test(
        textwrap.dedent("""\
            is_on:
              value_type: BOOL
              {maybe_default_value}
              tags:
        """.format(maybe_default_value=maybe_default_value)),

        {'is_on': {
            'kind': 'Gauge',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 0.0}],
                'tags': [
                    {'key': 'discard', 'value': 'false'},
                ]
            }, {
                'values': [{'t': 1540224536922, 'v': 1.0}],
                'tags': [
                    {'key': 'discard', 'value': 'true'},
                ]
            }, {
                'values': [{'t': 1540224536923, 'v': 1.0}],
                'tags': [
                    {'key': 'discard', 'value': 'true'},
                ]
            },
                             ])},
        },

        {'is_on': {
            'kind': 'Gauge',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536923, 'v': expect}],
            },
                             ])}
        },
        options=options
    )

  def test_remove_tag_bool_value_no_transform(self):
    self._do_remove_tag_bool_value({}, 2.0)

  def test_remove_tag_bool_value_true(self):
    options = {'transform_values': True}
    self._do_remove_tag_bool_value(options, True)

  def test_remove_tag_bool_value_false(self):
    options = {'transform_values': True}
    self._do_remove_tag_bool_value(options, False)

  def test_discard_tag_values(self):
    self.do_test(
        textwrap.dedent("""\
            jvm.memory.used:
              tags:
                  - id
              change_tags:
                - from: memtype
                  to: heap
                  type: BOOL
                  compare_value: HEAP
              discard_tag_values:
                heap: "(?i)^false$"
        """),

        {'jvm.memory.used': {
            'kind': 'Gauge',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                'tags': [
                    {'key': 'id', 'value': 'PS Eden Space'},
                    {'key': 'memtype', 'value': 'HEAP'},
                ]
            }, {
                'values': [{'t': 1540224536923, 'v': 12345.0}],
                'tags': [
                    {'key': 'id', 'value': 'Code Cache'},
                    {'key': 'memtype', 'value': 'NON HEAP'},
                ]
            },
                             ])},
        },

        {'jvm.memory.used': {
            'kind': 'Gauge',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'id', 'value': 'PS Eden Space'},
                    # This test is not using tag types, so
                    # the BOOL value will be a string value.
                    {'key': 'heap', 'value': 'true'},
                ])
            },
                             ])}
        }
    )

  def test_per_application_removed(self):
    # Test is we transform into an application tag and have per_application
    # then the application tag will be removed (and values aggregated).
    self.do_test(
        textwrap.dedent("""\
            executions.started:
              kind: Counter
              per_application: true
              change_tags:
                 - from: source
                   to: application
                   type: STRING
              tags:
                - executionType
        """),

        {'executions.started': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536922, 'v': 12.0}],
                'tags': [
                    {'key': 'source', 'value': 'MyApplication'},
                    {'key': 'executionType', 'value': 'Pipeline'},
                ]
            }, {
                'values': [{'t': 1540224536923, 'v': 21.0}],
                'tags': [
                    {'key': 'source', 'value': 'YourApplication'},
                    {'key': 'executionType', 'value': 'Pipeline'},
                ]
            },
                             ])},
        },

        {'executions.started': {
            'kind': 'Counter',
            'values': sort_dictionaries([{
                'values': [{'t': 1540224536923, 'v': 33.0}],
                'tags': sort_tag_dictionaries([
                    {'key': 'executionType', 'value': 'Pipeline'},
                ]),
                '__per_tag_values': {
                    'application': sort_dictionaries([
                        {
                            'values': [{'t': 1540224536922, 'v': 12.0}],
                            'tags': sort_tag_dictionaries([
                                {'key': 'application',
                                 'value': 'MyApplication'},
                                {'key': 'executionType', 'value': 'Pipeline'}
                            ])
                        }, {
                            'values': [{'t': 1540224536923, 'v': 21.0}],
                            'tags': sort_tag_dictionaries([
                                {'key': 'application',
                                 'value': 'YourApplication'},
                                {'key': 'executionType', 'value': 'Pipeline'}
                            ])
                        }
                    ]),
                }}]),
            }
        }
    )

if __name__ == '__main__':
  unittest.main()
