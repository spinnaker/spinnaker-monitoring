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
    return sorted(expect_tags)

  def test_timer(self):
    # This test is just showing nothing interesting happening
    # and we get out what we put in.
    builder = self._make_simple_rule_builder()
    for measurement in self._make_timer_measurements():
      builder.add(measurement['values'][0], measurement['tags'])
    self.assertEquals(
        sorted([
            {
                'values': [{'v': 123, 't': self.TIMESTAMP}],
                'tags': sorted([{'key': 'status', 'value': '2xx'},
                                {'key': 'statistic', 'value': 'count'}])
            },
            {
                'values': [{'v': 321, 't': self.TIMESTAMP}],
                'tags': sorted([{'key': 'status', 'value': '2xx'},
                                {'key': 'statistic', 'value': 'totalTime'}])
            }
        ]),
        sorted(builder.build()))


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
        values.sort()
    self.assertResponseEquals(expect_response, got_response)

  def assertResponseEquals(self, expect_response, got_response):
    if expect_response != got_response:
      print('Expected: %r\n'
            'Actual:   %r\n'
            % (expect_response, got_response))
    self.assertEquals(expect_response, got_response)

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

    do_name = lambda name, kind: transformer.normalize_meter_name(
        name, kind)
    self.assertEquals('timers', do_name('timers', 'Gauge'))
    self.assertEquals('timers', do_name('timers', 'Counter'))
    self.assertEquals('timer_latency', do_name('timer', 'Timer'))
    self.assertEquals('timer_latency', do_name('timers', 'Timer'))
    self.assertEquals('timer_latency', do_name('timer_latency', 'Timer'))
    self.assertEquals('timer_latency', do_name('timerLatency', 'Timer'))

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

  def test_change_meter_name_default(self):
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
    transformed_value['values'][0]['tags'] = sorted([
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

  def test_add_tags(self):
    transformed_value = copy.deepcopy(
        EXAMPLE_MEMORY_USED_RESPONSE['jvm.memory.used'])
    transformed_value['values'][0]['tags'] = sorted(
        transformed_value['values'][0]['tags']
        + [
            {'key': 'first', 'value': 'FIRST'},
            {'key': 'T', 'value': True},
            {'key': 'F', 'value': False},
            {'key': 'S', 'value': 'true'},
            {'key': 'numeric', 'value': 123},
        ])

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

        EXAMPLE_MEMORY_USED_RESPONSE,
        {'jvm.memory.used': transformed_value}
    )

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
                'tags': sorted([
                    {'key': 'objectType', 'value': 'PIPELINES'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'scheduled', 'value': False}
                ])
            }, {
                'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                'tags': sorted([
                    {'key': 'objectType', 'value': 'PIPELINES'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'scheduled', 'value': True}
                ])
            }
                      ]
        }},
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
            'values': sorted([
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
            'values': sorted([
                {'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                 'tags': sorted([
                     {'key': 'id', 'value': 'PS Eden Space'},
                     {'key': 'heap', 'value': True},
                 ])},
                {'values': [{'t': 1540224536923, 'v': 12345.0}],
                 'tags': sorted([
                     {'key': 'id', 'value': 'Code Cache'},
                     {'key': 'heap', 'value': False},
                 ])},
            ])}
        })

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
            'values': sorted([{
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
            'values': sorted([{
                'values': [{'t': 1540318956422, 'v': 23258.0}],
                'tags': sorted([
                    {'key': 'provider',
                     'value': 'com.netflix.spinnaker.clouddriver.google.provider.GoogleInfrastructureProvider'},
                    {'key': 'account', 'value': 'my-google-account'},
                    {'key': 'region', 'value': 'australia-southeast1'},
                    {'key': 'agent', 'value': 'GoogleSubnetCachingAgent'},
                    {'key': 'status', 'value': 'success'}
                ])
            }, {
                'values': [{'t': 1540318956422, 'v': 9.0}],
                'tags': sorted([
                    {'key': 'provider',
                     'value': 'com.netflix.spinnaker.clouddriver.appengine.provider.AppengineProvider'},
                    {'key': 'account', 'value': 'my-appengine-account'},
                    {'key': 'region', 'value': ''},
                    {'key': 'agent', 'value': 'AppenginePlatformApplicationCachingAgent'},
                    {'key': 'status', 'value': 'failure'},
                ])
            }
                             ])}
        })

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
            'values': sorted([{
                'values': [{'t': 12347, 'v': 5555.0}],
                'tags': sorted([
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'status', 'value': '4xx'},
                ])
            }, {
                'values': [{'t': 12346, 'v': 2222.0}],
                'tags': sorted([
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'totalTime'},
                    {'key': 'status', 'value': '2xx'},
                ])
            }, {
                'values': [{'t': 12348, 'v': 8888.0}],
                'tags': sorted([
                    {'key': 'controller', 'value': 'ClusterController'},
                    {'key': 'method', 'value': 'getServerGroup'},
                    {'key': 'statistic', 'value': 'count'},
                    {'key': 'status', 'value': '4xx'},
                ])
            },
                             ])},
        },
    )

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
            'values': sorted([{
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
            'values': sorted([{
                'values': [{'t': 1540224536922, 'v': 1489720024.0}],
                'tags': sorted([
                    {'key': 'id', 'value': 'PS Eden Space'},
                    {'key': 'heap', 'value': True},
                ])
            },
                             ])}
        })

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
            'values': sorted([{
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
            'values': sorted([{
                'values': [{'t': 1540224536923, 'v': 33.0}],
                'tags': sorted([
                    {'key': 'executionType', 'value': 'Pipeline'},
                ]),
                '__per_tag_values': {
                    'application': sorted([
                        {
                            'values': [{'t': 1540224536922, 'v': 12.0}],
                            'tags': [
                                {'key': 'application',
                                 'value': 'MyApplication'},
                                {'key': 'executionType', 'value': 'Pipeline'}
                            ]
                        }, {
                            'values': [{'t': 1540224536923, 'v': 21.0}],
                            'tags': [
                                {'key': 'application',
                                 'value': 'YourApplication'},
                                {'key': 'executionType', 'value': 'Pipeline'}
                            ]
                        }
                    ]),
                }}]),
            }
        }
    )

if __name__ == '__main__':
  unittest.main()
