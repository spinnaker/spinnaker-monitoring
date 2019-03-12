# Copyright 2017 Google Inc. All Rights Reserved.
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

import os

import mock
import unittest
import tempfile
from mock import patch

import datadog_service
from datadog_service import DatadogMetricsService, DatadogArgumentsGenerator


def service_generation_helper(config_data=[], datadog_options={},
                              spinnaker_monitoring_options={},
                              use_types=False):
    """
    This utility lets you build a DatadogMetricsService in a DRY fashion
    for all the tests below. You can inject additional parameters anywhere.

    It guarantees the base invariants - api_key present,
    'datadog' and 'dd_agent_config' keys exist in required arguments,
    and that 'dd_agent_config' is correctly parsed as a file. These are
    guarded against within the DatadogService.
    """

    data = ["[Main]", "api_key: FOUND_KEY"] + config_data
    options = {'datadog': datadog_options, 'dd_agent_config': ''}
    options.update(spinnaker_monitoring_options)
    if use_types:
      options['datadog'] = {'use_types': True}
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data).encode('utf-8'))
      config.flush()
      options['dd_agent_config'] = config.name
      service = datadog_service.make_datadog_service(options)

    return service

def arguments_generator_helper(config_data=[], options={}, set_dd_agent_conf=True):
    """
    This utility lets you build a DatadogArgumentsGenerator in a DRY fashion
    for all the tests below. You can inject additional parameters anywhere.
    """

    data = config_data
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data).encode('utf-8'))
      config.flush()
      if set_dd_agent_conf:
        options['dd_agent_config'] = config.name
      generator = DatadogArgumentsGenerator(options)

    return generator

class DatadogServiceTest(unittest.TestCase):
  @staticmethod
  def setUpClass():
    for key in ['DATADOG_APP_KEY', 'DATADOG_API_KEY']:
      if key in os.environ:
         del os.environ[key]

  @patch('datadog_service.datadog.initialize')
  def test_initialize_once(self, mock_initialize):
    spectator_helper = None #  dont care
    options = {}
    service = DatadogMetricsService(options, spectator_helper,
                                    api_key='testAPI', app_key='testAPP',
                                    host='testHOST', tags=[])
    first = service.api
    second = service.api
    self.assertEquals(first, second)
    mock_initialize.assert_called_with(
          api_key='testAPI', app_key='testAPP', host_name='testHOST')
    self.assertEquals(1, mock_initialize.call_count)

  @patch('datadog_service.datadog.initialize')
  def test_initialize_from_dd_agent_config(self, mock_initialize):
    options = {'datadog': {}, 'dd_agent_config': ''}
    data = ["[Main]", "#api_key: COMMENT", "api_key: FOUND_KEY",
            "hostname: FOUND_HOST"]
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data).encode('utf-8'))
      config.flush()
      options['dd_agent_config'] = config.name
      service = datadog_service.make_datadog_service(options)

    self.assertIsNotNone(service)
    self.assertIsNotNone(service.api)
    mock_initialize.assert_called_with(
            api_key='FOUND_KEY',
            app_key=None,
            host_name='FOUND_HOST')

  @patch('datadog_service.datadog.initialize')
  def test_initialize_from_options(self, mock_initialize):
    options = {'datadog': {}, 'dd_agent_config': ''}
    data = ["[Main]", "api_key: testApi", "app_key: testApi", "hostname: testHost"]
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data).encode('utf-8'))
      config.flush()
      options['dd_agent_config'] = config.name
      service = datadog_service.make_datadog_service(options)

    self.assertIsNotNone(service)
    self.assertIsNotNone(service.api)  # initialize on demand
    mock_initialize.assert_called_with(
          api_key='testApi', app_key='testApi', host_name='testHost')

  @patch('datadog_service.socket.getfqdn')
  @patch('datadog_service.datadog.initialize')
  def test_initialize_from_localhost_config(
          self, mock_initialize, mock_getfqdn):
    options = {'datadog': {}, 'dd_agent_config': ''}
    data = ["[Main]", "api_key: FOUND_KEY", "app_key: testApi"]
    mock_getfqdn.return_value = 'testFQDN'

    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data).encode('utf-8'))
      config.flush()
      options['dd_agent_config'] = config.name
      options['datadog_host'] = "wrongHOST"
      service = datadog_service.make_datadog_service(options)

    mock_getfqdn.assert_called_with('wrongHOST')
    self.assertIsNotNone(service)
    self.assertIsNotNone(service.api)  # initialize on demand
    mock_initialize.assert_called_with(
          api_key='FOUND_KEY', app_key='testApi', host_name='testFQDN')

  @patch('datadog_service.spectator_client.foreach_metric_in_service_map')
  @patch('datadog_service.datadog.initialize')
  def test_publish_metrics(self, mock_initialize, mock_xform):
    data = ["[Main]", "api_key: FOUND_KEY", "app_key: testApi"]
    options = {'datadog': {}, 'dd_agent_config': ''}
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data).encode('utf-8'))
      config.flush()
      options['dd_agent_config'] = config.name
      options['datadog_host'] = 'testHost'
      service = datadog_service.make_datadog_service(options)

    bogus_data = [i for i in range(0, service.MAX_BATCH * 2)]
    for test_case in [
            (service.MAX_BATCH - 1, [bogus_data[0:service.MAX_BATCH - 1]]),
            (service.MAX_BATCH, [bogus_data[0:service.MAX_BATCH]]),
            (service.MAX_BATCH + 1,
               [bogus_data[0:service.MAX_BATCH],
                bogus_data[service.MAX_BATCH:service.MAX_BATCH + 1]])]:
      mock_xform.side_effect = (lambda _, __, result:
                                result.extend(bogus_data[0:test_case[0]]))
      with patch('datadog_service.datadog.api.Metric.send') as mock_send:
          self.assertEquals(
              test_case[0], service.publish_metrics(service_metrics={}))
      self.assertEquals(mock_send.call_args_list,
                        [mock.call(batch) for batch in test_case[1]])


class DatadogServiceExternalTagsTest(unittest.TestCase):
  """
  A class that tests whether external tags are correctly passed to the underlying
  DatadogService object from the make_datadog_service wrapper. This ensures
  the end results of DataArgumentsGenerator is correct for one argument.

  The constraints tested here are based on order of precedence:

  1. Are tags from Datadog agent configuration passed to DatadogService _only if_
     not present in more preferred arguments?

  2. Are tags from environment variables preferred above all else?

  3. Are tags from spinnaker-monitoring.yml always preferred if environment variables
     are not present?

  4. Are tags from datadog options in spinnaker monitoring always preferred when
     spinnaker-monitoring.yml itself does not contain a key and
     when environment variable is not set?

  5. Does publish_metrics actually attach these tags?

  In oher words, in order for robust testing, sources of lower priority should be
  present in the test when testing if sources of higher priority are favoured in
  each test. This has been reflected in the tests below.

  Incidentally tested are whether a string 'tags' value is converted to a list of strings.
  This will be covered more robustly in the tests for DatadogArgumentsGenerator.
  """

  @patch.dict(os.environ, {'DATADOG_TAGS': 'foo:bar, ham:spam'})
  def test_passing_datadog_tags_from_environment(self):
    """
    Are tags from environment variables preferred above all else?
    """

    service = service_generation_helper(config_data=["tags: mytag, env:prod, role:database"],
                                        datadog_options={
                                          'tags': 'this:is, a, drill',
                                        },
                                        spinnaker_monitoring_options={
                                          'datadog_tags': 'kung:fu,star:wars'
                                        }
                                        )

    self.assertEqual(service._DatadogMetricsService__arguments['tags'],
                     ['foo:bar', 'ham:spam'])

  @patch.dict(os.environ, {})
  def test_passing_datadog_tags_from_options(self):
    """
    Are tags from spinnaker-monitoring.yml always preferred if environment variables
    are not present?
    """

    service = service_generation_helper(config_data=["tags: mytag, env:prod, role:database"],
                                        datadog_options={
                                          'tags': 'this:is, a, drill',
                                        },
                                        spinnaker_monitoring_options={
                                          'datadog_tags': 'kung:fu,star:wars'
                                        }
                                        )

    self.assertEqual(service._DatadogMetricsService__arguments['tags'],
                     ['kung:fu', 'star:wars'])

  @patch.dict(os.environ, {})
  def test_passing_datadog_tags_from_datadog_options(self):
    """
    Are tags from datadog options in spinnaker monitoring always preferred when
    spinnaker-monitoring.yml itself does not contain a key and
    when environment variable is not set?
    """

    service = service_generation_helper(config_data=["tags: mytag, env:prod, role:database"],
                                        datadog_options={
                                          'tags': 'this:is, a, drill',
                                        },
                                        )

    self.assertEqual(service._DatadogMetricsService__arguments['tags'],
                     ['this:is', 'a', 'drill'])

  @patch.dict(os.environ, {})
  def test_passing_datadog_tags_from_dd_agent_config(self):
    """
    Are tags from Datadog agent configuration passed to DatadogService _only if_
    not present in more preferred arguments?
    """

    service = service_generation_helper(config_data=["tags: mytag, env:prod, role:database"])

    self.assertEqual(service._DatadogMetricsService__arguments['tags'],
                     ['mytag', 'env:prod', 'role:database'])

  @patch('datadog_service.datadog.initialize')
  def test_publish_metrics_with_type(self, mock_initialize):
    tests = [('Gauge', 'gauge'),
             ('Timer', 'count'),
             ('Counter', 'count'),
             ('DistributionSummary', 'count')]

    service_with_types = service_generation_helper(use_types=True)
    service_without_types = service_generation_helper()

    with patch('datadog_service.datadog.api.Metric.send') as mock_send:
      service_metrics = {
        'clouddriver': [{
          '__host': 'localhost',
          'metrics': {
            'jvm.buffer.memoryUsed': {
              'values': [{
                  'tags': [],
                  'values': [{'t': 1471917869670, 'v': 0.0}]
               }, {
                  'tags': [],
                  'values': [{'t': 1471917869671, 'v': 81920.0}]
               }]
            },
          }
        }]
      }
      metric = service_metrics['clouddriver'][0]['metrics']['jvm.buffer.memoryUsed']
      for spectator_kind, datadog_type in tests:
        metric['kind'] = spectator_kind
        service_with_types.publish_metrics(service_metrics=service_metrics)
        self.assertEquals(mock_send.call_args[0][0][0]['type'], datadog_type)
        service_without_types.publish_metrics(service_metrics=service_metrics)
        self.assertEquals(mock_send.call_args[0][0][0]['type'], 'gauge')

  @patch('datadog_service.datadog.initialize')
  def test_publish_metrics_with_tags(self, mock_initialize):
    """ Does publish_metrics actually attach these tags? """

    service = service_generation_helper()

    # set these tags directly instead because it doesn't matter how they get written
    # in so long as they exist for this test.
    service._DatadogMetricsService__arguments['tags'] = ['foo', 'bar', 'ham', 'spam']

    with patch('datadog_service.datadog.api.Metric.send') as mock_send:

      # roughly stolen from spectator_client_test.py and reconstructed from code -
      # should be replaced with an actual real-life example
      service_metrics = {
        'clouddriver': [{
          '__host': 'localhost',
          'metrics': {
            'jvm.buffer.memoryUsed': {
              'values': [{
                  'tags': [],
                  'values': [{'t': 1471917869670, 'v': 0.0}]
               }, {
                  'tags': [],
                  'values': [{'t': 1471917869671, 'v': 81920.0}]
               }]
            },
          }
        }]
      }

      service.publish_metrics(service_metrics=service_metrics)

      self.assertEqual(mock_send.call_args[0][0][0]['tags'],
                       ['foo', 'bar', 'ham', 'spam'])

      self.assertEqual(mock_send.call_args[0][0][1]['tags'],
                       ['foo', 'bar', 'ham', 'spam'])

      # Now add tags into metrics
      for entry in (service_metrics['clouddriver'][0]['metrics']
                                   ['jvm.buffer.memoryUsed']['values']):
          entry['tags'] = [{'key': 'id', 'value': 'direct'}]
      service.publish_metrics(service_metrics=service_metrics)

      self.assertEqual(sorted(mock_send.call_args[0][0][0]['tags']),
                       sorted(['foo', 'bar', 'ham', 'spam', 'id:direct']))


class DatadogArgumentsGeneratorTest(unittest.TestCase):

  def raise_error_if_api_key_not_present(self):

    with self.assertRaises(AssertionError):
      # the helper method by default contains no API key
      arguments_generator_helper()

  def raise_error_if_datadog_option_is_not_present(self):

    with self.assertRaises(AssertionError):
      arguments_generator_helper(config_data=["[Main]", "api_key: FOUND_KEY"],
                                 options={})

  def raise_error_if_datadog_configuration_option_is_not_present(self):

    with self.assertRaises(AssertionError):
      arguments_generator_helper(config_data=["[Main]", "api_key: FOUND_KEY"],
                                 options={'datadog': {}}, set_dd_agent_conf=False)

  def test_no_error_is_raised_if_all_asserts_pass(self):
      arguments_generator_helper(config_data=["[Main]", "api_key: FOUND_KEY"],
                                 options={'datadog': {}}, set_dd_agent_conf=True)

if __name__ == '__main__':
  unittest.main()
