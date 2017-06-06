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
from StringIO import StringIO

import datadog_service
from datadog_service import DatadogMetricsService
from ConfigParser import ConfigParser

class DatadogServiceTest(unittest.TestCase):
  @staticmethod
  def setUpClass():
    for key in ['DATADOG_APP_KEY', 'DATADOG_API_KEY']:
      if key in os.environ:
         del os.environ[key]

  @patch('datadog_service.datadog.initialize')
  def test_initialize_once(self, mock_initialize):
    service = DatadogMetricsService('testAPI', 'testAPP', host='testHOST')
    first = service.api
    second = service.api
    self.assertEquals(first, second)
    mock_initialize.assert_called_with(
          api_key='testAPI', app_key='testAPP', host_name='testHOST')
    self.assertEquals(1, mock_initialize.call_count)

  @patch('datadog_service.datadog.initialize')
  def test_initialize_from_dd_agent_config(self, mock_initialize):
    options = dict()
    data = ["[Main]", "#api_key: COMMENT", "api_key: FOUND_KEY", "hostname: FOUND_HOST"]
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data))
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
    options = dict()
    data = ["[Main]", "api_key: testApi", "hostname: testHost"]
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data))
      config.flush()
      options['dd_agent_config'] = config.name
      service = datadog_service.make_datadog_service(options)

    self.assertIsNotNone(service)
    self.assertIsNotNone(service.api)  # initialize on demand
    mock_initialize.assert_called_with(
          api_key='testApi', app_key=None, host_name='testHost')

  @patch('datadog_service.socket.getfqdn')
  @patch('datadog_service.datadog.initialize')
  def test_initialize_from_localhost_config(
          self, mock_initialize, mock_getfqdn):
    options = dict()
    data = ["[Main]", "api_key: FOUND_KEY"]
    mock_getfqdn.return_value = 'testFQDN'

    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data))
      config.flush()
      options['dd_agent_config'] = config.name
      options['datadog_host'] = "wrongHOST"
      service = datadog_service.make_datadog_service(options)

    mock_getfqdn.assert_called_with('wrongHOST')
    self.assertIsNotNone(service)
    self.assertIsNotNone(service.api)  # initialize on demand
    mock_initialize.assert_called_with(
          api_key='FOUND_KEY', app_key=None, host_name='testFQDN')

  @patch('datadog_service.spectator_client.foreach_metric_in_service_map')
  @patch('datadog_service.datadog.initialize')
  def test_publish_metrics(self, mock_initialize, mock_xform):
    data = ["[Main]", "api_key: FOUND_KEY"]
    options = dict()
    with tempfile.NamedTemporaryFile() as config:
      config.write('\n'.join(data))
      config.flush()
      options['dd_agent_config'] = config.name
      options['datadog_host'] = 'testHost'
      service = datadog_service.make_datadog_service(options)

    bogus_data = [i for i in range(0, service.MAX_BATCH * 2)]
    for test_case in [
            (service.MAX_BATCH - 1, [bogus_data[0:service.MAX_BATCH-1]]),
            (service.MAX_BATCH, [bogus_data[0:service.MAX_BATCH]]),
            (service.MAX_BATCH + 1,
               [bogus_data[0:service.MAX_BATCH],
                bogus_data[service.MAX_BATCH:service.MAX_BATCH + 1]])]:
      mock_xform.side_effect = (lambda ignore_metrics, ignore_fn, result:
                                  result.extend(bogus_data[0:test_case[0]]))
      with patch('datadog_service.datadog.api.Metric.send') as mock_send:
          self.assertEquals(
              test_case[0], service.publish_metrics(service_metrics={}))
      self.assertEquals(mock_send.call_args_list,
                        [mock.call(batch) for batch in test_case[1]])

if __name__ == '__main__':
  unittest.main()
