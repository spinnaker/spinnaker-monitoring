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

import argparse
import base64
import copy
import json
import os
import sys
import yaml
import unittest
from StringIO import StringIO
import mock

from mock import patch
from urllib2 import Request
from tempfile import NamedTemporaryFile

import spectator_client

# pylint: disable=missing-docstring
# pylint: disable=invalid-name


def args_to_options(args):
  parser = argparse.ArgumentParser()
  spectator_client.SpectatorClient.add_standard_parser_arguments(parser)
  old_argv = sys.argv
  try:
    sys.argv = ['foo']
    sys.argv.extend(args)
    options = vars(parser.parse_args())
  finally:
    sys.argv = old_argv
  return options


TEST_HOST = 'test_hostname'


CLOUDDRIVER_RESPONSE_OBJ = {
  'applicationName': 'clouddriver',
  'metrics' : {
    'jvm.buffer.memoryUsed' : {
      'kind': 'AggrMeter',
      'values': [{
          'tags': [{'key': 'id', 'value': 'mapped'}],
          'values': [{'t': 1471917869670, 'v': 0.0}]
       }, {
          'tags': [{'key': 'id', 'value': 'direct'}],
          'values': [{'t': 1471917869671, 'v': 81920.0}]
       }]
    },
    'jvm.gc.maxDataSize' : {
      'kind': 'AggrMeter',
      'values': [{
        'tags': [],
        'values': [{'t': 1471917869672, 'v': 12345.0}]
      }]
    },
    'tasks': {
      'kind': 'Counter',
      'values': [{
        'tags': [{'key': 'success', 'value': 'true'}],
        'values': [{'t': 1471917869673, 'v': 24.0}]
      }]
    }
  }
}


CLOUDDRIVER_RESPONSE_TEXT = json.JSONEncoder(encoding='utf-8').encode(
    CLOUDDRIVER_RESPONSE_OBJ)


GATE_RESPONSE_OBJ = {
  'applicationName': 'gate',
  'metrics' : {
    'jvm.buffer.memoryUsed' : {
      'kind': 'AggrMeter',
      'values': [{
          'tags': [{'key': 'id', 'value': 'mapped'}],
          'values': [{'t': 1471917869677, 'v': 2.0}]
        }, {
          'tags': [{'key': 'id', 'value': 'direct'}],
          'values': [{'t': 1471917869678, 'v': 22222.0}]
        }]
    },
    'jvm.gc.maxDataSize': {
      'kind': 'AggrMeter',
      'values': [{
        'tags': [],
        'values': [{'t' : 1471917869679, 'v' : 54321.0}]
      }]
    },
    'controller.invocations': {
      'kind': 'Timer',
      'values': [{
        'tags': [{'key': 'controller', 'value': 'PipelineController'},
                 {'key': 'method', 'value': 'savePipeline'}],
        'values': [{'t' : 1471917869679, 'v' : 1.0}]
      }]
    }
  }
}

GATE_RESPONSE_TEXT = json.JSONEncoder(encoding='utf-8').encode(
    GATE_RESPONSE_OBJ)


class TestableSpectatorClient(spectator_client.SpectatorClient):
  def __init__(self, options):
    self.requests = []
    super(TestableSpectatorClient, self).__init__(options)

  def create_request(self, url, authorization):
    self.requests.append((url, authorization))
    return super(TestableSpectatorClient, self).create_request(url, authorization)


class SpectatorClientTest(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
      spectator_client.DEFAULT_REGISTRY_DIR = os.path.abspath(
          os.path.join(os.path.dirname(__file__), '..', 'registry.dev'))

  def setUp(self):
    options = {'prototype_path': None,
               'host': TEST_HOST,
               'metric_filter_path': None}
    self.spectator = TestableSpectatorClient(options)
    self.default_query_params = '?tagNameRegex=.%2A'  # tagNameRegex=.*


  @patch('glob.glob')
  @patch('os.path.getmtime')
  def test_get_source_catalog(self, mock_getmtime, mock_glob):
    mock_getmtime.return_value = 1234
    mock_glob.return_value = ['one.yml', 'two.yml']
    mo = mock.mock_open(read_data='metrics_url: http://testhost:1122')
    mo.side_effect = (
        mo.return_value,
        mock.mock_open(
            read_data='metrics_url: http://testhost:3344').return_value)
    options = {'registry_dir': '/my/registry/path'}
    with patch('spectator_client.open', mo, create=True):
      catalog = spectator_client.get_source_catalog(options)
    self.assertEqual({'one': {'metrics_url': ['http://testhost:1122']},
                      'two': {'metrics_url': ['http://testhost:3344']}},
                     catalog)
    mock_getmtime.assert_called_with('/my/registry/path')
    mock_glob.assert_called_with('/my/registry/path/*.yml')
    self.assertEquals(1, mock_getmtime.call_count)

    # Verify that we dont rescan content if timestamp hasnt changed.
    again = spectator_client.get_source_catalog(options)
    self.assertEquals(catalog, again)
    self.assertEquals(2, mock_getmtime.call_count)
    self.assertEquals(1, mock_glob.call_count)

    # Verify that we query again if timestamp changes
    mock_getmtime.return_value = 1235
    mock_glob.return_value = ['three.yml']
    mo = mock.mock_open(read_data='metrics_url: http://testhost:3333')
    with patch('spectator_client.open', mo, create=True):
      retry = spectator_client.get_source_catalog(options)
    self.assertEqual({'three': {'metrics_url': ['http://testhost:3333']}},
                     retry)

  def test_default_dev_endpoints(self):
    got_urls = {name: config['metrics_url']
                for name, config
                in spectator_client.get_source_catalog({}).items()}

    def localhost_urls(port):
      return ['http://localhost:{port}/spectator/metrics'.format(port=port)]
    self.assertEquals({'clouddriver': localhost_urls(7002),
                       'echo': localhost_urls(8089),
                       'fiat': localhost_urls(7003),
                       'front50': localhost_urls(8080),
                       'gate': localhost_urls(8084),
                       'igor': localhost_urls(8088),
                       'kayenta': localhost_urls(8090),
                       'orca': localhost_urls(8083),
                       'rosco': localhost_urls(8087)},
                      got_urls)

  @patch('spectator_client.time.time')
  @patch('spectator_client.urllib2.urlopen')
  def test_collect_metrics_no_params(self, mock_urlopen, mock_time):
    now_time = 1.234
    port = 80
    url = 'http://{0}/spectator-metrics'.format(TEST_HOST)
    metrics_response = CLOUDDRIVER_RESPONSE_OBJ
    expect = copy.deepcopy(metrics_response)
    expect['__host'] = TEST_HOST
    expect['__port'] = port
    expect['metrics']['spectator.datapoints'] = {
      'kind': 'Gauge',
      'values': [{'values': [{'t': int(now_time * 1000), 'v': 4}],
                  'tags': [{'key': 'success', 'value': 'true'}]}]
    }

    text = json.JSONEncoder(encoding='utf-8').encode(metrics_response)
    mock_http_response = StringIO(text)
    mock_urlopen.return_value = mock_http_response
    mock_time.return_value = now_time

    response = self.spectator.collect_metrics('testService', url)
    self.assertEquals([(url + self.default_query_params, None)],
                      self.spectator.requests)
    self.assertEqual(expect, response)

  @patch('spectator_client.time.time')
  @patch('spectator_client.urllib2.urlopen')
  def test_collect_metrics_filter_no_jvm(self, mock_urlopen, mock_time):
    spec = {'services': {
              'filterTest': {
                'meters': {
                  'excludeNameRegex': 'jvm.*'
                }
              }
            }}

    with NamedTemporaryFile(delete=False) as fd:
      fd.write(yaml.dump(spec))
      metric_path = fd.name

    options = {'prototype_path': None,
               'host': TEST_HOST,
               'metric_filter_path': metric_path}
    test_spectator = TestableSpectatorClient(options)
    os.remove(metric_path)

    now_time = 1.234
    port = 80
    url = 'http://{0}/spectator-metrics'.format(TEST_HOST)
    metrics_response = CLOUDDRIVER_RESPONSE_OBJ
    expect = copy.deepcopy(metrics_response)
    expect['__host'] = TEST_HOST
    expect['__port'] = port
    expect['metrics']['spectator.datapoints'] = {
      'kind': 'Gauge',
      'values': [{'values': [{'t': int(now_time * 1000), 'v': 1}],
                  'tags': [{'key': 'success', 'value': 'true'}]}]
    }
    del expect['metrics']['jvm.buffer.memoryUsed']
    del expect['metrics']['jvm.gc.maxDataSize']

    text = json.JSONEncoder(encoding='utf-8').encode(metrics_response)
    mock_http_response = StringIO(text)
    mock_urlopen.return_value = mock_http_response
    mock_time.return_value = now_time

    response = test_spectator.collect_metrics('filterTest', url)
    self.assertEquals([(url + self.default_query_params, None)],
                      test_spectator.requests)
    self.assertEqual(expect, response)

  @patch('spectator_client.urllib2.urlopen')
  def test_collect_metrics_with_params(self, mock_urlopen):
    port = 13246
    url = 'http://{0}:{1}/spectator-metrics'.format(TEST_HOST, port)

    params = {'tagNameRegex': 'someName', 'tagValueRegex': 'Second+Part&Third'}
    encoded_params = {'tagNameRegex': 'someName',
                      'tagValueRegex': 'Second%2BPart%26Third'}
    expected_query = ''
    for key in params.keys():
      expected_query += '{sep}{key}={value}'.format(
          sep='&' if expected_query else '?',
          key=key,
          value=encoded_params[key])

    text = json.JSONEncoder(encoding='utf-8').encode(CLOUDDRIVER_RESPONSE_OBJ)
    mock_http_response = StringIO(text)
    mock_urlopen.return_value = mock_http_response

    self.spectator.collect_metrics('testService', url, params)
    self.assertEquals([(url + expected_query, None)],
                      self.spectator.requests)

  @patch('spectator_client.time.time')
  @patch('spectator_client.urllib2.urlopen')
  def test_collect_metrics_with_password(self, mock_urlopen, mock_time):
    now_time = 1.234
    port = 80
    url = 'https://TESTUSER:TESTPASSWORD@{0}/spectator-metrics'.format(TEST_HOST)
    metrics_response = CLOUDDRIVER_RESPONSE_OBJ
    expect = copy.deepcopy(metrics_response)
    expect['__host'] = TEST_HOST
    expect['__port'] = port
    expect['metrics']['spectator.datapoints'] = {
      'kind': 'Gauge',
      'values': [{'values': [{'t': int(now_time * 1000), 'v': 4}],
                  'tags': [{'key': 'success', 'value': 'true'}]}]
    }

    text = json.JSONEncoder(encoding='utf-8').encode(metrics_response)
    mock_http_response = StringIO(text)
    mock_urlopen.return_value = mock_http_response
    mock_time.return_value = now_time

    response = self.spectator.collect_metrics('testService', url)
    self.assertEquals([
      ('https://{0}/spectator-metrics{1}'.format(TEST_HOST,
                                                 self.default_query_params),
           base64.encodestring('TESTUSER:TESTPASSWORD').replace('\n', ''))],
       self.spectator.requests)
    self.assertEqual(expect, response)

  @patch('spectator_client.time.time')
  @patch('spectator_client.urllib2.urlopen')
  def test_scan_by_service_one(self, mock_urlopen, mock_time):
    now_time = 1.234
    url = 'http://{0}:7002/spectator-metrics'.format(TEST_HOST)
    metrics_response = CLOUDDRIVER_RESPONSE_OBJ
    expect = copy.deepcopy(metrics_response)
    expect['__host'] = TEST_HOST
    expect['__port'] = 7002
    expect['metrics']['spectator.datapoints'] = {
      'kind': 'Gauge',
      'values': [{'values': [{'t': int(now_time * 1000), 'v': 4}],
                  'tags': [{'key': 'success', 'value': 'true'}]}]
    }

    text = json.JSONEncoder(encoding='utf-8').encode(metrics_response)
    mock_http_response = StringIO(text)
    mock_urlopen.return_value = mock_http_response
    mock_time.return_value = now_time

    response = self.spectator.scan_by_service(
        {'clouddriver': {'metrics_url': [url]}})
    self.assertEquals([(url + self.default_query_params, None)],
                      self.spectator.requests)
    self.assertEqual({'clouddriver': [expect]}, response)

  @patch('spectator_client.time.time')
  @patch('spectator_client.urllib2.urlopen')
  def test_scan_by_service_two(self, mock_urlopen, mock_time):
    now_time = 1.234
    url_one = 'http://FirstHost:7002/spectator/metrics'
    one_response = CLOUDDRIVER_RESPONSE_OBJ
    expect_one = copy.deepcopy(one_response)
    expect_one['__host'] = 'firsthost'
    expect_one['__port'] = 7002
    expect_one['metrics']['spectator.datapoints'] = {
      'kind': 'Gauge',
      'values': [{'values': [{'t': int(now_time * 1000), 'v': 4}],
                  'tags': [{'key': 'success', 'value': 'true'}]}]
    }

    url_two = 'http://SecondHost:7002/spectator/metrics'
    two_response = dict(one_response)
    two_response['random'] = 'A distinguishing value'
    expect_two = dict(expect_one)
    expect_two['__host'] = 'secondhost'
    expect_two['random'] = two_response['random']

    text_one = json.JSONEncoder(encoding='utf-8').encode(one_response)
    text_two = json.JSONEncoder(encoding='utf-8').encode(two_response)

    expect = [expect_one, expect_two]
    mock_urlopen.side_effect = [StringIO(text_one), StringIO(text_two)]
    mock_time.return_value = now_time

    response = self.spectator.scan_by_service(
        {'clouddriver': {'metrics_url': [url_one, url_two]}})
    self.assertEquals(
      [
          ('http://firsthost:7002/spectator/metrics{0}'
             .format(self.default_query_params), None),
          ('http://secondhost:7002/spectator/metrics{0}'
             .format(self.default_query_params), None)
      ],
      self.spectator.requests)

    self.assertEqual({'clouddriver': expect}, response)

  @patch('spectator_client.time.time')
  @patch('spectator_client.urllib2.urlopen')
  def test_scan_by_service_list(self, mock_urlopen, mock_time):
    now_time = 1.234
    clouddriver_url = 'http://{0}:7002/spectator/metrics'.format(TEST_HOST)
    clouddriver_response = CLOUDDRIVER_RESPONSE_OBJ
    expect_clouddriver = copy.deepcopy(clouddriver_response)
    expect_clouddriver['__host'] = TEST_HOST
    expect_clouddriver['__port'] = 7002
    expect_clouddriver['metrics']['spectator.datapoints'] = {
      'kind': 'Gauge',
      'values': [{'values': [{'t': int(now_time * 1000), 'v': 4}],
                  'tags': [{'key': 'success', 'value': 'true'}]}]
    }

    gate_url = 'http://{0}:8084/spectator/metrics'.format(TEST_HOST)
    gate_response = GATE_RESPONSE_OBJ
    expect_gate = copy.deepcopy(gate_response)
    expect_gate['__host'] = TEST_HOST
    expect_gate['__port'] = 8084
    expect_gate['metrics']['spectator.datapoints'] = {
      'kind': 'Gauge',
      'values': [{'values': [{'t': int(now_time * 1000), 'v': 4}],
                  'tags': [{'key': 'success', 'value': 'true'}]}]}

    clouddriver_text = json.JSONEncoder(encoding='utf-8').encode(
        clouddriver_response)
    gate_text = json.JSONEncoder(encoding='utf-8').encode(gate_response)

    mock_time.return_value = now_time
    # The order is sensitive to the order we'll call in.
    # To get the call order, we'll let the dict tell us,
    # since that is the order we'll be calling internally.
    # Ideally this can be specified a different way, but I cant find how.
    mock_urlopen.side_effect = {'clouddriver': StringIO(clouddriver_text),
                                'gate': StringIO(gate_text)}.values()

    response = self.spectator.scan_by_service(
        {'clouddriver': {'metrics_url': [clouddriver_url]},
         'gate': {'metrics_url': [gate_url]}})

    # Order does not matter.
    self.assertEquals(
        sorted([(clouddriver_url + self.default_query_params, None),
                (gate_url + self.default_query_params, None)]),
        sorted(self.spectator.requests))

    self.assertEqual({'clouddriver': [expect_clouddriver],
                      'gate': [expect_gate]},
                     response)

  def test_service_map_to_type_map_one(self):
    got = spectator_client.SpectatorClient.service_map_to_type_map(
      {'clouddriver': [CLOUDDRIVER_RESPONSE_OBJ]})
    expect = {}
    self.spectator.ingest_metrics(
        'clouddriver', CLOUDDRIVER_RESPONSE_OBJ, expect)
    self.assertEquals(expect, got)

  def test_service_map_to_type_map_two_different(self):
    got = spectator_client.SpectatorClient.service_map_to_type_map(
      {'clouddriver': [CLOUDDRIVER_RESPONSE_OBJ],
       'gate': [GATE_RESPONSE_OBJ]})
    expect = {}
    self.spectator.ingest_metrics(
        'clouddriver', CLOUDDRIVER_RESPONSE_OBJ, expect)
    self.spectator.ingest_metrics(
        'gate', GATE_RESPONSE_OBJ, expect)
    self.assertEquals(expect, got)

  def test_service_map_to_type_map_two_same(self):
    another = dict(CLOUDDRIVER_RESPONSE_OBJ)
    metric = another['metrics']['jvm.buffer.memoryUsed']['values'][0]
    metric['values'][0]['t'] = 12345
    got = spectator_client.SpectatorClient.service_map_to_type_map(
      {'clouddriver': [CLOUDDRIVER_RESPONSE_OBJ, another]})

    expect = {}
    self.spectator.ingest_metrics(
        'clouddriver', CLOUDDRIVER_RESPONSE_OBJ, expect)
    self.spectator.ingest_metrics(
        'clouddriver', another, expect)
    self.assertEquals(expect, got)

  @patch('spectator_client.urllib2.urlopen')
  def test_scan_by_type_base_case(self, mock_urlopen):
    expect = {}
    self.spectator.ingest_metrics(
        'clouddriver', CLOUDDRIVER_RESPONSE_OBJ, expect)

    mock_http_response = StringIO(CLOUDDRIVER_RESPONSE_TEXT)
    mock_urlopen.return_value = mock_http_response

    url = 'http://{0}:7002/spectator/metrics'.format(TEST_HOST)
    response = self.spectator.scan_by_type(
        {'clouddriver': {'metrics_url': [url]}})
    self.assertEquals([(url + self.default_query_params, None)],
                      self.spectator.requests)
    del response['spectator.datapoints']
    self.assertEqual(expect, response)

  @patch('spectator_client.urllib2.urlopen')
  def test_scan_by_type_incremental_case(self, mock_urlopen):
    expect = {}
    self.spectator.ingest_metrics(
        'clouddriver', CLOUDDRIVER_RESPONSE_OBJ, expect)
    self.spectator.ingest_metrics(
        'gate', GATE_RESPONSE_OBJ, expect)

    mock_clouddriver_response = StringIO(CLOUDDRIVER_RESPONSE_TEXT)
    mock_gate_response = StringIO(GATE_RESPONSE_TEXT)

    # The order is sensitive to the order we'll call in.
    # To get the call order, we'll let the dict tell us,
    # since that is the order we'll be calling internally.
    # Ideally this can be specified a different way, but I cant find how.
    mock_urlopen.side_effect = {'clouddriver': mock_clouddriver_response,
                                'gate': mock_gate_response}.values()

    clouddriver_url = 'http://{0}:7002/spectator/metrics?a=C'.format(
        TEST_HOST)
    gate_url = 'http://{0}:8084/spectator/metrics?gate=YES'.format(
        TEST_HOST)
    response = self.spectator.scan_by_type(
        {'clouddriver': {'metrics_url': [clouddriver_url]},
         'gate': {'metrics_url': [gate_url]}})
      
    self.assertEquals(
        sorted([(clouddriver_url + '&tagNameRegex=.%2A', None),
                (gate_url + '&tagNameRegex=.%2A', None)]),
        sorted(self.spectator.requests))

    del response['spectator.datapoints']
    self.assertEqual(expect, response)

  def test_ingest_metrics_base_case(self):
    result = {}
    self.spectator.ingest_metrics(
        'clouddriver', CLOUDDRIVER_RESPONSE_OBJ, result)

    expect = {
        key: {'clouddriver': [value]}
        for key, value in CLOUDDRIVER_RESPONSE_OBJ['metrics'].items()
        }

    self.assertEqual(expect, result)

  def test_ingest_metrics_incremental_case(self):
    result = {}
    self.spectator.ingest_metrics(
        'clouddriver', CLOUDDRIVER_RESPONSE_OBJ, result)
    self.spectator.ingest_metrics(
      'gate', GATE_RESPONSE_OBJ, result)

    expect = {key: {'clouddriver': [value]}
              for key, value
              in CLOUDDRIVER_RESPONSE_OBJ['metrics'].items()}
    for key, value in GATE_RESPONSE_OBJ['metrics'].items():
      if key in expect:
        expect[key]['gate'] = [value]
      else:
        expect[key] = {'gate': [value]}

    self.assertEqual(expect, result)

  def test_filter_name(self):
    prototype = {'metrics': {'tasks': {}}}
    expect = {'applicationName': 'clouddriver',
              'metrics': {
                  'tasks': CLOUDDRIVER_RESPONSE_OBJ['metrics']['tasks']}}
    got = self.spectator.filter_metrics(CLOUDDRIVER_RESPONSE_OBJ, prototype)
    self.assertEqual(expect, got)

  def test_filter_tag(self):
    prototype = {
      'metrics': {
        'jvm.buffer.memoryUsed': {
          'values': [{
            'tags': [{'key': 'id', 'value': 'direct'}]
            }]
          }
        }
      }

    metric = dict(CLOUDDRIVER_RESPONSE_OBJ['metrics']['jvm.buffer.memoryUsed'])
    metric['values'] = [metric['values'][1]]  # Keep just the one tag set value.
    expect = {'applicationName': 'clouddriver',
              'metrics': {'jvm.buffer.memoryUsed': metric}
             }
    got = self.spectator.filter_metrics(CLOUDDRIVER_RESPONSE_OBJ, prototype)
    self.assertEqual(expect, got)


if __name__ == '__main__':
  unittest.main()
