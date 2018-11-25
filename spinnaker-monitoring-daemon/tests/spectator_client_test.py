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
import shutil
import unittest
from StringIO import StringIO
import mock

from mock import patch
from urllib2 import Request
from tempfile import mkdtemp

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
  },
  'startTime': 12345678
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
  },
  'startTime': 87654321
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


class SpectatorClientHelperTest(unittest.TestCase):
  METRIC_METADATA = {}  # Not yet used
  SIMPLE_VALUE_DATA = {
    'tags': [{'key': 'myTag', 'value': 'myTagValue'}],
    'values': [{'t': 1471917869670, 'v': 123.0}]
  }

  TIMER_TIME_VALUE_DATA = {
    'tags': [{'key': 'myTag', 'value': 'myTagValue'},
             {'key': 'statistic', 'value': 'totalTime'}],
    'values': [{'t': 1471917869670, 'v': 123.0}]
  }
  TAGLESS_VALUE_DATA = {
    'values': [{'t': 1471917869670, 'v': 123.0}]
  }

  def test_normalize_name_and_tags_simple_default(self):
    options = {}
    helper = spectator_client.SpectatorClientHelper(options)
    name, tags = helper.normalize_name_and_tags(
        'myService', 'myMetric', self.SIMPLE_VALUE_DATA, self.METRIC_METADATA)
    self.assertEquals('myService/myMetric', name)
    self.assertEquals([{'key': 'myTag', 'value': 'myTagValue'}], tags)

  def test_normalize_name_and_tags_statistic_default(self):
    options = {}
    helper = spectator_client.SpectatorClientHelper(options)
    name, tags = helper.normalize_name_and_tags(
        'myService', 'myMetric', self.TIMER_TIME_VALUE_DATA, self.METRIC_METADATA)
    self.assertEquals('myService/myMetric__totalTime', name)
    self.assertEquals([{'key': 'myTag', 'value': 'myTagValue'}], tags)

  def test_normalize_name_and_tags_tagless_default(self):
    options = {}
    helper = spectator_client.SpectatorClientHelper(options)
    name, tags = helper.normalize_name_and_tags(
        'myService', 'myMetric', self.TAGLESS_VALUE_DATA, self.METRIC_METADATA)
    self.assertEquals('myService/myMetric', name)
    self.assertEquals([], tags)

  def test_normalize_name_and_tags_simple_with_service_tag(self):
    options = {'spectator': {'inject_service_tag': True}}
    helper = spectator_client.SpectatorClientHelper(options)
    name, tags = helper.normalize_name_and_tags(
        'myService-ro', 'myMetric', self.SIMPLE_VALUE_DATA, self.METRIC_METADATA)
    self.assertEquals('myMetric', name)
    self.assertEquals(sorted([{'key': 'myTag', 'value': 'myTagValue'},
                              {'key': 'spin_service', 'value': 'myService'},
                              {'key': 'spin_variant', 'value': 'ro'}]),
                      sorted(tags))

  def test_normalize_name_and_tags_simple_with_service_tag_and_decoration(self):
    options = {'spectator': {'inject_service_tag': True,
                             'decorate_metric_name': True}}
    helper = spectator_client.SpectatorClientHelper(options)
    name, tags = helper.normalize_name_and_tags(
        'myService-ro', 'myMetric', self.SIMPLE_VALUE_DATA, self.METRIC_METADATA)
    self.assertEquals('myService-ro/myMetric', name)
    self.assertEquals(sorted([{'key': 'myTag', 'value': 'myTagValue'},
                              {'key': 'spin_service', 'value': 'myService'},
                              {'key': 'spin_variant', 'value': 'ro'}]),
                      sorted(tags))


class SpectatorClientTest(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
      spectator_client.DEFAULT_REGISTRY_DIR = os.path.abspath(
          os.path.join(os.path.dirname(__file__), '..', 'registry.dev'))

  def setUp(self):
    options = {'prototype_path': None,
               'host': TEST_HOST,
               'metric_filter_dir': '/none'}
    self.spectator = TestableSpectatorClient(options)
    self.default_query_params = '?tagNameRegex=.%2A'  # tagNameRegex=.*


  @patch('glob.glob')
  @patch('os.path.getmtime')
  def do_test_get_source_catalog(self, options, mock_getmtime, mock_glob):
    mock_getmtime.return_value = 1234
    mock_glob.return_value = ['one.yml', 'two.yml',
                              'multi-ro.yml', 'multi-rw.yml']
    mo = mock.mock_open(read_data='metrics_url: http://testhost:1122')
    mo.side_effect = (
        mo.return_value,
        mock.mock_open(
            read_data='metrics_url: http://testhost:3344').return_value,
        mock.mock_open(
            read_data='metrics_url: http://testhost:5555').return_value,
        mock.mock_open(
            read_data='metrics_url: http://testhost:6666').return_value,
    )
    options.update({'registry_dir': '/my/registry/path'})
    with patch('spectator_client.open', mo, create=True):
      catalog = spectator_client.get_source_catalog(options)
    expect = {'one': {'metrics_url': ['http://testhost:1122']},
              'two': {'metrics_url': ['http://testhost:3344']}}
    if options.get('spectator', {}).get('use_base_service_name_only'):
      expect['multi'] = {'metrics_url': ['http://testhost:5555',
                                         'http://testhost:6666']}
    else:
      expect['multi-ro'] = {'metrics_url': ['http://testhost:5555']}
      expect['multi-rw'] = {'metrics_url': ['http://testhost:6666']}

    self.assertEqual(expect, catalog)
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

  def test_get_source_catalog_default(self):
    self.do_test_get_source_catalog({})

  def test_get_source_catalog_normalized(self):
    options = {'spectator': {'use_base_service_name_only': True}}
    self.do_test_get_source_catalog(options)

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
    spec = {'monitoring': {
              'filters': {
                'meters': {
                  'excludeNameRegex': 'jvm.*'
                }
              }
            }}

    temp_dir = mkdtemp()
    metric_path = os.path.join(temp_dir, 'filterTestService.yml')
    with open(metric_path, 'w') as fd:
      fd.write(yaml.safe_dump(spec))

    options = {'host': TEST_HOST,
               'metric_filter_dir': temp_dir}
    test_spectator = TestableSpectatorClient(options)

    now_time = 1.234
    port = 80
    url = 'http://{0}/spectator-metrics'.format(TEST_HOST)
    metrics_response = CLOUDDRIVER_RESPONSE_OBJ
    expect = copy.deepcopy(metrics_response)
    expect['__host'] = TEST_HOST
    expect['__port'] = port
    del expect['metrics']['jvm.buffer.memoryUsed']
    del expect['metrics']['jvm.gc.maxDataSize']

    text = json.JSONEncoder(encoding='utf-8').encode(metrics_response)
    mock_http_response = StringIO(text)
    mock_urlopen.return_value = mock_http_response
    mock_time.return_value = now_time

    response = test_spectator.collect_metrics('filterTestService', url)
    shutil.rmtree(temp_dir)

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

    gate_url = 'http://{0}:8084/spectator/metrics'.format(TEST_HOST)
    gate_response = GATE_RESPONSE_OBJ
    expect_gate = copy.deepcopy(gate_response)
    expect_gate['__host'] = TEST_HOST
    expect_gate['__port'] = 8084

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


if __name__ == '__main__':
  unittest.main()
