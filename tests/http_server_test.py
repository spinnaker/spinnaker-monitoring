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

import socket
import threading
import time
import urllib2

import mock
import unittest
from mock import patch

import http_server


class HttpServerTest(unittest.TestCase):
  @patch('http_server.BaseHTTPServer.HTTPServer.__init__')
  def test_init_from_options(self, mock_http):
    """Verify we pick up commandline args, and empty host is passed through."""
    options = {'port': 1234, 'host': '',
               'server': {'port': 666, 'host': 'wrong'}}
    server = http_server.HttpServer(options)
    mock_http.assert_called_with(server, ('', 1234), mock.ANY)

  @patch('http_server.BaseHTTPServer.HTTPServer.__init__')
  def test_init_from_hardcoded_defaults(self, mock_http):
    """Verify if options arent overriden that we get the builtin defaults."""
    options = {'port': None, 'host': None}
    server = http_server.HttpServer(options)
    mock_http.assert_called_with(server, ('localhost', 8008), mock.ANY)

  @patch('http_server.BaseHTTPServer.HTTPServer.__init__')
  def test_init_from_server_options(self, mock_http):
    """Verify that if options arent overriden we get server config."""
    options = {'port': None, 'host': None,
               'server': {'port': 1234, 'host': 'testHost'}}
    server = http_server.HttpServer(options)
    mock_http.assert_called_with(server, ('testHost', 1234), mock.ANY)


class HttpServerUrlTest(unittest.TestCase):
  def setUp(self):
    self.handler_a = mock.Mock()
    self.handler_b = mock.Mock()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0))
    self.port = sock.getsockname()[1]
    sock.close()
     
    server = http_server.HttpServer(
        {'port': self.port},
        handlers={'/path/a': self.handler_a, '/path/b': self.handler_b})
    self.thread = threading.Thread(target=server.handle_request)
    self.thread.daemon = True
    self.thread.start()

  def tearDown(self):
    self.thread.join()

  def test_not_found(self):
    """Verify that our server delegates to commands."""
    with self.assertRaises(urllib2.HTTPError) as context:
        urllib2.urlopen('http://localhost:{0}/unknown_path'.format(self.port))
    self.assertEqual(404, context.exception.code)

  def test_delegation(self):
    """Verify that our server delegates to commands."""
    self.handler_b.side_effect = (
        lambda request, *args, **kwargs: request.send_response(212))
    response = urllib2.urlopen('http://localhost:{0}/path/b'.format(self.port))
    self.assertEqual(212, response.code)

    self.assertEqual(0, self.handler_a.call_count)
    self.assertEqual(1, self.handler_b.call_count)
    self.handler_b.assert_called_with(mock.ANY, '/path/b', {}, None)

  def test_params(self):
    """Verify that our server breaks out query parameters."""
    self.handler_a.side_effect = (
        lambda request, *args, **kwargs: request.send_response(200))
    response = urllib2.urlopen('http://localhost:{0}/path/a?p1=1&p2=test'.format(self.port))
    self.assertEqual(200, response.code)
    self.handler_a.assert_called_with(
        mock.ANY, '/path/a', {'p1': '1', 'p2': 'test'}, None)


if __name__ == '__main__':
  unittest.main()
