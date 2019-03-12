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

"""Implements HTTP Server."""

import textwrap
import logging
import traceback

try:
  from BaseHTTPServer import (
      HTTPServer,
      BaseHTTPRequestHandler)
  from urllib2 import unquote as urllibUnquote
except ImportError:
  from http.server import (
      HTTPServer,
      BaseHTTPRequestHandler)
  from urllib.request import unquote as urllibUnquote
    

def build_html_document(body, title=None):
  """Produces the HTML document wrapper for a text/html response."""
  title_html = '<h1>{0}</h1>\n'.format(title) if title else ''
  html = ['<html>', '<head>',
          '<title>{title}</title>'.format(title=title),
          '<style>',
          textwrap.dedent('''\
            body { font-size:10pt }
            table { font-size:10pt;border-width:none;
            border-spacing:0px;border-color:#F8F8F8;border-style:solid }
            th, td { padding:5px;vertical-align:top;
              padding-left:10px;
              border-width:1px;border-color:#F8F8F8;border-style:solid; }
            th { font-weight:bold;text-align:left;font-family:times }
            th { background-color:#666666; color:#FFFFFF }

            a:link, a:visited { background-color:#FFFFFF;color:#000099 }
            a:hover, a:active { color:#FFFFFF;background-color:#000099 }
            td.warning, a.warning, *.warning {
                background-color:#FFF8F8; color:#990033 }
            *.error, td.error, a.warning:hover {
                color:#FFF8F8; background-color:#990033 }
            td.ok, a.ok, *.ok { background-color:#EEFFEE; color:#006600 }
            a.ok:hover { color:#EEFFEE; background-color:#006600 }
          '''),
          '</style>'
          '</head>', '<body>',
          title_html,
          body,
          '</body>', '</html>']
  return '\n'.join(html)


class DelegatingRequestHandler(BaseHTTPRequestHandler):
  """An HttpServer request handler that delegates to our CommandHandler."""

  def respond(self, code, headers, body=None):
    """Send response to the HTTP request."""
    self.send_response(code)
    for key, value in headers.items():
      self.send_header(key, value)
    self.end_headers()
    if body:
      if isinstance(body, str):
        body = body.encode('utf-8')
      self.wfile.write(body)

  def decode_request(self, request):
    """Extract the URL components from the request."""
    parameters = {}
    path, _, query = request.partition('?')
    if not query:
      return request, parameters, None
    query, _, fragment = query.partition('#')

    for part in query.split('&'):
      key, _, value = part.partition('=')
      parameters[key] = urllibUnquote(value)

    return path, parameters, fragment or None

  def do_HEAD(self):
    """Implements BaseHTTPRequestHandler."""
    # pylint: disable=invalid-name
    self.respond(200, {'Content-Type': 'text/html'})

  def do_GET(self):
    """Implements BaseHTTPRequestHandler."""
    # pylint: disable=invalid-name
    path, parameters, fragment = self.decode_request(self.path)
    offset = len(path)
    handler = None
    while handler is None and offset >= 0:
      handler = HttpServer.PATH_HANDLERS.get(path[0:offset])
      if handler is None:
        offset = path.rfind('/', 0, offset)

    if handler is None:
      self.respond(404, {'Content-Type': 'text/html'}, "Unknown")
    else:
      try:
        handler(self, path, parameters, fragment)
      except:
        self.send_error(500, traceback.format_exc())
        raise

  def log_message(self, msg_format, *args):
    """Suppress HTTP request logging."""
    pass


class HttpServer(HTTPServer):
  """Implements HTTP Server that will delegate to injected request handlers."""

  PATH_HANDLERS = {}

  def __init__(self, options, handlers=None):
    server_options = options.get('server', {'port': 8008, 'host': 'localhost'})
    def get_option(name):
      """Return command-line option override or configuration value"""
      value = options.get(name)
      return value if value is not None else server_options[name]
    port = get_option('port') or 8008
    host = get_option('host') or '0.0.0.0'

    logging.info('Starting HTTP server on host=%s, port=%d', host, port)
    HTTPServer.__init__(
        self, (host, port), DelegatingRequestHandler)
    HttpServer.PATH_HANDLERS.update(handlers or {})
