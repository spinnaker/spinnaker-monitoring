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

"""Implements commands that starts the web-server daemon."""


import logging
import threading
import time
import traceback
import http_server

import command_processor
import spectator_client


class HomePageHandler(command_processor.CommandHandler):
  """Implements the home page for the server.

  This lists all the commands with links to execute them.
  """
  def __init__(self, all_handlers, url_path, command_name, description):
    """Constructor.

    Args:
      all_handlers: [list of CommandHandler] Determines the page contents.
        The entries that have url_paths will be displayed.
    """
    super(HomePageHandler, self).__init__(url_path, command_name, description)
    self.__all_handlers = all_handlers

  def process_web_request(self, request, path, params, fragment):
    """Implements CommandHandler."""
    query = self.params_to_query(params)
    rows = [(handler.url_path or '', handler.description)
            for handler in self.__all_handlers]
    rows = sorted(rows)
    row_html = [('<tr>'
                 '<td><A href="{path}{params}">{path}</A></td>'
                 '<td>{info}</td>'
                 '</tr>'.format(path=row[0], params=query, info=row[1]))
                for row in rows if row[0]]

    html_body = ('<table>\n'
                 '<tr><th>Path</th><th>Description</th></tr>'
                 '{rows}\n'
                 '</table>'
                 .format(rows='\n'.join(row_html)))
    html_doc = http_server.build_html_document(
        html_body, title='Spinnaker Metrics Administration')
    request.respond(200, {'ContentType': 'application/html'}, html_doc)


class WebserverCommandHandler(command_processor.CommandHandler):
  """Implements the embedded Web Server."""

  @property
  def command_handlers(self):
    """Return list of CommandHandlers available to the server."""
    return self.__handler_list

  def __init__(self, handler_list, url_path, command_name, description):
    """Constructor.

    Args:
      handler_list: The list of CommandHandlers available to the server.
        The server will lookup and delegate based on the URL path received.
    """
    super(WebserverCommandHandler, self).__init__(
        url_path, command_name, description)
    self.__handler_list = handler_list

  def process_commandline_request(self, options):
    """Implements CommandHandler.

    This starts the server and will run forever.
    """
    url_path_to_handler = {handler.url_path: handler.process_web_request
                           for handler in self.__handler_list}

    httpd = http_server.HttpServer(options, url_path_to_handler)
    httpd.serve_forever()

  def add_argparser(self, subparsers):
    """Implements CommandHandler."""
    parser = super(WebserverCommandHandler, self).add_argparser(subparsers)
    parser.add_argument(
        '--port', default=None, type=int,
        help='Override the port for the embedded webserver to listen on.')
    parser.add_argument(
        '--host', default=None,
        help='Override the network interface IP address for the embedded server'
        ' to listen on. The default is localhost for security.'
        ' An empty value can be used for all available interfaces.')
    spectator_client.SpectatorClient.add_standard_parser_arguments(parser)
    return parser


class MonitorCommandHandler(WebserverCommandHandler):
  """Runs the embedded Web Server with a metric publishing loop."""

  _service_factories = []

  @staticmethod
  def register_metric_service_factory(factory):
    """Add a factory for using a concrete metric service.

    This method should be called before processing commands or add_argparser().

    Args:
      factory: [obj] Factories are callable objects (options, [CommandHandler])
          That also have a method "enabled(options)" that determines if the
          service is enabled or not, and "add_argparser(ArgParser)" for adding
          command line options.
    """
    MonitorCommandHandler._service_factories.append(factory)

  def make_metric_services(self, options):
    """Create the metric services we'll use to publish metrics to a backend.
    """
    service_list = []
    for factory in MonitorCommandHandler._service_factories:
      if factory.enabled(options):
        service_list.append(factory(options, self.command_handlers))

    if service_list:
      return service_list

    raise ValueError('No metric service specified.')

  def __data_map_to_service_metrics(self, data_map):
    """Extract raw responses into just the metrics.

    Args:
      data_map: [dict of list of response dicts] Keyed by service name,
          whose value is the list of raw response dictionaries.
    Returns:
      dictionary keyed by service ame whose value is the list of 'metrics'
          dictionaries embedded in the original raw response dictionaries.
    """
    result = {}
    for service, metrics in data_map.items():
      actual_metrics = metrics.get('metrics', None)
      if actual_metrics is None:
        logging.error('Unexpected response from "%s"', service)
      else:
        result[service] = actual_metrics
    return result

  def process_commandline_request(self, options, metric_service_list=None):
    """Impements CommandHandler."""

    if metric_service_list is None:
      metric_service_list = self.make_metric_services(options)

    daemon = threading.Thread(target=self, name='monitor',
                              args=(options, metric_service_list))
    daemon.daemon = True
    daemon.start()
    super(MonitorCommandHandler, self).process_commandline_request(options)

  def __call__(self, options, metric_service_list):
    """This is the actual method that implements the CommandHandler.

    It is put here in a callable so that we can run this in a separate thread.
    The main thread will be the standard WebServer.
    """
    period = (options.get('monitor_period')
              or options.get('monitor', {}).get('period', 60))
    catalog = spectator_client.get_source_catalog(options)
    spectator = spectator_client.SpectatorClient(options)

    publishing_services = [service
                           for service in metric_service_list
                           if 'publish_metrics' in dir(service)]

    logging.info('Starting Monitor with period=%d', period)
    time_offset = int(time.time())
    while True:
      if not publishing_services:
        # we still need this loop to keep the server running
        # but the loop doesnt do anything.
        time.sleep(period)
        continue

      start = time.time()
      done = start
      service_metric_map = spectator.scan_by_service(catalog)
      collected = time.time()

      for service in publishing_services:
        try:
          start_publish = time.time()
          count = service.publish_metrics(service_metric_map)
          if count is None:
            count = 0

          done = time.time()
          logging.debug(
              'Wrote %d metrics to %s in %d ms + %d ms',
              count, service.__class__.__name__,
              (collected - start) * 1000, (done - start_publish) * 1000)
        except:
          logging.error(traceback.format_exc())
          # ignore exception, continue server.

      # Try to align time increments so we always collect around the same time
      # so that the measurements we report are in even intervals.
      # There is still going to be jitter on the collection end but we'll at
      # least always start with a steady rhythm.
      now = time.time()
      delta_time = (period - (int(now) - time_offset)) % period
      if delta_time == 0 and (int(now) == time_offset
                              or (now - start <= 1)):
        delta_time = period
      time.sleep(delta_time)

  def add_argparser(self, subparsers):
    """Implements CommandHandler."""
    parser = super(MonitorCommandHandler, self).add_argparser(subparsers)
    for factory in MonitorCommandHandler._service_factories:
      factory.add_argparser(parser)
    parser.add_argument('--period', dest='monitor_period',
                        default=None, type=int)
    return parser


def add_handlers(all_handlers, subparsers):
  """Registers the commands that run the embedded web server."""
  all_handlers.append(
      HomePageHandler(all_handlers, '/', None,
                      'Home page for Spinnaker metric administration.'))

  handler_list = [
      MonitorCommandHandler(
          all_handlers, None, 'monitor',
          'Run a daemon that monitors Spinnaker services and publishes metrics'
          ' to a metric service.'),
      WebserverCommandHandler(
          all_handlers, None, 'webserver',
          'Run a daemon that provides a webserver to manually interact with'
          ' spinnaker services publishing metrics.')
  ]
  for handler in handler_list:
    handler.add_argparser(subparsers)
    all_handlers.append(handler)
