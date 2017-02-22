#!/usr/bin/env python

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


"""Tool to help support consuming Spinnaker metrics."""

import argparse
import logging
import logging.config
import os

import command_processor
import datadog_service
import datadog_handlers
import prometheus_service
import server_handlers
import spectator_client
import spectator_handlers
import stackdriver_service
import stackdriver_handlers
import util


DEFAULT_CONFIG_PATH = '/opt/spinnaker-monitoring/spinnaker-monitoring.yml'


def init_logging(options):
  """Initialize logging within this tool."""
  log_file = options['log_basename'] + '.log'
  log_dir = options['log_dir']

  log_config = {
    'version':1,
    'disable_existing_loggers':True,
    'formatters': {
      'timestamped':{
        'format':'%(asctime)s %(message)s',
        'datefmt':'%H:%M:%S'
      }
    },
    'handlers':{
      'console':{
        'level':'WARNING',
        'class':'logging.StreamHandler',
        'formatter':'timestamped'
      },
      'file':{
        'level':'DEBUG',
        'class':'logging.FileHandler',
        'formatter':'timestamped',
        'filename': os.path.join(log_dir, log_file),
        'mode':'w'
      },
    },
    'loggers':{
       '': {
         'level':'DEBUG',
         'handlers':['console', 'file']
       },
    }
  }
  logging.config.dictConfig(log_config)


def add_global_args(parser):
  """Add global parser options that are independent of the command."""
  parser.add_argument('--log_basename', default='spinnaker-monitoring')
  parser.add_argument('--log_dir', default='.')
  parser.add_argument('--config', default=DEFAULT_CONFIG_PATH,
                      help='Path to base configuration directory.')


def prepare_commands():
  """Returns a list of commands and command-line parser for options."""
  all_command_handlers = []
  parser = argparse.ArgumentParser(
      description='Helper tool to interact with Spinnaker deployment metrics.')
  add_global_args(parser)

  subparsers = parser.add_subparsers(title='commands', dest='command')
  spectator_handlers.add_handlers(all_command_handlers, subparsers)
  datadog_handlers.add_handlers(all_command_handlers, subparsers)
  stackdriver_handlers.add_handlers(all_command_handlers, subparsers)
  server_handlers.MonitorCommandHandler.register_metric_service_factory(
      prometheus_service.PrometheusServiceFactory())
  server_handlers.MonitorCommandHandler.register_metric_service_factory(
      datadog_service.DatadogServiceFactory())
  server_handlers.MonitorCommandHandler.register_metric_service_factory(
      stackdriver_service.StackdriverServiceFactory())
  server_handlers.add_handlers(all_command_handlers, subparsers)

  return all_command_handlers, parser


def main():
  """The main program sets up the commands then delegates to one of them."""

  all_command_handlers, parser = prepare_commands()
  opts = parser.parse_args()
  options = vars(opts)
  init_logging(options)
  options = util.merge_options_and_yaml_from_path(options, opts.config)

  # TODO(ewiseblatt): decouple this so we dont need to know about this here.
  # Take the union of stores enabled on the command line or in the config file.
  if options.get('monitor') is None:
    options['monitor'] = {}
  stores = options['monitor'].get('metric_store', [])
  if not isinstance(stores, list):
    stores = [stores]
  stores.extend([store for store in ['datadog', 'prometheus', 'stackdriver']
                 if options.get('monitor_' + store)])
  options['monitor']['metric_store'] = set(stores)

  command_processor.set_global_options(options)
  command_processor.process_command(
      options['command'], options, all_command_handlers)


def set_default_paths():
  abs_path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
  registry_path = os.path.join(abs_path, 'registry')
  dev_path = os.path.join(abs_path, 'registry.dev')
  yml_path = os.path.join(abs_path, 'spinnaker-monitoring.yml')

  if os.path.exists(registry_path):
    spectator_client.DEFAULT_REGISTRY_DIR = registry_path
  elif os.path.exists(dev_path):
    spectator_client.DEFAULT_REGISTRY_DIR = dev_path

  if os.path.exists(yml_path):
    global DEFAULT_CONFIG_PATH
    DEFAULT_CONFIG_PATH = yml_path


if __name__ == '__main__':
  set_default_paths()
  main()