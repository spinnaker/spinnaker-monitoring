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

"""Helper functions for reading configs from yaml files."""


import logging
import os
import yaml


def _log_and_load_yaml(config_path):
  """Load options from the YAML file at the specified path.

  Returns an empty dictionary and logs a warning on error.
  """
  config = {}
  try:
    with open(config_path, 'r') as stream:
      config = yaml.safe_load(stream)
      logging.info('Loaded config from %s', config_path)
  except IOError:
    logging.warn('Failed to load %s', config_path)
  return config


def update_with_overrides(baseline_config, override_config):
  for key, value in override_config.items():
    if key not in baseline_config or not isinstance(value, dict):
      baseline_config[key] = value
    else:
      update_with_overrides(baseline_config[key], value)


def merge_options_and_yaml_from_dirs(options, search_path):
  """Load options from the YAML files found in the specified search path.

  Will attempt to apply override values from "-local.yml" file if present.
  Returns an empty dictionary and logs a warning on error.

  -local files have precedence over non "-local" file, and later directories
  in the search path over earlier ones.
  """
  filenames = ['spinnaker-monitoring.yml', 'spinnaker-monitoring-local.yml']
  for filename in filenames:
    for dir_path in search_path:
      path = os.path.join(dir_path, filename)
      if os.path.exists(path):
        update_with_overrides(options, _log_and_load_yaml(path))
  return options
