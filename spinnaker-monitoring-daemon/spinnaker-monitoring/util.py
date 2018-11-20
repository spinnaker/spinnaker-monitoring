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


def load_yaml_options(config_path):
  """Load options from the YAML file at the specified path.

  Will attempt to apply override values from "-local.yml" file if present.
  Returns an empty dictionary and logs a warning on error.
  """

  config = _log_and_load_yaml(config_path)

  local_path = None
  if config_path.endswith('.yml'):
    local_path = config_path[:-4] + '-local.yml'
  if not os.path.exists(local_path):
    return config

  local_config = _log_and_load_yaml(local_path)
  logging.info('Overriding %s with values from %s', config_path, local_path)

  update_with_overrides(config, local_config)
  return config


def merge_options_and_yaml_from_path(options, config_path):
  """Return a new dictionary containing all the options and YAML info.

  Non-None option values have higher precedence if found in both places.
  """
  config = load_yaml_options(config_path)
  for key, value in options.items():
    if value is not None:
      config[key] = value
  return config
