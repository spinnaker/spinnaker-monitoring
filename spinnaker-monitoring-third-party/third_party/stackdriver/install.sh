#!/bin/bash
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

set -e
source `dirname "$0"`/../install_helper_functions.sh

DIRNAME=`dirname $0`
SERVER=true
CLIENT=true
DASHBOARDS=true

function process_args() {
  while [[ $# > 0 ]]; do
    local key="$1"
    shift
    case $key in
        --server_only)
            CLIENT=false
            DASHBOARDS=false
            ;;
        --client_only)
            SERVER=false
            DASHBOARDS=false
            ;;
        --dashboards_only)
            SERVER=false
            CLIENT=false
            ;;
        *)
            >&2 echo "Unrecognized argument '$key'."
            exit -1
    esac
  done
}

function install_server() {
  curl -sSO https://repo.stackdriver.com/stack-install.sh
  if ! bash stack-install.sh --write-gcm; then
    echo "See https://cloud.google.com/monitoring/agent/install-agent"
    echo "The agent is optional (and only available on GCP and AWS)"
  fi
}

function install_client() {
  # 20170226
  # Moved this from the daemon requirements for consistency with datadog.
  pip install -r "$DIRNAME/requirements.txt"

  config_path=$(find_config_path)
  if [[ -f "$config_path" ]]; then
    echo "Enabling stackdriver in '$config_path'"
    chmod 600 "$config_path"
    sed -e "s/^\( *\)#\( *- stackdriver$\)/\1\2/" \
        -i "$config_path"
  else
    echo ""
    echo "You will need to edit '$config_path'"
    echo "  and add stackdriver as a monitor_store before running spinnaker-monitoring"
  fi
}

function install_dashboards() {
  if [[ -z $STACKDRIVER_API_KEY ]]; then
    # Remove this once API is no longer whitelisted.
    >&2 echo "You need a STACKDRIVER_API_KEY to use this installer."
    exit -1
  fi
  local cli="$DIRNAME/../../bin/spinnaker-monitoring.sh"
  if [[ ! -f "$cli" ]]; then
    # See if we are running from source
    cli="$DIRNAME/../../../spinnaker-monitoring-daemon/bin/spinnaker-monitoring.sh"
  fi
  if [[ ! -f "$cli" ]]; then
    >&2 echo "You need spinnaker-monitoring installed into /opt/spinnaker-monitoring to use this installer."
    exit -1
  fi

  # 20170226
  # Moved this from the daemon requirements for consistency with datadog.
  pip install -r "$DIRNAME/requirements.txt"

  for dashboard in "$DIRNAME"/*-dashboard.json; do
    "$cli" upload_stackdriver_dashboard --dashboard ${dashboard} "$@"
  done
}


process_args "$@"

if $CLIENT || $SERVER; then
  if [[ $(id -u) -ne 0 ]]; then
    >&2 echo "This command must be run as root. Try again with sudo."
    exit -1
  fi
fi


if $SERVER; then
  install_server
fi

if $DASHBOARDS; then
  install_dashboards "$@"
fi

if $CLIENT; then
  install_client
fi

