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
      esac
  done
}

function install_server() {
  curl -sSO https://repo.stackdriver.com/stack-install.sh
  if ! sudo bash stack-install.sh --write-gcm; then
    echo "See https://cloud.google.com/monitoring/agent/install-agent"
    echo "The agent is optional (and only available on GCP and AWS)"
  fi
}

function configure_client() {
  if [[ -f /opt/spinnaker-monitoring/spinnaker-monitoring.yml ]]; then
    echo "Enabling stackdriver in spinnaker-monitoring.yml"
    chmod 600 /opt/spinnaker-monitoring/spinnaker-monitoring.yml
    sed -e "s/^\( *\)#\( *- stackdriver$\)/\1\2/" \
        -i /opt/spinnaker-monitoring/spinnaker-monitoring.yml
  else
    echo ""
    echo "You will need to edit /opt/spinnaker-monitoring/spinnaker-monitoring.yml"
    echo "  and add stackdriver as a monitor_store before running spinnaker-monitoring"
  fi
}

function install_dashboards() {
  if [[ -z $STACKDRIVER_API_KEY ]]; then
    # Remove this once API is no longer whitelisted.
    echo "You need a STACKDRIVER_API_KEY to use this installer."
    exit -1
  fi
  if [[ ! -f "$DIRNAME/../../bin/spinnaker-monitoring.sh" ]]; then
    echo "You need spinnaker-monitoring installed into /opt/spinnaker-monitoring to use this installer."
    exit -1
  fi

  for dashboard in '$DIRNAME"/*Dashboard.json; do
    "$DIRNAME/../../bin/spinnaker-monitoring.sh" \
        upload_stackdriver_dashboard --dashboard ${dashboard} \
        "$@"
  done
}


process_args "$@"

if $SERVER; then
  install_server
fi

if $DASHBOARDS; then
  install_dashboards
fi

if $CLIENT; then
  configure_client
fi

