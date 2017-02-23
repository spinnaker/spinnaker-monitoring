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


SOURCE_DIR=$(dirname $0)
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


function prompt_if_unset() {
  local name=$1
  local tmp

  # Attempt to read the key out of the dd-agent file if it exists.
  if [[ "${!name}" == "" ]] && [[ -f /etc/dd-agent/datadog.conf ]]; then
      if [[ "$name" == "DATADOG_API_KEY" ]]; then
        local value=$(grep api_key /etc/dd-agent/datadog.conf 2> /dev/null \
                      | sed "s/^api_key: *//")
        eval ${name}=$value
      fi
  fi
  while [[ "${!name}" == "" ]]; do
      read -e -p "ENTER $name: " tmp
      eval ${name}=$tmp
  done
}

function install_server() {
  echo "Installing Datadog Agent"
  prompt_if_unset DATADOG_API_KEY
  DD_API_KEY=$DATADOG_API_KEY bash -c "$(curl -L https://raw.githubusercontent.com/DataDog/dd-agent/master/packaging/datadog-agent/source/install_agent.sh)"
}

function install_dashboards() {
  prompt_if_unset DATADOG_API_KEY
  prompt_if_unset DATADOG_APP_KEY

  for dashboard in ${SOURCE_DIR}/*Timeboard.json; do
    echo "Installing $(basename $dashboard)"
    curl -s -X POST -H "Content-type: application/json" \
         -d "@${dashboard}" \
        "https://app.datadoghq.com/api/v1/dash?api_key=${DATADOG_API_KEY}&application_key=${DATADOG_APP_KEY}" > /dev/null
  done

}

function install_client() {
  if [[ -f /opt/spinnaker-monitoring/config/spinnaker-monitoring.yml ]]; then
    echo "Injecting Datadog API key into spinnaker-monitoring.yml"
    echo "   and enabling Datadog in spinnaker-monitoring.yml"
    chmod 600 /opt/spinnaker-monitoring/config/spinnaker-monitoring.yml
    sed -e "s/\(^ *api_key:\).*/\1 $DATADOG_API_KEY/" \
        -e "s/^\( *\)#\( *- datadog$\)/\1\2/" \
        -i /opt/spinnaker-monitoring/config/spinnaker-monitoring.yml
  else
    echo ""
    echo "You will need to edit /opt/spinnaker-monitoring/config/spinnaker-monitoring.yml to add your DATADOG_API_KEY and to add datadog as a monitor_store before running spinnaker-monitoring."
  fi
}

process_args "$#"


if $SERVER; then
  install_server
fi

if $DASHBOARDS; then
  install_dashboards
fi

if $CLIENT; then
  install_client
fi

