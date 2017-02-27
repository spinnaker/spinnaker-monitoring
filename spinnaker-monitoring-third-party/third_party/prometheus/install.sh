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

PROMETHEUS_VERSION=prometheus-1.5.0.linux-amd64
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
SOURCE_DIR=$(readlink -f `dirname $0`)
GATEWAY_URL=
SERVER=true
CLIENT=true
DASHBOARDS=true

function process_args() {
  while [[ $# > 0 ]]; do
    local key="$1"
    shift
    case $key in
        --gateway)
            GATEWAY_URL="$1"
            shift
            ;;
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

function install_prometheus() {
  curl -s -S -L -o /tmp/prometheus.gz \
     https://github.com/prometheus/prometheus/releases/download/v1.5.0/prometheus-1.5.0.linux-amd64.tar.gz
  tar xzf /tmp/prometheus.gz -C /opt
  rm /tmp/prometheus.gz
  cp $SOURCE_DIR/prometheus.conf /etc/init/prometheus.conf
  if [[ ! -z $GATEWAY_URL ]]; then
      sed "s/spinnaker-prometheus\.yml/gateway-prometheus\.yml/" \
          -i /etc/init/prometheus.conf
  fi
  service prometheus start
}

function install_node_exporter() {
  curl -s -S -L -o /tmp/node_exporter.gz \
     https://github.com/prometheus/node_exporter/releases/download/v0.13.0/node_exporter-0.13.0.linux-amd64.tar.gz
  tar xzf /tmp/node_exporter.gz -C /opt/$PROMETHEUS_VERSION
  ln -fs /opt/$PROMETHEUS_VERSION/node_exporter-0.13.0.linux-amd64/node_exporter \
         /usr/bin/node_exporter
  rm /tmp/node_exporter.gz
  cp $SOURCE_DIR/node_exporter.conf /etc/init/node_exporter.conf
  service node_exporter restart
}

function install_push_gateway() {
  curl -s -S -L -o /tmp/pushgateway.gz \
     https://github.com/prometheus/pushgateway/releases/download/v0.3.1/pushgateway-0.3.1.linux-amd64.tar.gz
  tar xzf /tmp/pushgateway.gz -C /opt/$PROMETHEUS_VERSION
  ln -fs /opt/$PROMETHEUS_VERSION/pushgateway-0.3.1.linux-amd64/pushgateway \
         /usr/bin/pushgateway
  rm /tmp/pushgateway.gz
  cp $SOURCE_DIR/pushgateway.conf /etc/init/pushgateway.conf
  service pushgateway restart
}

function install_grafana() {
  curl -s -S -L -o /tmp/grafana.deb \
      https://grafanarel.s3.amazonaws.com/builds/grafana_4.1.1-1484211277_amd64.deb
  apt-get install -y adduser libfontconfig
  dpkg -i /tmp/grafana.deb
  update-rc.d grafana-server defaults
  rm /tmp/grafana.deb
  service grafana-server restart
}

function add_userdata() {
  echo "Adding datasource"
  PAYLOAD="{'name':'Spinnaker','type':'prometheus','url':'http://localhost:${PROMETHEUS_PORT}','access':'direct','isDefault':true}"
  curl -s -S -u admin:admin http://localhost:${GRAFANA_PORT}/api/datasources \
       -H "Content-Type: application/json" \
       -X POST \
       -d "${PAYLOAD//\'/\"}"

  for dashboard in ${SOURCE_DIR}/*Dashboard.json; do
    echo "Installing $(basename $dashboard)"
    x=$(sed -e "/\"__inputs\"/,/],/d" \
            -e "/\"__requires\"/,/],/d" \
            -e "s/\${DS_SPINNAKER\}/Spinnaker/g" < "$dashboard")
    temp_file=$(mktemp)
    echo "{ \"dashboard\": $x }" > $temp_file
    curl -s -S -u admin:admin http://localhost:${GRAFANA_PORT}/api/dashboards/import \
         -H "Content-Type: application/json" \
         -X POST \
         -d @${temp_file}
    rm -f $temp_file
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
  mkdir -p  /opt/$PROMETHEUS_VERSION
  if [[ -z $GATEWAY_URL ]]; then
    cp $SOURCE_DIR/spinnaker-prometheus.yml /opt/$PROMETHEUS_VERSION
    install_node_exporter
  else
    cp $SOURCE_DIR/pushgateway-prometheus.yml /opt/$PROMETHEUS_VERSION
    install_push_gateway
  fi
  install_prometheus
  install_grafana
fi

if $DASHBOARDS; then
  TRIES=0
  until nc -z localhost $GRAFANA_PORT || [[ $TRIES -gt 5 ]]; do
    sleep 1
    let TRIES+=1
  done

  add_userdata
fi

if $CLIENT; then
  # 20170226
  # Moved this from the daemon requirements for consistency with datadog.
  pip install -r "$SOURCE_DIR/requirements.txt"

  config_path=$(find_config_path)
  if [[ -f "$config_path" ]]; then
    echo "Enabling prometheus in $config_path"
    chmod 600 "$config_path"
    sed -e "s/^\( *\)#\( *- prometheus$\)/\1\2/" -i "$config_path"
    if [[ $GATEWAY_URL != "" ]]; then
      escaped_url=${GATEWAY_URL//\//\\\/}
      sed -e "s/^\( *push_gateway:\)/\1 $escaped_url/" -i "$config_path"
    fi
  else
    echo ""
    echo "You will need to edit $config_path"
    echo "  and add prometheus as a monitor_store before running spinnaker-monitoring"
    if [[ $GATEWAY_URL != "" ]]; then
        echo "  and also set prometheus to $GATEWAY_URL"
    fi
  fi
fi
