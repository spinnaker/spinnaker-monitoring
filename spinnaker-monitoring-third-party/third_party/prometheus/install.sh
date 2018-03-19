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
SOURCE_DIR=$(readlink -f `dirname $0`)

# Feature flags
SERVER=true
CLIENT=true
DASHBOARDS=true

# Variables for Server Configuration
# explicit prometheus versions because its not available with apt-get
# grafana will be latest version in apt-get
PROMETHEUS_VERSION=prometheus-2.2.1.linux-amd64
NODE_EXPORTER_VERSION=node_exporter-0.15.2.linux-amd64
PUSHGATEWAY_VERSION=pushgateway-0.4.0.linux-amd64
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
GCE_CONFIG=false
OVERWRITE=false

# Variables for Client Configuration
CLIENT_HOST="not specified"

# Variables for Client and Server configuration
GATEWAY_URL=


if [[ $USE_SYSTEMD ]]; then
  AUTOSTART_SOURCE_DIR=${SOURCE_DIR}/systemd
else
  AUTOSTART_SOURCE_DIR=${SOURCE_DIR}/upstart
fi
    

function show_usage() {
    cat <<EOF

Usage:

$0 [<CONTROL_OPTIONS>] [<CONFIG_OPTIONS>]

Installation scripts specific to Prometheus monitoring support for Spinnaker.
Currently this also requires installing the spinnaker-monitoring-daemon package,
usually on each machine running a Spinnaker microservice. The daemon can be
installed by running apt-get install spinnaker-monitoring-daemon. See the
--client_only option for more information.


<CONTROL_OPTIONS> specify which installations to perform.
    By default it will install client, server, and dashboards.
    When configuring a client, this script will make changes into the
    spinnaker-monitoring daemon's spinnaker-monitoring.yml configuration file
    and may install local components (such as prometheus node_extractor)

    When configuring a server, this script will install various prometheus
    infrastructure (prometheus, grafana, optiona gateway server) as well as
    start these services and configure upstart to restart them on a reboot.

    When configuring dashboards, this will install various canned dashboards
    into Grafana as well as the prometheus datasource being used. This requires
    access to port 3000, which will be present if you are installing server too.


    --no_client       Dont install the client-side components for spinnaker.
    --client_only     Only install the server-side components for spinnaker.

    --no_server       Dont install the server-side components.
    --server_only     Only install the server-side components.

    --no_dashboards   Dont install the dashboard (and datasource) data.
    --dashboards_only Only install the dashboard (and datasource) data.
                      These require connectivity to grafana (port 3000)


<CONFIG_OPTIONS> are:
    --user=USER       The grafana user name when installing dashboards.
    or --user USER   

    --password=PASSWORD      The grafana user password when installing
    or --password PASSWORD   dashboards.

    --gateway=URL     Configure prometheus to use the pushgateway.
    or --gateway URL  If using the gateway, both client and server need this.
                      Generally, the gateway is a last-resort config option.

    --gce             Configure prometheus to discovery monitoring daemons
                      in GCE VMs within this project and region.
                      This is a server configuration only, though clients
                      should use --client_host to expose the port externally.

    --overwrite       Ovewrite existing dashboards if found. This is false
                      by default. If true, existing dashboards will upgrade
                      with any changes made, however will lose any local changes
                      that might have been added to the previous installation.

    --client_host IP    Configure the spinnaker-monitoring daemon to use
    or --client_host=IP the designated NIC. Clients are configured to use
                        localhost by default. Specifying "" will enable all
                        NICs.

                        WARNING: Depending on your network and its firewall
                        rules, this may make the daemon visible to any external
                        host.


Example usage:
   $0
   Installs everything on the local machine. This is suitable when
   you are running a single-instance all-in-one spinnaker deployment with
   everything on it.

   $0 --no_client --gce
   Installs prometheus (and grafana) on the local machine, with canned
   dashboards, and configure prometheus to scan this project, in this
   region, for VMs that are running the spinnaker-monitoring daemon
   (and/or node_exporter) and monitor those. This assumes that you have
   run the client-side install where the daemon is.

   $0 --client_only
   Installs and configures the client side components. You should already
   have installed the spinnaker-monitoring-daemon package so that it can
   configure the spinnaker-monitoring.yml file. If not, then you will have
   to edit it manually later, or re-run this install with --client_only.
EOF
}


GRAFANA_USER=${GRAFANA_USER:-admin}
GRAFANA_PASSWORD=${GRAFANA_PASSWORD:-admin}


# We are going to use this file as a template for the prometheus.yml
# file we give to configure Prometheus.
# We will add additional scrape_configs for Spinnaker itself depending
# on which deployment strategy we take.
PROMETHEUS_YML_TEMPLATE=$(cat<<EOF
global:
  scrape_interval:     15s
  evaluation_interval: 15s

  external_labels:
     monitor: "spinnaker-monitor"

rule_files:
   # - "first.rules"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

EOF
)


# This is the scrape_config for the spinnaker-daemon.
# it is incomplete because it lacks the protocol and endpoint to use
# that will vary depending on how we configure it later.
SPINNAKER_YML_CONFIG=$(cat<<EOF
  - job_name: 'spinnaker'
    metrics_path: '/prometheus_metrics'
    honor_labels: true
EOF
)

# This is the scrape_config for the prometheus node_extractor.
# it is incomplete because it lacks the protocol and endpoint to use
# that will vary depending on how we configure it later.
NODE_EXTRACTOR_YML_CONFIG=$(cat<<EOF
  - job_name: 'node'
EOF
)


function process_args() {
  while [[ $# > 0 ]]; do
    local key="$1"
    shift
    case $key in
        --help)
            show_usage
            exit 0
            ;;
        --user=*)
            GRAFANA_USER="${key#*=}"  # See --user
            ;;
        --user)
            GRAFANA_USER="$1"  # Only used for dashboards (and source)
            shift
            ;;
        --password=*)
            GRAFANA_PASSWORD="${key#*=}"  # See --user
            ;;
        --password)
            GRAFANA_PASSWORD="$1"  # Only used for dashboards (and source)
            shift
            ;;

        --gateway=*)
            GATEWAY_URL="${key#*=}"  # See --gateway
            ;;
        --gateway)
            GATEWAY_URL="$1"  # Used  both client and server side
            shift
            ;;
        --gce)
            GCE_CONFIG=true  # Only used when installing the server side
            ;;
        --client_host=*)
            CLIENT_HOST="${key#*=}"  # See --client_host
            ;;
        --client_host)
            CLIENT_HOST="$1"  # host in client side spinnaker-monitoring.yml
            shift
            ;;
        --server_only)
            CLIENT=false
            DASHBOARDS=false
            ;;
        --no_server)
            SERVER=false
            ;;
        --client_only)
            SERVER=false
            DASHBOARDS=false
            ;;
        --no_client)
            CLIENT=false
            ;;
        --dashboards_only)
            SERVER=false
            CLIENT=false
            ;;
        --overwrite)
            OVERWRITE=true
            ;;
        --no_dashboards)
            DASHBOARDS=false
            ;;
        *)
            show_usage
            >&2 echo "Unrecognized argument '$key'."
            exit -1
    esac
  done
}


function extract_version_number() {
  echo "$1" | sed 's/^[^0-9]\+\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/v\1/'
}

function configure_gce_prometheus() {
  local path="$1"
  local project=$(gce_project_or_empty)
  local zone_list=$(gce_zone_list_or_empty)

  if [[ -z $project ]]; then
      >&2 echo "You are not on GCE so must manually configure $path"
      return
  fi

  #
  # We are going to configure both spinnaker and node_extractor
  # such that there is an entry for every zone.
  # We'll build both these lists in one loop
  # for each zone in our region (and project).
  #
  spinnaker_zone_configs="    gce_sd_configs:"
  node_zone_configs="    gce_sd_configs:"
  for zone in $zone_list
  do
      # Note that the indent of the data block is intentional
      local spinnaker_entry=$(cat<<EOF
      - project: '$project'
        zone: '$zone'
        port: 8008
EOF
)
      # Note that the indent of the data block is intentional
      local node_entry=$(cat<<EOF
      - project: '$project'
        zone: '$zone'
        port: 9100
EOF
)
      spinnaker_zone_configs="$spinnaker_zone_configs
$spinnaker_entry"
      node_zone_configs="$node_zone_configs
$node_entry"
  done

  #
  # Now put it all together to generate the file.
  #
  cat <<EOF > $path
$PROMETHEUS_YML_TEMPLATE
$SPINNAKER_YML_CONFIG
$spinnaker_zone_configs

$NODE_EXTRACTOR_YML_CONFIG
$node_zone_configs
EOF
  chown spinnaker:spinnaker $path >& /dev/null || true
  chmod 644 $path
}


function configure_gateway_prometheus() {
  local path="$1"
  gateway_configs=$(cat<<EOF
  - job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['localhost:9091']
EOF
)

  echo "$PROMETHEUS_YML_TEMPLATE
$gateway_configs" > $path
  chown spinnaker:spinnaker $path >& /dev/null || true
  chmod 644 $path
}


function configure_local_prometheus() {
  local path="$1"
  local spinnaker_target=$(cat<<EOF
    static_configs:
      - targets: ['localhost:8008']
EOF
)

  local node_target=$(cat<<EOF
    static_configs:
      - targets: ['localhost:9100']
EOF
)

  cat <<EOF > "$path"
$PROMETHEUS_YML_TEMPLATE
$SPINNAKER_YML_CONFIG
$spinnaker_target

$NODE_EXTRACTOR_YML_CONFIG
$node_target
EOF

  chown spinnaker:spinnaker $path >& /dev/null || true
  chmod 644 $path
}

function install_prometheus() {
  local old_conf_file_path=""
  local old_data_path=""
  local autostart_config_path=$(determine_autostart_config_path "prometheus")

  if [[ -f $autostart_config_path ]]; then
      old_data_path=$(grep storage.tsdb.path $autostart_config_path \
                      | sed "s/.*--storage.tsdb.path *\([^ ]*\).*/\1/")
      old_conf_file_path=$(grep config.file $autostart_config_path \
                      | sed "s/.*-config.file *\([^ ]*\).*/\1/")
  fi

  curl -s -S -L -o /tmp/prometheus.gz \
     https://github.com/prometheus/prometheus/releases/download/$(extract_version_number $PROMETHEUS_VERSION)/${PROMETHEUS_VERSION}.tar.gz
  local version_dir=/opt/$PROMETHEUS_VERSION
  mkdir -p $version_dir
  tar xzf /tmp/prometheus.gz -C $(dirname $version_dir)
  rm -f /opt/prometheus
  ln -fs $version_dir /opt/prometheus
  rm /tmp/prometheus.gz
  cp "$AUTOSTART_SOURCE_DIR/$(basename $autostart_config_path)" $autostart_config_path
  if [[ "$old_data_path" != "" ]]; then
     echo "Configuring existing non-standard datastore $old_data_path"
     sed "s/\/opt\/prometheus-data/${old_data_path//\//\\\/}/" \
         -i $autostart_config_path
  fi
  if [[ "$GCE_CONFIG" == "true" ]]; then
      sed "s/spinnaker-prometheus\.yml/gce-prometheus\.yml/" \
          -i $autostart_config_path
      configure_gce_prometheus "$version_dir/gce-prometheus.yml"
  elif [[ ! -z $GATEWAY_URL ]]; then
      sed "s/spinnaker-prometheus\.yml/pushgateway-prometheus\.yml/" \
          -i $autostart_config_path
      configure_gateway_prometheus "$version_dir/pushgateway-prometheus.yml"
  else
      sed "s/spinnaker-prometheus\.yml/local-prometheus\.yml/" \
          -i $autostart_config_path
      configure_local_prometheus "$version_dir/local-prometheus.yml"
  fi

  # Keep old configuration file as backup if it contains
  # customizations that may need to be re-added.
  if [[ "$old_conf_file_path" != "" ]]; then
      local old_backup="/opt/prometheus/$(basename $old_conf_file_path).old"
      if [[ ! -f $old_backup ]]; then
        echo "Copying $old_conf_file_path to $old_backup"
        cp $old_conf_file_path $old_backup
      else
        echo "Copying $old_backup already exists."
      fi
  fi

  restart_service "prometheus"
}

function install_node_exporter() {
  curl -s -S -L -o /tmp/node_exporter.gz \
     https://github.com/prometheus/node_exporter/releases/download/$(extract_version_number $NODE_EXPORTER_VERSION)/${NODE_EXPORTER_VERSION}.tar.gz
  local node_dir=/opt/${NODE_EXPORTER_VERSION}
  mkdir -p $node_dir
  tar xzf /tmp/node_exporter.gz -C $(dirname $node_dir)
  rm -f /usr/bin/node_exporter
  ln -fs $node_dir /opt/node_exporter
  ln -fs $node_dir/node_exporter /usr/bin/node_exporter
  rm /tmp/node_exporter.gz

  local autostart_config_path=$(determine_autostart_config_path "node_exporter")
  cp $AUTOSTART_SOURCE_DIR/$(basename $autostart_config_path) $autostart_config_path

  restart_service "node_exporter"
}

function install_push_gateway() {
  curl -s -S -L -o /tmp/pushgateway.gz \
     https://github.com/prometheus/pushgateway/releases/download/$(extract_version_number $PUSHGATEWAY_VERSION)/${PUSHGATEWAY_VERSION}.tar.gz
  local gateway_dir=/opt/$PUSH_GATEWAY_VERSION
  mkdir -p $gateway_dir
  tar xzf /tmp/pushgateway.gz -C $(dirname $gateway_dir)
  rm -f /usr/bin/pushgateway
  ln -fs $gateway_dir/pushgateway /usr/bin/pushgateway
  rm /tmp/pushgateway.gz

  local autostart_config_path=$(determine_autostart_config_path "pushgateway")
  cp $AUTOSTART_SOURCE_DIR/$(basename $autostart_config_path) $autostart_config_path

  restart_service "pushgateway"
}

function install_grafana() {
  echo "deb https://packagecloud.io/grafana/stable/debian/ jessie main" \
      > /etc/apt/sources.list.d/grafana.list
  curl -s -S https://packagecloud.io/gpg.key | sudo apt-key add -
  sudo apt-get update -y
  sudo apt-get install grafana -y --force-yes

  update-rc.d grafana-server defaults
  sed -e "s/^;admin_user *=.*/admin_user = $GRAFANA_USER/" \
      -e "s/^;admin_password *=.*/admin_password = ${GRAFANA_PASSWORD//\\//\\\/}/" \
      -i /etc/grafana/grafana.ini

  restart_service "grafana-server"
}

function add_grafana_userdata() {
  echo "Adding datasource"
  PAYLOAD="{'name':'Spinnaker','type':'prometheus','url':'http://localhost:${PROMETHEUS_PORT}','access':'direct','isDefault':true}"
  curl -s -S -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
       http://localhost:${GRAFANA_PORT}/api/datasources \
       -H "Content-Type: application/json" \
       -X POST \
       -d "${PAYLOAD//\'/\"}"

  for dashboard in ${SOURCE_DIR}/*-dashboard.json; do
    echo "Installing $(basename $dashboard)"
    x=$(sed -e "/\"__inputs\"/,/],/d" \
            -e "/\"__requires\"/,/],/d" \
            -e "s/\${DS_SPINNAKER\}/Spinnaker/g" < "$dashboard")
    temp_file=$(mktemp)
    echo "{ \"dashboard\": $x, \"overwrite\": $OVERWRITE }" > $temp_file
    curl -s -S -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
         http://localhost:${GRAFANA_PORT}/api/dashboards/import \
         -H "Content-Type: application/json" \
         -X POST \
         -d @${temp_file}
    rm -f $temp_file
  done
}

function enable_spinnaker_monitoring_config() {
  local config_path=$(find_config_path)
  if [[ -f "$config_path" ]]; then
    echo "Enabling prometheus in $config_path"
    chmod 600 "$config_path"
    sed -e "s/^\( *\)#\( *- prometheus$\)/\1\2/" -i "$config_path"

    if [[ "$CLIENT_HOST" != "not specified" ]]; then
      sed -e "s/\(^ *host:\).*/\1 $CLIENT_HOST/" -i "$config_path"
    fi
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
}


process_args "$@"

if $CLIENT || $SERVER; then
  if [[ $(id -u) -ne 0 ]]; then
    >&2 echo "This command must be run as root. Try again with sudo."
    exit -1
  fi
fi


if $SERVER; then
  if [[ -z $GATEWAY_URL ]]; then
    install_node_exporter
  else
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

  add_grafana_userdata
fi

if $CLIENT; then
  # 20170226
  # Moved this from the daemon requirements for consistency with datadog.
  sudo apt-get update -y
  sudo apt-get install python-pip -y --force-yes
  pip install -r "$SOURCE_DIR/requirements.txt"

  enable_spinnaker_monitoring_config
fi
