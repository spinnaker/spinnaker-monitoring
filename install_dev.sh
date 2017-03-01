#!/bin/bash

ROOT_DIR=$(dirname $0)
THIRD_PARTY_DIR="$ROOT_DIR/spinnaker-monitoring-third-party/third_party"

if [[ $# -eq 0 ]] || [[ ! -f "$THIRD_PARTY_DIR/$1"/install.sh ]]; then
    >&2 echo "Usage: $0  <system> <args>"
    >&2 echo "       where <system> is one of datadog, prometheus, stackdriver"
    >&2 echo "       and args depends on the system but is typically empty."
    exit -1
fi

# Install third_party service to run as development
# This will still install and run the external services as root.
# However it creates a personal $HOME/.spinnaker/spinnaker-monitoring.yml file.

if [[ ! -f $HOME/.spinnaker/spinnaker-monitoring.yml ]]; then
  mkdir -p $HOME/.spinnaker
  cp "$ROOT_DIR/spinnaker-monitoring-daemon/spinnaker-monitoring.yml" \
     "$HOME/.spinnaker/spinnaker-monitoring.yml"
  chmod 600 "$HOME/.spinnaker/spinnaker-monitoring.yml"
fi

source "$THIRD_PARTY_DIR/install_helper_functions.sh"
echo "Using $(find_config_path $ROOT_DIR)"   # Creates as side effect if not present

which=$1
shift
sudo DEFAULT_CONFIG_YML_DIR="$DEFAULT_CONFIG_YML_DIR" \
     "$THIRD_PARTY_DIR/$which/install.sh" \
     $@

echo "Installing python requirements"
if [[ ! pip install -r spinnaker-monitoring-daemon/requirements.txt ]]
    >&2 echo "Could not install spinnaker-monitoring-daemon/requirements.txt"
    >&2 echo "You might need to sudo it yourself, use virtualenv or install python-pip."
fi
