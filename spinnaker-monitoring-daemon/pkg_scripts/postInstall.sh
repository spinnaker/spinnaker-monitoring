#!/usr/bin/env bash

pip install -r /opt/spinnaker-monitoring/requirements.txt

LOG_DIR="/var/log/spinnaker/monitoring"
mkdir -p "${LOG_DIR}"
chown spinnaker:spinnaker "${LOG_DIR}"
chown -R spinnaker:spinnaker /opt/spinnaker-monitoring
