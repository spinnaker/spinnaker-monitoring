DEFAULT_CONFIG_YML_DIR=${DEFAULT_CONFIG_YML_DIR:-$(dirname $0)/../../spinnaker-monitoring/daemon}
function find_config_path() {
  local dirs_to_search=(\
       /opt/spinnaker-monitoring \
       "$HOME/.spinnaker" \
        "$DEFAULT_CONFIG_YML_DIR")
  for dir in ${dirs_to_search[@]}; do
    if [[ -f "$dir/spinnaker-monitoring.yml" ]]; then
       echo "$dir/spinnaker-monitoring.yml"
       return
    fi
  done
  echo "/opt/spinnaker-monitoring/spinnaker-monitoring.yml"
  return
}

