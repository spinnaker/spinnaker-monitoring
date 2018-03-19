# This default directory is when running from source.
DEFAULT_CONFIG_YML_DIR=\
${DEFAULT_CONFIG_YML_DIR:-$(dirname $0)/../../spinnaker-monitoring/spinnaker-monitoring-daemon/config}

if [[ `ps -p 1 | tail -1` == *systemd ]]; then
  USING_SYSTEMD=true
else
  USING_SYSTEMD=false
fi


function determine_autostart_config_path() {
   local service_name=$1
   if $USING_SYSTEMD; then
      echo "/lib/systemd/system/${service_name}.service"
   else
      echo "/etc/init/${service_name}.conf"
   fi
}


function restart_service() {
   local service_name=$1
   if $USING_SYSTEMD; then
      sudo systemctl daemon-reload
      sudo systemctl stop $service_name || true
      sudo systemctl start $service_name
      sudo systemctl enable $service_name
   else
      service $service_name restart
   fi
}


function find_config_path() {
  local dirs_to_search=(\
       /opt/spinnaker-monitoring/config \
       "$HOME/.spinnaker" \
        "$DEFAULT_CONFIG_YML_DIR")
  for dir in ${dirs_to_search[@]}; do
    if [[ -f "$dir/spinnaker-monitoring.yml" ]]; then
       echo "$dir/spinnaker-monitoring.yml"
       return
    fi
  done

  # We shouldnt reach this since we already checked for it.
  # So this is going to cause a failure later.
  echo "/opt/spinnaker-monitoring/config/spinnaker-monitoring.yml"
  return
}

GOOGLE_METADATA_URL="http://metadata.google.internal/computeMetadata/v1"
function get_google_metadata_value() {
  local path="$1"
  local value=$(curl -L -s -f -H "Metadata-Flavor: Google" \
                     $GOOGLE_METADATA_URL/$path)

  if [[ $? -eq 0 ]]; then
    echo "$value"
  else
    echo ""
  fi
}

function gce_project_or_empty() {
    echo $(get_google_metadata_value "project/project-id")
}

function gce_zone_list_or_empty() {
  local qualified_zone=$(get_google_metadata_value "instance/zone")
  local zone=$(basename $qualified_zone)
  local region=${zone%-*}
  local zones_in_region
  read zones_in_region<<<$(gcloud compute zones list \
                           | grep $region \
                           | sed "s/^\([a-z0-9-]*\) .*/\1/" \
                           | tr '\n' ' ')
  echo "$zones_in_region"
}
