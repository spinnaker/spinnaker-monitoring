#!/usr/bin/env bash

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONTEXT=${1:-$(kubectl config current-context)}


echo "Adding the Spinnaker ServiceMonitor to current context: ${CONTEXT}"

kubectl apply -f spinnaker-service-monitor.yaml


echo "Generating Grafana dashboard configmaps..."

for filename in $ROOT/../prometheus/*-dashboard.json; do
  fn_only=$(basename $filename)
  fn_root="${fn_only%.*}"
  dest_file="generated_dashboards/${fn_root}.yaml"

  cat grafana-dashboard.yaml.template | sed -e "s/%DASHBOARD%/${fn_root}/" > $dest_file
  printf "  ${fn_only}: |-\n" >> $dest_file

  cat $filename | sed -e "/\"__inputs\"/,/],/d" \
      -e "/\"__requires\"/,/],/d" \
      -e "s/\${DS_SPINNAKER\}/Prometheus/g" \
      -e "s/^/    /" \
  >> $dest_file
done


echo "applying dashboards as configmaps to cluster..."

kubectl apply -f generated_dashboards
