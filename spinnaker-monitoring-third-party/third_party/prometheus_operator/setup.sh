#!/usr/bin/env bash

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONTEXT=$(kubectl config current-context)
NAMESPACE=${1:-default}
KUBECTL="kubectl --context ${CONTEXT} --namespace ${NAMESPACE}"
echo "Using context ${CONTEXT} and namespace ${NAMESPACE}."

echo "Adding the Spinnaker ServiceMonitor..."
$KUBECTL apply -f spinnaker-service-monitor.yaml

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

echo "Applying dashboards as configmaps to cluster..."
$KUBECTL apply -f generated_dashboards
