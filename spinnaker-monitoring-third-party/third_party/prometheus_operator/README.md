# Prometheus Operator + Spinnaker

This setup script assumes:

* You've already enabled Prometheus metric store in Spinnaker
* You've already installed Prometheus Operator to your cluster
* Your kubectl context is the cluster where you have Spinnaker + Prometheus Operator installed

## Usage

`./setup.sh <spinnaker-namespace>`

provide an optional namespace, if you installed Spinnaker in a different namespace than `default` on your cluster.
