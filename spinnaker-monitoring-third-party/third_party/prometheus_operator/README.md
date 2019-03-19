# Prometheus Operator + Spinnaker

This setup script assumes:

* You've already enabled Prometheus metric store in Spinnaker
* You've already installed Prometheus Operator to your cluster

## Usage

`./setup.sh <kubeconfig-context>`

provide an optional kubeconfig context to the script to use.

If you don't provide a context, it will use the current kubeconfig context.
