# Copyright 2019 New Relic Corporation. All rights reserved.
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

import spectator_client
import logging
import os
from newrelic_telemetry_sdk import CountMetric, GaugeMetric, MetricClient


class NewRelicMetricsService(object):
    """A metrics service for interacting with New Relic."""

    def __init__(self, spectator_helper, metric_client, tags, options):
        self.spectator_helper = spectator_helper
        self.metric_client = metric_client
        self.tags = tags

    def parse_metric(self, service, metric_name, metric_instance, metric_data, service_data, metric_list):
        kind = self.spectator_helper.determine_primitive_kind(
            metric_data["kind"])
        for metric_data_value in metric_instance["values"]:
            tags = self.tags.copy()
            for tag in metric_instance["tags"]:
                tags[tag["key"]] = tag["value"]
            tags["applicationName"] = service_data["applicationName"]
            tags["applicationVersion"] = service_data["applicationVersion"]
            interval = metric_data_value["t"] - \
                service_data["__collectStartTime"]
            if kind == spectator_client.GAUGE_PRIMITIVE_KIND:
                metric_list.append(GaugeMetric(
                    name=metric_name, value=metric_data_value["v"], tags=tags))
            else:
                metric_list.append(CountMetric(
                    name=metric_name, value=metric_data_value["v"], interval_ms=interval, tags=tags))

    def publish_metrics(self, service_metrics):
        metric_list = []
        spectator_client.foreach_metric_in_service_map(
            service_metrics, self.parse_metric, metric_list)
        # using 1000 as a known-good size, not a theoretical maximum
        chunk_size = 1000
        chunks = [metric_list[i:i + chunk_size]
                  for i in xrange(0, len(metric_list), chunk_size)]
        for chunk in chunks:
            response = self.metric_client.send_batch(chunk)
            response.raise_for_status()
        return len(metric_list)


NEWRELIC_KUBERNETES_METADATA_MAPPING = {
    "NEW_RELIC_METADATA_KUBERNETES_CLUSTER_NAME": "clusterName",
    "NEW_RELIC_METADATA_KUBERNETES_NODE_NAME": "nodeName",
    "NEW_RELIC_METADATA_KUBERNETES_NAMESPACE_NAME": "namespaceName",
    "NEW_RELIC_METADATA_KUBERNETES_DEPLOYMENT_NAME": "deploymentName",
    "NEW_RELIC_METADATA_KUBERNETES_POD_NAME": "podName",
    "NEW_RELIC_METADATA_KUBERNETES_CONTAINER_NAME": "containerName",
    "NEW_RELIC_METADATA_KUBERNETES_CONTAINER_IMAGE_NAME": "containerImageName",
}


def extract_tags(options):
    tags = {}
    if 'newrelic' in options and 'tags' in options['newrelic']:
        option_tags = options['newrelic'].get('tags', []) or []
        for tag in option_tags:
            if tag.find(":"):
                tags.update(tag.split(":", 2))
    for env_var_name, tag_name in NEWRELIC_KUBERNETES_METADATA_MAPPING.iteritems():
        if env_var_name in os.environ:
            tags[tag_name] = os.environ[env_var_name]

    return tags


def make_new_relic_service(options, spectator_helper=None):
    spectator_helper = spectator_helper or spectator_client.SpectatorClientHelper(
        options)
    if 'newrelic' in options and 'insert_key' in options['newrelic']:
        insert_key = options['newrelic']['insert_key']
    elif 'NEWRELIC_INSERT_KEY' in os.environ:
        insert_key = os.environ['NEWRELIC_INSERT_KEY']
    else:
        raise Exception("New Relic is enabled but the config file has no New Relic Insights Insert Key option \n"
                        "See https://docs.newrelic.com/docs/insights/insights-data-sources/custom-data/send-custom-events-event-api for details on insert keys")
    if 'NEWRELIC_HOST' in os.environ:
        host = os.environ['NEWRELIC_HOST']
    elif 'newrelic' in options and 'host' in options['newrelic']:
        host = options['newrelic']['host']
    else:
        host = 'metric-api.newrelic.com'
    tags = extract_tags(options)
    metric_client = MetricClient(insert_key, host=host)
    return NewRelicMetricsService(spectator_helper, metric_client, tags, options)


class NewRelicServiceFactory(object):
    def enabled(self, options):
        return 'newrelic' in options.get('monitor', {}).get('metric_store', [])

    def add_argparser(self, parser):
        parser.add_argument("--newrelic", default=False, action='store_true',
                            dest='monitor_newrelic', help='Publish metrics to New Relic')

    def __call__(self, options, command_handlers):
        return make_new_relic_service(options)
