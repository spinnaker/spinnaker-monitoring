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


import argparse
import os
import unittest
from mock import patch
from spectator_client import SpectatorClientHelper
from newrelic_service import (
    NewRelicServiceFactory,
    NewRelicMetricsService,
    NEWRELIC_KUBERNETES_METADATA_MAPPING,
)
from newrelic_telemetry_sdk import MetricClient


class MockRequest:
    def __init__(self, status_code=200):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("error " + str(self.status_code))


class MockMetricClient:
    def __init__(self, insert_key, host="metric-api.newrelic.com"):
        self.insert_key = insert_key or ""
        self.host = host
        self.sent_single_items = []
        self.sent_item_batches = []
        self.send_should_fail = False
        self.status_code = 200

    def send_should_have_status_code(self, status_code=200):
        """ used to set a status code other than 200 for the returned response """
        self.status_code = status_code

    def send(self, item):
        """
        sends a single item and returns a request, storing the item sent in last_item_sent.
        the object also records all items sent through this method in sent_single_items
        """
        self.last_sent_item = item
        self.sent_single_items.append(item)
        return MockRequest(self.status_code)

    def send_batch(self, items):
        self.last_sent_items = items
        self.sent_item_batches.append(items)
        return MockRequest(self.status_code)


def generate_options(insert_key="abc", host="not-metric-api.newrelic.com", tags=None):
    options = {
        "newrelic": {
            "insert_key": insert_key,
            "host": host,
            "tags": tags
        }
    }
    return options


def get_gauge_metric():
    return (
        {
            "applicationName": "spinnaker-monitoring",
            "applicationVersion": "0.0",
            "__collectStartTime": 0,
            "metrics": {
                "metricname": {
                    "kind": "Gauge",
                    "values": [
                        {
                            "tags": [
                                {
                                    "key": "test2",
                                    "value": "tag2"
                                }
                            ],
                            "values": [
                                {
                                    "v": 0.5,
                                    "t": 890697600
                                }
                            ]
                        }
                    ],
                    "tags": [
                        [
                            {
                                "key": "test",
                                "value": "tag",
                            }
                        ]
                    ]
                }
            }
        }
    )


def get_non_gauge_metric(kind="Counter"):
    return (
        {
            "applicationName": "spinnaker-monitoring",
            "applicationVersion": "0.0",
            "__collectStartTime": 0,
            "metrics": {
                "metricname": {
                    "kind": kind,
                    "values": [
                        {
                            "tags": [
                                {
                                    "key": "test2",
                                    "value": "tag2"
                                }
                            ],
                            "values": [
                                {
                                    "v": 0.5,
                                    "t": 890697600
                                }
                            ]
                        }
                    ],
                    "tags": [
                            [
                                {
                                    "key": "test",
                                    "value": "tag",
                                }
                            ]
                    ]
                }
            }
        }
    )


def getKubernetesMetadataValues():
    return {
        "NEW_RELIC_METADATA_KUBERNETES_CLUSTER_NAME": "testCluster",
        "NEW_RELIC_METADATA_KUBERNETES_NODE_NAME": "testNode",
        "NEW_RELIC_METADATA_KUBERNETES_NAMESPACE_NAME": "testNamespace",
        "NEW_RELIC_METADATA_KUBERNETES_DEPLOYMENT_NAME": "testDeployment",
        "NEW_RELIC_METADATA_KUBERNETES_POD_NAME": "testPod",
        "NEW_RELIC_METADATA_KUBERNETES_CONTAINER_NAME": "testContainer",
        "NEW_RELIC_METADATA_KUBERNETES_CONTAINER_IMAGE_NAME": "testImage",
    }


class NewRelicServiceFactoryTest(unittest.TestCase):
    def setUp(self):
        self.serviceFactory = NewRelicServiceFactory()

    def test_make_new_relic_service(self):
        """ test if options are being passed through correctly by checking url of metric client """
        options = generate_options()
        service = self.serviceFactory(options, None)
        metric_client = service.metric_client
        self.assertIsInstance(metric_client, MetricClient)
        self.assertEqual(metric_client.url, metric_client.URL_TEMPLATE.format(
            "not-metric-api.newrelic.com"))
        self.assertEqual(service.tags, {})

    def test_inject_kubernetes_metadata(self):
        options = generate_options()
        with patch.dict('os.environ', getKubernetesMetadataValues()):
            service = self.serviceFactory(options, None)
        kubernetes_metadata_values = getKubernetesMetadataValues()
        for env_var_name, tag_name in NEWRELIC_KUBERNETES_METADATA_MAPPING.iteritems():
            self.assertEqual(service.tags[tag_name],
                             kubernetes_metadata_values[env_var_name])


class NewRelicMetricsServiceTest(unittest.TestCase):
    def setUp(self):
        self.metric_client = MockMetricClient("abc")
        self.spectator_helper = SpectatorClientHelper({})

    def test_insert_gauge_metric_with_tags(self):
        """
        test a large number of attributes that should be passed through to any successfully created metric
        using a gauge metric with a tags option as a sample
        """
        options = generate_options(tags=["abc:def"])
        tags = {"abc": "def"}
        service = NewRelicMetricsService(
            self.spectator_helper, self.metric_client, tags, options)
        service_metrics = {"spinnaker-monitoring": [get_gauge_metric()]}
        num_metrics = service.publish_metrics(service_metrics)
        self.assertEqual(num_metrics, 1)
        self.assertEqual(len(self.metric_client.sent_item_batches), 1)
        self.assertEqual(len(self.metric_client.last_sent_items), 1)
        metric = self.metric_client.last_sent_items[0]
        self.assertTrue('name' in metric)
        self.assertEqual(metric['name'], 'metricname')
        # gauge metrics do not have an interval.ms property but are do not have other identifiers
        self.assertTrue('interval.ms' not in metric)
        self.assertTrue('attributes' in metric)
        self.assertTrue('applicationName' in metric['attributes'])
        self.assertEqual(metric['attributes']
                         ['applicationName'], 'spinnaker-monitoring')

        self.assertTrue('abc' in metric['attributes'])
        self.assertEqual(metric['attributes']
                         ['abc'], 'def')

        self.assertTrue('value' in metric)
        self.assertEqual(metric['value'], 0.5)

    def test_insert_gauge_metric_without_tags(self):
        """
        test that a metric with no tags option does not have extraneous attributes added
        """
        options = generate_options()
        service = NewRelicMetricsService(
            self.spectator_helper, self.metric_client, {}, options)
        service_metrics = {"spinnaker-monitoring": [get_gauge_metric()]}
        service.publish_metrics(service_metrics)
        metric = self.metric_client.last_sent_items[0]
        self.assertEqual(len(metric['attributes'].items()), 3)

    def test_metric_chunking(self):
        """
        test that a batch of 2000 metrics is correctly "chunked" into two batches
        """
        options = generate_options(tags=["abc:def"])
        tags = {"abc": "def"}
        service = NewRelicMetricsService(
            self.spectator_helper, self.metric_client, tags, options)
        service_metrics = {
            "spinnaker-monitoring": [get_gauge_metric() for _ in range(2000)]}

        num_metrics = service.publish_metrics(service_metrics)

        self.assertEqual(num_metrics, 2000)
        self.assertEqual(len(self.metric_client.last_sent_items), 1000)
        self.assertEqual(len(self.metric_client.sent_item_batches), 2)

    def test_insert_counter_metric(self):
        options = generate_options()
        service = NewRelicMetricsService(
            self.spectator_helper, self.metric_client, {}, options)
        service_metrics = {"spinnaker-monitoring":
                           [get_non_gauge_metric(),
                            get_non_gauge_metric("DistributionSummary"),
                            get_non_gauge_metric("Timer")]}
        num_metrics = service.publish_metrics(service_metrics)
        self.assertEqual(num_metrics, 3)
        for metric in self.metric_client.last_sent_items:
            # all non gauge metrics are inserted as counters so each should have an interval.ms property
            self.assertEqual(metric['interval.ms'], 890697600)

    def test_propagate_response_error(self):
        """ test if the metric service correctly raises an exception when the client returns an error """
        options = generate_options()
        self.metric_client.send_should_have_status_code(400)
        service = NewRelicMetricsService(
            self.spectator_helper, self.metric_client, {}, options)
        service_metrics = {
            "spinnaker_monitoring": [get_gauge_metric()]
        }

        with self.assertRaises(Exception) as context:
            service.publish_metrics(service_metrics)

        self.assertTrue("error 400" in context.exception)


if __name__ == "__main__":
    unittest.main()
