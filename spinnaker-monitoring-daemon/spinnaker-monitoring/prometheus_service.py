# Copyright 2017 Google Inc. All Rights Reserved.
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

"""Implements metric service for interacting with Prometheus.

Rather than pushing into prometheus, we'll let prometheus call us
and collect on demand. However the base interface assumes it can call
us so we'll stub that out with a no-op.

To use this service, configure prometheus.yml as follows:

scrape_configs:
  - job_name: 'spinnaker'
    static_configs:
      - targets: ['localhost:8008']
    metrics_path: '/prometheus_metrics'
    honor_labels: true


Where the localhost:8008 is the spinnaker-monitoring service.
The 'honor_labels: true' uses the job and service labels injected from
this service (which will be the spinnaker microservices the metrics came from)
rather than the job and instance labels of this service which is
what prometheus is scraping to collect the metrics.


This server also supports the PrometheusPushGateway
https://prometheus.io/download/#pushgateway
Using the push gateway, configure the daemon to publish metrics
to the push gateway by setting the prometheus.push_gateway attribute
in /opt/spinnaker-monitoring/config/spinnaker-monitoring.yml to the URL of
the push gateway, and configure prometheus to poll the pushgateway instead
of this monitoring daemon. Note that you will have to download and install
the gateway debian package. See prometheus.io.
"""

import collections
import os
import time

import command_processor
import spectator_client
import util

try:
  from prometheus_client import (
      CONTENT_TYPE_LATEST,
      generate_latest)

  from prometheus_client.core import (
      GaugeMetricFamily,
      CounterMetricFamily,
      REGISTRY)

  from prometheus_client.exposition import push_to_gateway
  prometheus_available = True
except ImportError:
  prometheus_available = False


InstanceRecord = collections.namedtuple(
    'InstanceRecord', ['service', 'netloc', 'tags', 'data'])
MetricInfo = collections.namedtuple('MetricInfo', ['kind', 'tags', 'records'])


class PrometheusMetricsService(object):
  """Implements monitoring service that implements a Prometheus client.

  This service implements the Prometheus client library interface which
  collects metrics in response to a collect() call.
  """

  def __init__(self, options):
    if not prometheus_available:
      raise ImportError(
           'You must "pip install prometheus-client" to get the prometheus client library.')
    
    self.__catalog = spectator_client.get_source_catalog(options)
    self.__spectator = spectator_client.SpectatorClient(options)
    self.__add_metalabels = options.get(
        'prometheus_add_source_metalabels',
        options.get('prometheus', {}).get('add_source_metalabels', True))

    self.__push_gateway = options.get('prometheus', {}).get('push_gateway')
    if self.__push_gateway:
      self.publish_metrics = self.__publish_to_gateway
    self.__last_collect_time = 0
    self.__last_collect_metric_map = {}
    REGISTRY.register(self)  # Register this so it will call our collect()

  def __publish_to_gateway(self, metric_map):
    """Helper function to publish polled metrics to the gateway."""

    # When we push to the gateway, prometheus will collect the metrics.
    # It doesnt have a way to inject the metrics. We've already collected
    # them so dont want to do that again. Here we will cache the metrics that
    # were injected along with our timestamp. Later in the collect method,
    # we'll check the cache time to see if it is recent before we poll for
    # the metrics (as in the non-gateway use case).
    self.__last_collect_metric_map = metric_map
    self.__last_collect_time = time.time()

    all_metrics = self.collect_with_metrics(metric_map)
    push_to_gateway(self.__push_gateway, "SpinnakerMonitoringDaemon", REGISTRY)
    return len(all_metrics)

  def __collect_instance_info(
      self, service, name,
      instance, metric_metadata, service_metadata, service_to_name_to_info):
    """Creates an InstanceRecord for the given metric sample instance.

       This record is an internal structure that will be used to feed the
       Prometheus client library API. We need to see all the different time
       series for a given metric before we can form the payload so that we
       can anticipate all the labels we are going to need each prometheus
       instance needs the same labels present, but spectator did not.

    Args:
      service: [string] The name of the service that the metric is from.
      name: [string] The name of the metric coming from the service.
      instance: [dict] The spectator entry for a specific metric value
         for a specific tag binding instance that we're going to append.
      metric_metadata: [dict] The spectator JSON object for the metric
         is used to get the kind and possibly other metadata.
      service_to_name_to_info: [dict] A dictionary keyed by service to
        A dictionary mapping metric names to MetricInfo being built.
    """
    # In practice this converts a Spinnaker Timer into either
    # <name>__count or <name>__totalTime and removes the "statistic" tag.
    name, tags = spectator_client.normalize_name_and_tags(
        name, instance, metric_metadata)
    if tags is None:
      return  # ignore metrics that had no tags because these are bogus.

    record = InstanceRecord(service,
                            '{0}:{1}'.format(service_metadata['__host'],
                                             service_metadata['__port']),
                            tags, instance)

    name_to_info = service_to_name_to_info.get(service)
    if name_to_info is None:
      name_to_info = {}
      service_to_name_to_info[service] = name_to_info

    tag_names = set([tag['key'] for tag in tags])
    info = name_to_info.get(name)
    if info is None:
      info = MetricInfo(metric_metadata['kind'], tag_names, [record])
      name_to_info[name] = info
      return

    info.records.append(record)
    info.tags.update(tag_names)

  def collect(self):
    """Implements Prometheus Client interface."""

    # We will conditionally perform our polling depending on how old
    # the metrics we have are. Under normal circumstances this should be
    # our last collection. However when we are using the push gateway,
    # we are called right after we already performed a polling so do not
    # want to poll again.
    now = time.time()
    if now - self.__last_collect_time > 1:
      self.__last_collect_metric_map = (
          self.__spectator.scan_by_service(self.__catalog))
      self.__last_collect_time = now

    all_members = self.collect_with_metrics(self.__last_collect_metric_map)
    for metric in all_members:
      yield metric

  def collect_with_metrics(self, service_metric_map):
    """Puts Spectator metrics into Prometheus client library REGISTRY."""
    service_to_name_to_info = {}
    spectator_client.foreach_metric_in_service_map(
        service_metric_map, self.__collect_instance_info,
        service_to_name_to_info)

    all_members = []
    for service, name_to_info in service_to_name_to_info.items():
      for name, info in name_to_info.items():
        family = (CounterMetricFamily
                  if info.kind in ('Counter', 'Timer')
                  else GaugeMetricFamily)

        member_name = '{service}:{name}'.format(
            service=service, name=name.replace('.', ':'))

        tags = list(info.tags)
        all_tags = list(tags)
        if self.__add_metalabels:
          all_tags.extend(['job', 'instance'])
        member = family(member_name, '', labels=all_tags)
        all_members.append(member)

        # All the Prometheus metrics need to have the same sequence of tags.
        # However the did not necessarily come this way from Spectator so we
        # will normalize them. Fortunately it doesnt matter if the tags change
        # from period to period (call to call). They only need to be consistent
        # within the individual collection response.
        for record in info.records:
          instance = record.data
          labels = [''] * len(tags)
          for elem in record.tags:
            index = tags.index(elem['key'])
            if index >= 0:
              labels[index] = elem['value']
          if self.__add_metalabels:
            labels.append(record.service)
            labels.append(record.netloc)

          # Just use the first value. We arent controlling the timestamp
          # so multiple values would be meaningless anyway.
          member.add_metric(labels=labels, value=instance['values'][0]['v'])

    return all_members


class ScrapeHandler(command_processor.CommandHandler):
  """Handles requests from Prometheus Server.

  The server should be configured to hit this URL.
  """
  def __init__(self):
    """Construct handler for Prometheus Server to call."""
    super(ScrapeHandler, self).__init__(
        '/prometheus_metrics',
        'Collect Prometheus Metrics',
        'Forces a server scrape and returns current metrics in'
        ' the current Prometheus format.')

  def process_web_request(self, request, path, params, fragment):
    output = generate_latest()
    request.respond(200, {'ContentType': CONTENT_TYPE_LATEST}, output)


class PrometheusServiceFactory(object):
  def enabled(self, options):
    """Implements server_handlers.MonitorCommandHandler interface."""
    return 'prometheus' in options.get('monitor', {}).get('metric_store', [])

  def add_argparser(self, parser):
    """Implements server_handlers.MonitorCommandHandler interface."""
    parser.add_argument('--prometheus', default=False,
                        dest='monitor_prometheus', action='store_true',
                        help='Enable endpoint for Prometheus to poll for metrics.')

    # Client library has its own http server. Not sure what we need to
    # do to hook it into ours so we'll let the client library use its server
    # for now.
    parser.add_argument(
        '--prometheus_add_source_metalabels', default=None,
        action='store_true',
        help='Add Spinnaker job/instance labels for prometheus.')

  def __call__(self, options, command_handlers):
    """Implements server_handlers.MonitorCommandHandler interface."""
    command_handlers.append(ScrapeHandler())
    return PrometheusMetricsService(options)
