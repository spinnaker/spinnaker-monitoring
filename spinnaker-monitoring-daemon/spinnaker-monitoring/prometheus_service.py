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
import time

import command_processor
import spectator_client

try:
  from prometheus_client import (
      CONTENT_TYPE_LATEST,
      generate_latest)

  from prometheus_client.core import (
      GaugeMetricFamily,
      CounterMetricFamily,
      REGISTRY)

  from prometheus_client.exposition import push_to_gateway
  PROMETHEUS_AVAILABLE = True
except ImportError:
  PROMETHEUS_AVAILABLE = False


InstanceRecord = collections.namedtuple(
    'InstanceRecord', ['service', 'netloc', 'tags', 'data'])
MetricInfo = collections.namedtuple('MetricInfo', ['kind', 'tags', 'records'])


class BaseMeterBuilder(object):
  """Base class for populating prometheus data objects."""

  def __init__(self, family, name, labels, documentation=''):
    self.__meter = family(name, documentation, labels=labels)
    self.__labels = labels

    # These might be -1
    self.__job_tag_index = labels.index('job')
    self.__instance_tag_index = labels.index('instance')

  def build(self):
    """Return the prometheus client library object."""
    return self.__meter

  def add_instance(self, labels, instance):
    """Add a new datapoint to the prometheus client data object."""
    # Just use the first value. We arent controlling the timestamp
    # so multiple values would be meaningless anyway.
    self.__meter.add_metric(labels=labels, value=instance['values'][0]['v'])

  def add_meter_info(self, info):
    """Add all the datapoints to the prometheus client data object."""

    # All the Prometheus metrics need to have the same sequence of tags.
    # However the did not necessarily come this way from Spectator so we
    # will normalize them. Fortunately it doesnt matter if the tags change
    # from period to period (call to call). They only need to be consistent
    # within the individual collection response.
    label_names = self.__labels
    for record in info.records:
      instance = record.data
      label_values = [''] * len(label_names)
      for elem in record.tags:
        index = label_names.index(elem['key'])
        if index >= 0:
          label_values[index] = elem['value']
      if self.__job_tag_index >= 0:
        label_values[self.__job_tag_index] = record.service
      if self.__instance_tag_index >= 0:
        label_values[self.__instance_tag_index] = record.netloc

      self.add_instance(label_values, instance)


class CounterBuilder(BaseMeterBuilder):
  """Populate prometheus client library Counters."""
  def __init__(self, name, labels):
    super(CounterBuilder, self).__init__(
        CounterMetricFamily, name, labels)


class GaugeBuilder(BaseMeterBuilder):
  """Populate prometheus client library Gauges."""
  def __init__(self, name, labels):
    super(GaugeBuilder, self).__init__(
        GaugeMetricFamily, name, labels)


class PrometheusMetricsCollection(object):
  """Manage a collection of prometheus client library data objects."""
  @property
  def metrics(self):
    """Return a list of prometheus client library data objects."""
    return self.__metrics

  def __init__(self, metalabels):
    self.__metrics = []
    self.__metalabels = metalabels

  def add_info(self, service, name, info):
    """Add a metric from a given service.

    Args:
       service: [string] The service name.
       name: [string] The metric name.
       info: All the scraped values for the metric.
    """
    metric_name = '{service}:{name}'.format(
        service=service, name=name.replace('.', ':').replace('-', '_'))
    builder = self.make_metric_builder(metric_name, info)
    builder.add_meter_info(info)
    self.__metrics.append(builder.build())

  def make_metric_builder(self, metric_name, info):
    """Return the type-specific builder for the given metric."""
    if self.__metalabels:
      all_tags = list(info.tags)
      all_tags.extend(self.__metalabels)
    else:
      all_tags = info.tags

    kind_to_factory = {
        spectator_client.COUNTER_PRIMITIVE_KIND: CounterBuilder,
        spectator_client.GAUGE_PRIMITIVE_KIND: GaugeBuilder
    }
    primitive_kind = spectator_client.determine_primitive_kind(info.kind)
    return kind_to_factory[primitive_kind](metric_name, all_tags)


class PrometheusMetricsService(object):
  """Implements monitoring service that implements a Prometheus client.

  This service implements the Prometheus client library interface which
  collects metrics in response to a collect() call.
  """

  def __init__(self, options):
    if not PROMETHEUS_AVAILABLE:
      raise ImportError(
          'You must "pip install prometheus-client" to get'
          ' the prometheus client library.')

    self.__catalog = spectator_client.get_source_catalog(options)
    self.__spectator = spectator_client.SpectatorClient(options)

    add_metalabels = options.get(
        'prometheus_add_source_metalabels',
        options.get('prometheus', {}).get('add_source_metalabels', True))
    self.__metalabels = {'job', 'instance'} if add_metalabels else {}

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

    metric_collection = PrometheusMetricsCollection(self.__metalabels)
    for service, name_to_info in service_to_name_to_info.items():
      for name, info in name_to_info.items():
        metric_collection.add_info(service, name, info)

    return metric_collection.metrics


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
  """Factory for injecting prometheus integration."""

  def enabled(self, options):
    """Implements server_handlers.MonitorCommandHandler interface."""
    return 'prometheus' in options.get('monitor', {}).get('metric_store', [])

  def add_argparser(self, parser):
    """Implements server_handlers.MonitorCommandHandler interface."""
    parser.add_argument(
        '--prometheus', default=False,
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
