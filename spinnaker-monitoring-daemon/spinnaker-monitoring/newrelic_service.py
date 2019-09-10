import spectator_client
import logging
import os
from newrelic_telemetry_sdk import CountMetric, GaugeMetric, MetricClient


class NewRelicMetricsService(object):
    """A metrics service for interacting with New Relic."""

    def __init__(self, spectator_helper, metric_client, options):
        self.spectator_helper = spectator_helper
        self.metric_client = metric_client
        tags = {}
        if 'newrelic' in options and 'tags' in options['newrelic']:
            optionTags = options['newrelic'].get('tags', [])
            if optionTags != None:
                for tag in optionTags:
                    (key, value) = tag.split(":")
                    tags[key] = value
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
    metric_client = MetricClient(insert_key, host=host)
    return NewRelicMetricsService(spectator_helper, metric_client, options)


class NewRelicServiceFactory(object):
    def enabled(self, options):
        return 'newrelic' in options.get('monitor', {}).get('metric_store', [])

    def add_argparser(self, parser):
        parser.add_argument("--newrelic", default=False, action='store_true',
                            dest='monitor_newrelic', help='Publish metrics to New Relic')

    def __call__(self, options, command_handlers):
        return make_new_relic_service(options)
