# Copyright 2019 Google Inc. All Rights Reserved.
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

# pylint: disable=missing-docstring

from datetime import datetime
import collections
import json
import logging
import os
import urllib2
import httplib2

import spectator_client
from spectator_metric_transformer import PercentileDecoder


try:
  import apiclient
  from oauth2client.client import GoogleCredentials
  from oauth2client.service_account import ServiceAccountCredentials
  STACKDRIVER_AVAILABLE = True
except ImportError:
  STACKDRIVER_AVAILABLE = False


# This doesnt belong here, but this library insists on logging
# ImportError: file_cache is unavailable when using oauth2client >= 4.0.0
# The maintainer wont fix or remove the warning so we'll force it to be disabled
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)


GenericTaskInfo = collections.namedtuple('GenericTaskInfo',
                                         ['monitored_resource', 'start_time'])


def enforce(prefix, options, key, value):
  prefix = 'stackdriver.' + (prefix + '.' if prefix else '')
  if options.get(key) is not None and options[key] != value:
    logging.error('Forcing %s%s = %r  (rather than %r)',
                  prefix, key, value, options[key])
  options[key] = value


def normalize_options(options, embedded_options_key='stackdriver'):
  options_copy = dict(options)
  service_options = options_copy.get(embedded_options_key, {})
  options_copy[embedded_options_key] = service_options

  # Use toplevel overrides (e.g. commandline) if any
  for key in ['project', 'zone', 'instance_id', 'credentials_path']:
    if options_copy.get(key):
      service_options[key] = options[key]  # commandline override
  if options_copy.get('manage_stackdriver_descriptors'):
    service_options['manage_descriptors'] = (
        options_copy['manage_stackdriver_descriptors'])

  if service_options.get('enforce_standards'):
    prefix = ''
    enforce(prefix, service_options, 'distributions_also_have_count', True)
    enforce(prefix, service_options, 'fix_custom_metrics_unsafe', False)

    prefix = 'spectator'
    spectator = service_options.get('spectator')
    if spectator is None:
      spectator = {}

    enforce(prefix, spectator, 'inject_service_tag', True)
    enforce(prefix, spectator, 'decorate_metric_name', False)
    enforce(prefix, spectator, 'use_base_service_name_only', False)

    enforce(prefix, spectator, 'use_snake_case', True)
    enforce(prefix, spectator, 'enforce_stackdriver_names', True)
    enforce(prefix, spectator, 'summarize_compound_kinds', True)
    enforce(prefix, spectator, 'transform_values', True)
    if not options_copy.get('spectator'):
      options_copy['spectator'] = spectator
    else:
      options_copy['spectator'].update(spectator)

  return options_copy


# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
def get_aws_identity_document():
  url = 'http://169.254.169.254/latest/dynamic/instance-identity/document'
  request = urllib2.Request(url)
  try:
    response = urllib2.urlopen(request)
  except IOError as ioex:
    logging.info('Cannot read AWS Identity Document,'
                 ' probably not on Amazon Web Services.'
                 ' url=%s: %s', url, ioex)
    raise ioex
  return json.JSONDecoder().decode(response.read())


# https://cloud.google.com/compute/docs/storing-retrieving-metadata
def get_google_metadata(attribute):
  url = 'http://169.254.169.254/computeMetadata/v1/' + attribute
  request = urllib2.Request(url)
  request.add_header('Metadata-Flavor', 'Google')
  try:
    response = urllib2.urlopen(request)
  except IOError as ioex:
    logging.info('Cannot read google metadata,'
                 ' probably not on Google Cloud Platform.'
                 ' url=%s: %s', url, ioex)
    raise ioex

  return response.read()


def determine_local_project():
  """Determine which GCP project we are currently running in, if at all.

  Running on GCP is special because it means we can infer which
  Stackdriver project we're associating the metrics with.
  """
  try:
    return get_google_metadata('project/numeric-project-id')
  except IOError:
    # Not running on GCP
    return None


class GoogleMeasurementData(
    collections.namedtuple(
        'GoogleMeasurementData',
        ['metricKind', 'startTime', 'endTime', 'valueType', 'valueData']
    )):

  @staticmethod
  def make_from_measurement(
      service, service_metadata, metric_metadata, measurement):
    value_type, value_key = {
        int: ('INT64', 'int64Value'),
        bool: ('BOOL', 'boolValue'),
        float: ('DOUBLE', 'doubleValue'),
        dict: ('DISTRIBUTION', 'temp')
    }[measurement['v'].__class__]

    metric_kind = metric_metadata['kind']
    start_time = service.millis_to_time(service_metadata.get('startTime', 0))
    end_time = service.millis_to_time(measurement['t'])
    value_data = measurement['v']

    primitive_kind = service.spectator_helper.determine_primitive_kind(
        metric_kind)
    if primitive_kind == spectator_client.SUMMARY_PRIMITIVE_KIND:
      metric_kind = 'CUMULATIVE'
      value_type = 'DISTRIBUTION'
      raw_value = value_data
      bucket_bounds, bucket_counts, count = service.compute_buckets(raw_value)

      # Use the reported count for the mean so it will be more accurate
      raw_count = raw_value['count']
      # Summary was either a timer (totalTime) or summary (totalAmount).
      total = raw_value.get('totalTime') or raw_value.get('totalAmount', 0)
      mean = float(total) / float(raw_count) if raw_count else 0

      bucket_options = {
          'explicitBuckets': {'bounds': bucket_bounds}
      }

      value_key = 'distributionValue'
      value_data = {
          'count': count,  # agree with bucket_counts to pass Stackdriver check
          'mean': mean,
          'bucketOptions': bucket_options,
          'bucketCounts': bucket_counts
      }
    elif primitive_kind == spectator_client.GAUGE_PRIMITIVE_KIND:
      metric_kind = 'GAUGE'
    else:
      metric_kind = 'CUMULATIVE'

    return GoogleMeasurementData(metric_kind, start_time, end_time,
                                 value_type, {value_key: value_data})


class GoogleMonitoringService(object):
  SERVICE_SCOPE = None    # derived classes override this
  SERVICE_KEY = None      # derived classes override this
  SERVICE_NAME = None     # derived classes override this
  SERVICE_VERSION = None  # derived classes override this

  @staticmethod
  def millis_to_time(millis):
    return datetime.fromtimestamp(millis / 1000).isoformat('T') + 'Z'

  @property
  def project(self):
    """Returns the stackdriver project being used."""
    return self.__project

  @property
  def stub(self):
    """Returns the stackdriver client stub."""
    if self.__stub is None:
      self.__stub = self.__stub_factory()
    return self.__stub

  @property
  def spectator_helper(self):
    return self.__spectator_helper

  @property
  def service_options(self):
    """Return stackdriver config options."""
    return self.__service_options

  def _update_monitored_resources(self, service_map):
    """Exposed for testing."""
    if self.__service_options.get('generic_task_resources'):
      self.__update_monitored_generic_task_resources(service_map)
    else:
      self.__update_monitored_deployment_resources(service_map)

  def __update_monitored_deployment_resources(self, service_map):
    template = self.__monitored_resource.get('template')
    if not template:
      template = DeployedMonitoredResourceBuilder(
          self.__service_options, self.__project).build()
      self.__monitored_resource['template'] = template
    for service in service_map.keys():
      self.__monitored_resource[service] = template

  def __service_metadata_to_task_id(self, service_metadata):
    return '%s:%s' % (service_metadata['__host'], service_metadata['__port'])

  def __update_monitored_generic_task_resources(self, service_map):
    deployed = DeployedMonitoredResourceBuilder(
        self.__service_options, self.__project).build()
    my_task_id = (deployed['labels'].get('pod_id')          # from gke_container
                  or deployed['labels'].get('pod_name')     # from k8s_container
                  or deployed['labels'].get('instance_id')  # from gce or ec2
                  or None)

    for service, service_metric_list in service_map.items():
      service_resource = self.__monitored_resource.get(service)
      if not service_resource:
        service_resource = {}
        self.__monitored_resource[service] = service_resource

      for service_metrics in service_metric_list:
        task_id = self.__service_metadata_to_task_id(service_metrics)
        start_time = service_metrics['startTime']
        info = service_resource.get(task_id)
        if info and info.start_time != start_time:
          info = None
        if info is None:
          resource = GenericTaskResourceBuilder(
              self.__service_options, self.__project).build(
                  service, task_id, service_metrics)
          service_resource[task_id] = GenericTaskInfo(resource, start_time)

  def get_monitored_resource(self, service, service_metadata):
    if not self.__service_options.get('generic_task_resources'):
      return self.__monitored_resource[service]

    task_id = self.__service_metadata_to_task_id(service_metadata)
    return self.__monitored_resource[service][task_id].monitored_resource

  def __init__(self, stub_factory, options):
    """Constructor.

    Args:
      stub_factory: [callable that creates stub for stackdriver]
          This is passed as a callable to defer initialization because
          we create the handlers before we process commandline args.
    """
    self.logger = logging.getLogger(__name__)

    options_copy = normalize_options(options)
    self.__service_options = options_copy[self.SERVICE_KEY]

    self.__stub_factory = stub_factory
    self.__stub = None
    self.__project = (self.__service_options.get('project')
                      or determine_local_project())
    logging.info('Using stackdriver project %r', self.__project)

    spectator_options = options_copy.get('spectator', {})
    stackdriver_overrides = self.__service_options.get('spectator', {})
    spectator_options.update(stackdriver_overrides)
    if self.__service_options.get('generic_task_resources'):
      spectator_options['decorate_service_name'] = False
    options_copy['spectator'] = spectator_options
    if 'transform_values' in self.__service_options:
      spectator_options['transform_values'] = (
          self.__service_options['transform_values'])
    self.__spectator_helper = spectator_client.SpectatorClientHelper(
        options_copy)
    self.__monitored_resource = {}

  @staticmethod
  def add_parser_arguments(parser):
    """Add arguments for configuring stackdriver."""
    parser.add_argument('--project', default='')
    parser.add_argument('--zone', default='')
    parser.add_argument('--instance_id', default=0, type=int)
    parser.add_argument('--credentials_path', default=None)
    parser.add_argument(
        '--stackdriver_generic_task_resources',
        default=False,
        action='store_true',
        help='Use stackdriver "generic_task" monitored resources'
        ' rather than the container or VM.')
    parser.add_argument(
        '--manage_stackdriver_descriptors',
        choices=['none', 'full', 'create', 'delete'],
        help='Specifies how to maintain stackdriver descriptors on startup.'
             '\n  none: Do nothing.'
             '\n  create: Only create new descriptors seen in the'
             ' metric filter default.yml'
             '\n  delete: Only delete existing descriptors no longer'
             ' mentioned in filter default.yml'
             '\n  full: Both create and delete.')

  def project_to_resource(self, project):
    if not project:
      raise ValueError('No project specified')
    return 'projects/' + project

  def compute_buckets(self, raw_value):
    """Convert the distribution from spectator into one for Stackdriver.

       There is a race condition in spectator where these percentile
       distributions are not thread safe. This means that the total count
       and bucket count might not agree.

       This makes Stackdriver unhappy, justifiably so, and will 400.
       Since this means we lose visibility, we'll just tweak the count to
       what is counted by the buckets.

    Args:
       raw_value is {'buckets': {bucket_num: count}, 'count': total}

    Returns:
       bounds, counts, total_count
    """
    buckets = raw_value.get('buckets')

    if not buckets:
      # Using explicitBuckets with bounds[0] is recommendation of stackdriver.
      return [0], [raw_value.get('count')], raw_value.get('count')

    decoder = PercentileDecoder.singleton()
    bounds = []
    counts = []
    last_key = -1

    total_count = 0
    for key, value in sorted(buckets.items()):
      min_value, max_value = decoder.bucket_to_min_max(key)
      if key != last_key + 1:
        # Join adjecent 0-count buckets together into a single 0-count bucket.
        counts.append(0)
        bounds.append(min_value - 1)
      last_key = key
      bounds.append(max_value)
      counts.append(int(value))
      total_count += value

    # Stackdriver interprets the last bucket as a lower bound rather than upper.
    # Add another 0-bucket so we dont misinteret the last bucket we added to be
    # a lower bound rather than capping the upper bound.
    bounds.append(max_value + 1)
    counts.append(0)

    return bounds, counts, total_count


class GoogleMonitoringServiceFactory(object):
  SERVICE_CLASS = None  # Overriden by concrete factories

  def enabled(self, options):
    """Implements server_handlers.MonitorCommandHandler interface."""
    key = self.SERVICE_CLASS.SERVICE_KEY
    return key in options.get('monitor', {}).get('metric_store', [])

  @classmethod
  def make_stub(cls, options):
    """Helper function for making a stub to talk to service."""
    if not STACKDRIVER_AVAILABLE:
      raise ImportError(
          'You must "pip install google-api-python-client oauth2client"'
          ' to get the stackdriver client library.')

    klass = cls.SERVICE_CLASS
    stackdriver_config = options.get(klass.SERVICE_KEY, {})
    credentials_path = options.get('credentials_path', None)
    if credentials_path is None:
      credentials_path = stackdriver_config.get('credentials_path')
    if credentials_path:
      credentials_path = os.path.expandvars(credentials_path)

    http = httplib2.Http()
    http = apiclient.http.set_user_agent(
        http, 'SpinnakerStackdriverAgent/0.001')
    if credentials_path:
      logging.info('Using %s Credentials from "%s"',
                   klass.SERVICE_KEY, credentials_path)
      credentials = ServiceAccountCredentials.from_json_keyfile_name(
          credentials_path, scopes=klass.SERVICE_SCOPE)
    else:
      logging.info('Using Stackdriver Credentials from application default.')
      credentials = GoogleCredentials.get_application_default()

    http = credentials.authorize(http)
    discovery_url = options.get('stackdriver', {}).get('discovery_url')
    developer_key = os.environ.get(
        'STACKDRIVER_API_KEY',
        options.get('stackdriver', {}).get('api_key'))
    kwargs = {}
    if discovery_url:
      kwargs['discoveryServiceUrl'] = discovery_url
      logging.info('Overriding stackdriver discoveryServiceUrl with %r',
                   discovery_url)

    if developer_key:
      kwargs['developerKey'] = developer_key

      # We're going to assume that an API key also means dashboard access
      # is available. This isnt necessarily the case but dashboards are only
      # used for admin commands to install them so no harm done if this is
      # wrong. Those commands will just 401 or 403 if that is the case.
      url = kwargs.get('discoveryServiceUrl',
                       'https://monitoring.googleapis.com/$discovery/rest')
      sep = '&' if '?' in url else '?'
      url += sep + 'labels=DASHBOARD_TRUSTED_TESTER'
      kwargs['discoveryServiceUrl'] = url

    return apiclient.discovery.build(klass.SERVICE_NAME, klass.SERVICE_VERSION,
                                     http=http, **kwargs)

  def __call__(self, options, command_handlers):
    """Create a service instance for interacting with Stackdriver."""
    stub_factory = lambda: self.make_stub(options)
    return self.SERVICE_CLASS(stub_factory, options)


class GenericTaskResourceBuilder(object):
  """Determine generic task resource."""
  def __init__(self, options, project):
    self.__options = options
    self.__project = project

  def determine_location(self):
    try:
      zone = self.__options.get('zone')
      if not zone:
        zone = os.path.basename(get_google_metadata('instance/zone'))
      return zone
    except IOError:
      pass

    try:
      doc = get_aws_identity_document()
      return doc['region']
    except (IOError, ValueError, KeyError):
      logging.error('Not running on GCP or EC2 -- cannot determine location.'
                    ' Please provide an explicit --zone.')
      raise ValueError('Unable to determine location or --zone.')

  def build(self, service, task_id, service_metadata):
    location = self.determine_location()
    monitored_resource = {
        'type': 'generic_task',
        'labels': {
            'project_id': self.__project,
            'location': location,
            'namespace':  determine_local_project() or 'default',
            'job': 'default',   # placeholder for future use
            'task_id': task_id
        }
    }
    logging.info('%r monitored resource is %r',
                 service, monitored_resource)
    return monitored_resource


class DeployedMonitoredResourceBuilder(object):
  """Determine monitored resource based on deployment location."""

  def __init__(self, service_options, project):
    self.__project = project
    self.__service_options = service_options

  def build(self):
    monitored_resource = self.__gke_monitored_resource_or_none()

    if monitored_resource is None:
      monitored_resource = self.__google_monitored_resource_or_none()

    if monitored_resource is None:
      monitored_resource = self.__ec2_monitored_resource_or_none()

    if monitored_resource is None:
      monitored_resource = {
          'type': 'generic_node',
          'project_id': self.__project,
          'location': self.__service_options.get('generic_location', 'UNKNOWN'),
          'namespace': self.__service_options.get('generic_namespace', ''),
          'node_id': self.__service_options.get('generic_node_id', '')
      }

    logging.info('Monitoring resource=%r', monitored_resource)
    return monitored_resource

  def __ec2_monitored_resource_or_none(self):
    """If deployed on EC2, return the monitored resource, else None."""
    try:
      doc = get_aws_identity_document()

      return {
          'type': 'aws_ec2_instance',
          'labels': {
              'instance_id': doc['instanceId'],
              'region': doc['region'],
              'aws_account': doc['accountId'],
              'project_id': self.__project
          }
      }
    except (IOError, ValueError, KeyError):
      return None

  def __google_monitored_resource_or_none(self):
    """If deployed on GCE, return the monitored resource, else None."""
    project = self.__project
    zone = self.__service_options.get('zone')
    instance_id = self.__service_options.get('instance_id')

    try:
      if not project:
        project = get_google_metadata('project/project-id')
      if not zone:
        zone = os.path.basename(get_google_metadata('instance/zone'))
      if not instance_id:
        instance_id = int(get_google_metadata('instance/id'))

      return {
          'type': 'gce_instance',
          'labels': {
              'zone': zone,
              'instance_id': str(instance_id),
              'project_id': project
          }
      }
    except IOError:
      return None

  def __in_docker(self):
    """Determine if we are in a docker container or not."""
    return os.path.exists('/.dockerenv')

  def __container_from_pod(self, pod_id):
    """Determine a standard spinnaker container name from a given pod name.

    Standard containers are "spin-<service>" and pods are <container>-.
    """
    prefix = 'spin-'
    dash = pod_id.find('-', len(prefix))
    if not (dash > len(prefix) and pod_id.startswith(prefix)):
      logging.error('Cannot determine container_name from pod_id=%s',
                    pod_id)
      return None
    return pod_id[:dash]

  def __k8s_monitored_resource_or_none(self):
    """If deployed in a Kubernetes, return the monitored resource, else None."""
    if not self.__in_docker():
      return None

    cluster_name = self.__service_options.get(
        'cluster_name', os.environ.get('CLUSTER_NAME'))
    container_name = self.__service_options.get(
        'container_name', os.environ.get('CONTIANER_NAME'))
    location = self.__service_options.get(
        'location', os.environ.get('LOCATION'))
    namespace_id = self.__service_options.get(
        'namespace', os.environ.get('NAMESPACE_ID', 'spinnaker'))
    pod_id = self.__service_options.get(
        'pod_id', os.environ.get('POD_ID'))

    def check(value, name):
      if not value:
        logging.error('Cannot determine Kubernetes %s attribute', name)
        raise ValueError()

    try:
      if not container_name:
        container_name = self.__container_from_pod(pod_id)
      check(cluster_name, 'CLUSTER_NAME')
      check(container_name, 'CONTAINER_NAME')
      check(location, 'LOCATION')
      check(pod_id, 'POD_ID')
    except (IOError, KeyError, ValueError):
      return None

    return {
        'type': 'k8s_container',
        'labels': {
            'cluster_name': cluster_name,
            'container_name': container_name,
            'location': location,
            'namespace_name': namespace_id,
            'pod_name': pod_id,
            'project_id': self.__project
        }
    }

  def __gke_monitored_resource_or_none(self):
    """If deployed on GKE, return the monitored resource, else None."""
    if not self.__in_docker():
      return None

    resource = self.__google_monitored_resource_or_none()
    if resource is None:
      return None

    cluster_name = self.__service_options.get(
        'cluster_name', os.environ.get('CLUSTER_NAME'))
    container_name = self.__service_options.get(
        'container_name', os.environ.get('CONTIANER_NAME'))
    namespace_id = self.__service_options.get(
        'namespace', os.environ.get('NAMESPACE_ID', 'spinnaker'))
    pod_id = self.__service_options.get(
        'pod_id', os.environ.get('POD_ID'))

    try:
      def get_kube_env():
        kube_env = {}
        payload = get_google_metadata('instance/attributes/kube-env')
        for line in payload.split('\n'):
          colon = line.find(':')
          if colon < 0:
            continue
          kube_env[line[:colon]] = line[colon + 1:].strip()
        return kube_env

      if not cluster_name:
        cluster_name = get_kube_env()['CLUSTER_NAME']

      if not pod_id:
        pod_id = os.environ['HOSTNAME']

      if not container_name:
        container_name = self.__container_from_pod(pod_id)

    except (IOError, KeyError, ValueError):
      return None

    google_labels = resource['labels']
    return {
        'type': 'gke_container',
        'labels': {
            'cluster_name': cluster_name,
            'container_name': container_name,
            'instance_id': google_labels['instance_id'],
            'namespace_id': namespace_id,
            'pod_id': pod_id,
            'project_id': google_labels['project_id'],
            'zone': google_labels['zone']
        }
    }
