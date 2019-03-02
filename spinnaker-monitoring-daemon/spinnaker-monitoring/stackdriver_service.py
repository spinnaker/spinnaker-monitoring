# Copyright 2016 Google Inc. All Rights Reserved.
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
import copy
import json
import logging
import os
import re
import time
import traceback
import urllib2
import httplib2

import spectator_client
import stackdriver_descriptors


try:
  import apiclient
  from googleapiclient.errors import HttpError
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


def normalize_options(options):
  options_copy = dict(options)
  stackdriver_options = options_copy.get('stackdriver', {})
  options_copy['stackdriver'] = stackdriver_options

  # Use toplevel overrides (e.g. commandline) if any
  for key in ['project', 'zone', 'instance_id', 'credentials_path']:
    if options_copy.get(key):
      stackdriver_options[key] = options[key]  # commandline override
  if options_copy.get('manage_stackdriver_descriptors'):
    stackdriver_options['manage_descriptors'] = (
        options_copy['manage_stackdriver_descriptors'])

  if 'fix_labels_unsafe' not in stackdriver_options:
    stackdriver_options['fix_labels_unsafe'] = options.get(
        'fix_stackdriver_labels_unsafe', False)

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


class StackdriverMetricsService(object):
  """Helper class for interacting with Stackdriver."""
  WRITE_SCOPE = 'https://www.googleapis.com/auth/monitoring'
  MAX_BATCH = 200
  JANITOR_PERIOD = 600

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
  def descriptor_manager(self):
    """Return MetricDescriptorManager."""
    return self.__descriptor_manager

  @property
  def stackdriver_options(self):
    """Return stackdriver config options."""
    return self.__stackdriver_options

  def _update_monitored_resources(self, service_map):
    """Exposed for testing."""
    if self.__stackdriver_options.get('generic_task_resources'):
      self.__update_monitored_generic_task_resources(service_map)
    else:
      self.__update_monitored_deployment_resources(service_map)

  def __update_monitored_deployment_resources(self, service_map):
    template = self.__monitored_resource.get('template')
    if not template:
      template, self.__add_source_tag = (
          DeployedMonitoredResourceBuilder(
              self.__stackdriver_options, self.__project).build())
      self.__monitored_resource['template'] = template
    for service in service_map.keys():
      self.__monitored_resource[service] = template

  def __service_metadata_to_task_id(self, service_metadata):
    return '%s:%s' % (service_metadata['__host'], service_metadata['__port'])

  def __update_monitored_generic_task_resources(self, service_map):
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
              self.__stackdriver_options, self.__project).build(
                  service, task_id, service_metrics)
          service_resource[task_id] = GenericTaskInfo(resource, start_time)

  def get_monitored_resource(self, service, service_metadata):
    if not self.__stackdriver_options.get('generic_task_resources'):
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
    self.__stackdriver_options = options_copy['stackdriver']

    self.__stub_factory = stub_factory
    self.__stub = None
    self.__project = self.__stackdriver_options.get('project')
    logging.info('Using stackdriver project %r', self.__project)

    spectator_options = options_copy.get('spectator', {})
    stackdriver_overrides = self.__stackdriver_options.get('spectator', {})
    spectator_options.update(stackdriver_overrides)
    if self.__stackdriver_options.get('generic_task_resources'):
      spectator_options['inject_service_tag'] = False
      spectator_options['decorate_service_name'] = False
    options_copy['spectator'] = spectator_options
    if 'transform_values' in self.__stackdriver_options:
      spectator_options['transform_values'] = (
          self.__stackdriver_options['transform_values'])
    self.__spectator_helper = spectator_client.SpectatorClientHelper(options_copy)
    self.__distributions_also_have_count = self.__stackdriver_options.get(
        'distributions_also_have_count')

    if not self.__project:
      # Set default to our instance if we are on GCE.
      # Otherwise ignore since we might not actually need the project.
      try:
        self.__project = get_google_metadata('project/project-id')
      except IOError:
        pass

    manager = stackdriver_descriptors.MetricDescriptorManager(
        self,
        spectator_client.ResponseProcessor(options_copy))
    self.__descriptor_manager = manager
    # The janitor prepares metric descriptors before first write.
    self.__janitor_func = lambda: self.__auto_audit_metric_descriptors(options_copy)
    self.__next_janitor_time = time.time()
    self.__good_janitor_count = 0

    self.__fix_stackdriver_labels_unsafe = self.__stackdriver_options.get(
        'fix_labels_unsafe', False)
    self.__monitored_resource = {}
    self.__add_source_tag = False

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

  def __auto_audit_metric_descriptors(self, options):
    """The janitor function attempts to bring Stackdriver into compliance.

    If the metric descriptors are already as expected then we'll disable
    the janitor for the rest of the process' lifetime. Otherwise we'll
    continue to call it and try again around every JANITOR_PERIOD seconds
    to give time for the system to settle down.

    The reason we expect to have problems is that old replicas are still
    running and recreating the descriptors we are trying to delete when
    stackdriver automatically creates metrics they are attempting to write.
    If this is the case, we'll keep trying to clear them out until, eventually,
    the old processes are no longer around to overwrite us.

    Should something re-emerge then we'll be messed up until the next restart.
    Note that each replica of each service is probably trying to create all
    the descriptors so there is a lot of activity here. Since the descriptors
    are all the same, there should not be a problem with these replicas
    conflicting or needing coordination.

    Note if management is disabled then this will be in a stable state
    though still inconsistent with stackdriver because there will not
    be any errors or activity performed.
    """
    secs_remaining = self.__next_janitor_time - time.time()
    if secs_remaining > 0:
      logging.debug('Janitor skipping audit for at least another %d secs',
                    secs_remaining)
      return

    logging.info('Janitor auditing metric descriptors...')
    audit_results = self.__descriptor_manager.audit_descriptors(options)
    stable = (audit_results.errors == 0
              and audit_results.num_fixed_issues == 0)
    now = time.time()
    self.__next_janitor_time = now + self.JANITOR_PERIOD

    if stable:
      self.__good_janitor_count += 1
      if self.__good_janitor_count > 1:
        logging.info('Metric descriptors appear stable. Disabling janitor.')
        self.__janitor_func = lambda: None
      else:
        logging.info('Keeping janitor around to build confidence.')
    else:
      self.__good_janitor_count = 0
      logging.debug('Metric descriptors are not yet stable.'
                    ' There may be some errors writing metrics.'
                    ' Check again in %d secs.',
                    self.JANITOR_PERIOD)

  def publish_metrics(self, service_metrics):
    self.__janitor_func()

    time_series = []
    self._update_monitored_resources(service_metrics)
    spectator_client.foreach_metric_in_service_map(
        service_metrics, self.add_metric_to_timeseries, time_series)
    offset = 0
    method = self.stub.projects().timeSeries().create

    while offset < len(time_series):
      last = min(offset + self.MAX_BATCH, len(time_series))
      chunk = time_series[offset:last]
      try:
        (method(name=self.project_to_resource(self.__project),
                body={'timeSeries': chunk})
         .execute())
      except HttpError as err:
        self.handle_time_series_http_error(err, chunk)
      offset = last
    return len(time_series)

  def find_problematic_elements(self, error, batch):
    try:
      content = json.JSONDecoder().decode(error.content)
      message = content['error']['message']
    except KeyError:
      return []

    found = []

    unknown_label_pattern = (r'timeSeries\[(\d+?)\]\.metric\.labels\[\d+?\]'
                             r' had an invalid value of "(\w+?)"')
    for match in re.finditer(unknown_label_pattern, message):
      ts_index = int(match.group(1))
      label = match.group(2)
      metric = batch[ts_index]['metric']
      metric_type = metric['type']
      found.append((self.add_label_and_retry,
                    label, metric_type, batch[ts_index]))

    counter_to_gauge_pattern = (
        r'timeSeries\[(\d+?)\]\.metricKind'
        r' had an invalid value of \"(CUMULATIVE|GAUGE)\"'
        r'.* must be (CUMULATIVE|GAUGE).')
    for match in re.finditer(counter_to_gauge_pattern, message):
      ts_index = int(match.group(1))
      metric = batch[ts_index]['metric']
      metric_type = metric['type']
      found.append((self.delete_descriptor_and_retry,
                    metric_type, batch[ts_index]))

    return found

  def delete_descriptor_and_retry(self, metric_type, ts_request):
    metric_name_param = '/'.join([
        self.project_to_resource(self.__project),
        'metricDescriptors', metric_type])
    api = self.stub.projects().metricDescriptors()

    try:
      logging.info('Deleting existing descriptor %s', metric_name_param)
      response = api.delete(name=metric_name_param).execute()
      logging.info('Delete response: %s', repr(response))
    except HttpError as err:
      logging.error('Could not delete descriptor %s', err)
      if err.resp.status != 404:
        return
      else:
        logging.info("Ignore error.")

    logging.info('Retrying create timeseries %s', ts_request)
    (self.stub.projects().timeSeries().create(
        name=self.project_to_resource(self.__project),
        body={'timeSeries': ts_request})
     .execute())

  def add_label_and_retry(self, label, metric_type, ts_request):
    if self.add_label_to_metric(label, metric_type):
      # Try again to write time series data.
      logging.info('Retrying create timeseries %s', ts_request)
      (self.stub.projects().timeSeries().create(
          name=self.project_to_resource(self.__project),
          body={'timeSeries': ts_request})
       .execute())

  def add_label_to_metric(self, label, metric_type):
    metric_name_param = '/'.join([
        self.project_to_resource(self.__project),
        'metricDescriptors', metric_type])
    logging.info('Attempting to add label "%s" to %s', label, metric_type)
    api = self.stub.projects().metricDescriptors()

    try:
      descriptor = api.get(name=metric_name_param).execute()
    except HttpError as err:
      # Maybe another process is deleting it
      logging.error('Could not get descriptor: %s', err)
      return False

    labels = descriptor.get('labels', [])
    if [elem for elem in labels if elem['key'] == label]:
      logging.info('Label was already added: %s', descriptor)
      return True

    logging.info('Starting with metricDescriptors.get %s:', descriptor)
    labels.append({'key': label, 'valueType': 'STRING'})
    descriptor['labels'] = labels
    return self.__descriptor_manager.replace_custom_metric_descriptor(
        metric_name_param, descriptor)

  def handle_time_series_http_error(self, error, batch):
    logging.error('Caught %s', error)

    if error.resp.status == 400:
      problems = self.find_problematic_elements(error, batch)
      logging.info('PROBLEMS %r', problems)
      if problems and not self.__fix_stackdriver_labels_unsafe:
        logging.info(
            'Fixing this problem would wipe stackdriver data.'
            ' Doing so was not enabled with --fix_stackdriver_lables_unsafe')
      elif problems:
        logging.info('Attempting to fix these problems. This may lose'
                     ' stackdriver data for these metrics. To disable this,'
                     ' invoke with --nofix_stackdriver_labels_unsafe.')
        for elem in problems:
          try:
            elem[0](*elem[1:])
          except BaseException as bex:
            traceback.print_exc()
            logging.error('Failed %s(%s): %s', elem[0], elem[1:], bex)

  def add_metric_to_timeseries(self, service, name, instance,
                               metric_metadata, service_metadata, result):
    name, tags = self.__spectator_helper.normalize_name_and_tags(
        service, name, instance, metric_metadata)
    metric = {
        'type': self.__descriptor_manager.name_to_type(name),
        'labels': {tag['key']: tag['value'] for tag in tags}
    }
    if self.__add_source_tag:
      metric['labels']['InstanceSrc'] = '{host}:{port}'.format(
          host=service_metadata['__host'], port=service_metadata['__port'])
    value_type, value_key = {
        int: ('INT64', 'int64Value'),
        bool: ('BOOL', 'boolValue'),
        float: ('DOUBLE', 'doubleValue'),
        dict: ('DISTRIBUTION', 'temp')
    }[instance['values'][0]['v'].__class__]

    points = [{'interval': {'endTime': self.millis_to_time(e['t'])},
               'value': {value_key: e['v']}}
              for e in instance['values']]

    metric_kind = metric_metadata['kind']
    primitive_kind = self.__spectator_helper.determine_primitive_kind(
        metric_kind)
    if primitive_kind == spectator_client.SUMMARY_PRIMITIVE_KIND:
      start_time = self.millis_to_time(service_metadata.get('startTime', 0))
      if self.__distributions_also_have_count:
        # Add an implied metric which is just a counter.
        # This is to workaround a temporary shortcoming querying the counts.
        # Eventually this will be deprecated.
        counter_points = copy.deepcopy(points)
        for elem in counter_points:
          elem['interval']['startTime'] = start_time
          elem['value'] = {'int64Value': int(elem['value'][value_key]['count'])}
        counter_metric = copy.deepcopy(metric)
        counter_metric['type'] += '__count'
        result.append({
           'metric': counter_metric,
           'resource': self.get_monitored_resource(service, service_metadata),
           'metricKind': 'CUMULATIVE',
           'valueType': 'INT64',
           'points': counter_points})

      metric_kind = 'CUMULATIVE'
      value_type = 'DISTRIBUTION'
      for point in points:
        # Change points from assumed |value_key| to distributionValue
        # The |value_key| we encoded above was a dict
        raw_value = point['value'][value_key]
        count = raw_value['count']
        # Summary was either a timer (totalTime) or summary (totalAmount).
        total = raw_value.get('totalTime') or raw_value.get('totalAmount', 0)
        mean = float(total) / float(count) if count else 0

        # Using explicitBuckets with bounds[0] is recommendation of stackdriver.
        #    linearBuckets {'numFiniteBuckets':1, 'width':1, 'offset':mean}
        #    also works
        bucketOptions = {
            'explicitBuckets': {'bounds': [0]}
        }
        distribution_value = {
            'count': count,
            'mean': mean,
            'bucketOptions': bucketOptions,
            'bucketCounts': [count]
        }
        point['value'] = {'distributionValue': distribution_value}
        if metric_kind == 'CUMULATIVE':
            point['interval']['startTime'] = start_time
    elif primitive_kind == spectator_client.GAUGE_PRIMITIVE_KIND:
      metric_kind = 'GAUGE'
    else:
      metric_kind = 'CUMULATIVE'
      start_time = self.millis_to_time(service_metadata.get('startTime', 0))
      for elem in points:
        elem['interval']['startTime'] = start_time

    result.append({
        'metric': metric,
        'resource': self.get_monitored_resource(service, service_metadata),
        'metricKind': metric_kind,
        'valueType': value_type,
        'points': points})


def make_stub(options):
  """Helper function for making a stub to talk to service."""
  if not STACKDRIVER_AVAILABLE:
    raise ImportError(
        'You must "pip install google-api-python-client oauth2client"'
        ' to get the stackdriver client library.')

  stackdriver_config = options.get('stackdriver', {})
  credentials_path = options.get('credentials_path', None)
  if credentials_path is None:
    credentials_path = stackdriver_config.get('credentials_path')
  if credentials_path:
    credentials_path = os.path.expandvars(credentials_path)

  http = httplib2.Http()
  http = apiclient.http.set_user_agent(
      http, 'SpinnakerStackdriverAgent/0.001')
  if credentials_path:
    logging.info('Using Stackdriver Credentials from "%s"', credentials_path)
    credentials = ServiceAccountCredentials.from_json_keyfile_name(
        credentials_path, scopes=StackdriverMetricsService.WRITE_SCOPE)
  else:
    logging.info('Using Stackdriver Credentials from application default.')
    credentials = GoogleCredentials.get_application_default()

  http = credentials.authorize(http)
  developer_key = os.environ.get('STACKDRIVER_API_KEY',
                                 options.get('stackdriver', {}).get('api_key'))
  if developer_key:
    url = ('https://monitoring.googleapis.com/$discovery/rest'
           '?labels=DASHBOARD_TRUSTED_TESTER&key=' + developer_key)
    return apiclient.discovery.build(
        'monitoring', 'v3', http=http,
        discoveryServiceUrl=url)

  return apiclient.discovery.build('monitoring', 'v3', http=http)


def make_service(options):
  return StackdriverMetricsService(lambda: make_stub(options), options)


class StackdriverServiceFactory(object):
  def enabled(self, options):
    """Implements server_handlers.MonitorCommandHandler interface."""
    return 'stackdriver' in options.get('monitor', {}).get('metric_store', [])

  def add_argparser(self, parser):
    """Implements server_handlers.MonitorCommandHandler interface."""
    StackdriverMetricsService.add_parser_arguments(parser)
    parser.add_argument('--stackdriver', default=False, action='store_true',
                        dest='monitor_stackdriver',
                        help='Publish metrics to Stackdriver.')

    parser.add_argument(
        '--fix_stackdriver_labels_unsafe', default=True,
        action='store_true',
        help='Work around Stackdriver design bug. Using this'
        ' option can result in the loss of all historic data for'
        ' a given metric that needs to workaround. Not using this'
        ' options will result in the inability to collect metric'
        ' data for a given metric that needs the workaround.'
        ' When needed the workaround will only be needed once'
        ' and then remembered for the lifetime of the project.')
    parser.add_argument(
        '--nofix_stackdriver_labels_unsafe',
        dest='fix_stackdriver_labels_unsafe',
        action='store_false')

  def __call__(self, options, command_handlers):
    """Create a service instance for interacting with Stackdriver."""
    return make_service(options)


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
            'namespace': 'standard',  # eventually variant such as 'read-only'
            'job': service,
            'task_id': task_id
        }
    }
    logging.info('Monitoring resource=%r', monitored_resource)
    return monitored_resource


class DeployedMonitoredResourceBuilder(object):
  """Determine monitored resource based on deployment location."""

  def __init__(self, stackdriver_options, project):
    self.__project = project
    self.__stackdriver_options = stackdriver_options

  def build(self):
    add_source_tag = False
    monitored_resource = self.__gke_monitored_resource_or_none()

    if monitored_resource is None:
      monitored_resource = self.__google_monitored_resource_or_none()

    if monitored_resource is None:
      monitored_resource = self.__ec2_monitored_resource_or_none()

    if monitored_resource is None:
      add_source_tag = True
      monitored_resource = {
          'type': 'global',
          'project_id': self.__project
      }

    logging.info('Monitoring resource=%r', monitored_resource)
    return monitored_resource, add_source_tag

  def __ec2_monitored_resource_or_none(self):
    """If deployed on EC2, return the monitored resource, else None."""
    try:
      doc = get_aws_identity_document()

      return {
          'instance_id': doc['instanceId'],
          'region': doc['region'],
          'aws_account': doc['accountId'],
          'project_id': self.__project
      }
    except (IOError, ValueError, KeyError):
      return None

  def __google_monitored_resource_or_none(self):
    """If deployed on GCE, return the monitored resource, else None."""
    project = self.__project
    zone = self.__stackdriver_options.get('zone')
    instance_id = self.__stackdriver_options.get('instance_id')

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

    cluster_name = self.__stackdriver_options.get(
        'cluster_name', os.environ.get('CLUSTER_NAME'))
    container_name = self.__stackdriver_options.get(
        'container_name', os.environ.get('CONTIANER_NAME'))
    location = self.__stackdriver_options.get(
        'location', os.environ.get('LOCATION'))
    namespace_id = self.__stackdriver_options.get(
        'namespace', os.environ.get('NAMESPACE_ID', 'spinnaker'))
    pod_id = self.__stackdriver_options.get(
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

    cluster_name = self.__stackdriver_options.get(
        'cluster_name', os.environ.get('CLUSTER_NAME'))
    container_name = self.__stackdriver_options.get(
        'container_name', os.environ.get('CONTIANER_NAME'))
    namespace_id = self.__stackdriver_options.get(
        'namespace', os.environ.get('NAMESPACE_ID', 'spinnaker'))
    pod_id = self.__stackdriver_options.get(
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
