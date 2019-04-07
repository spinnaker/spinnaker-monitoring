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
# pylint: disable=superfluous-parens

import cgi
import logging

try:
  from googleapiclient.errors import HttpError
  STACKDRIVER_AVAILABLE = True
except ImportError:
  STACKDRIVER_AVAILABLE = False


def compare_descriptor_types(a, b):
  """Compare two metric types to sort them in order."""
  # pylint: disable=invalid-name
  a_root = a['type']
  b_root = b['type']
  return (-1 if a_root < b_root
          else 0 if a_root == b_root
          else 1)


def determine_metric_prefix(options):
  return options.get('metric_name_prefix',
                     'custom.googleapis.com/spinnaker/')
  

def get_descriptor_list(stackdriver):
  """Return a list of all the stackdriver custom metric descriptors."""
  type_map = stackdriver.descriptor_manager.fetch_all_descriptors(
      stackdriver.project)
  descriptor_list = type_map.values()
  descriptor_list.sort(compare_descriptor_types)
  return descriptor_list


class AuditResults(object):
  @property
  def descriptor_map(self):
    if self.__cached_descriptor_map is None:
      self.__cached_descriptor_map = {
          elem['type']: elem
          for elem in get_descriptor_list(self.__stackdriver)
      }
    return self.__cached_descriptor_map

  @property
  def unchanged_descriptor_names(self):
    names = set([
        descriptor['name'] for descriptor in self.descriptor_map.values()
    ])
    names -= set(self.new_descriptors.keys())
    names -= set(self.changed_descriptors.keys())

    # unused are keyed by the type
    names -= set(item['name'] for item in self.unused_descriptors.values())
    return names

  @property
  def num_unresolved_issues(self):
    return self.missing_count + self.outdated_count + self.obsoleted_count

  @property
  def num_fixed_issues(self):
    return self.created_count + self.updated_count + self.deleted_count

  def __init__(self, stackdriver):
    self.__stackdriver = stackdriver
    self.__cached_descriptor_map = None

    self.lines = []
    self.seen = {}

    self.warnings = 0
    self.errors = 0               # attempt to fix failed

    # The "could not" counts also include fixing being disabled.
    self.missing_count = 0        # new but could not create
    self.created_count = 0        # new and created OK
    self.outdated_count = 0       # modified and could not update
    self.updated_count = 0        # modified and updated OK
    self.obsoleted_count = 0      # unused but could not delete
    self.deleted_count = 0        # unused and deleted
    self.new_descriptors = {}     # wanted but not in stackdriver
    self.changed_descriptors = {} # wanted but stackdriver is different
    self.unused_descriptors = {}  # in stackdriver but no longer wanted

  def summary_string(self):
    num_unchanged = len(self.unchanged_descriptor_names)

    summary = []
    fyi = []
    fixed = []
    wrong = []
    if num_unchanged:
      summary.append(
          '* Unchanged Descriptors: %d' % num_unchanged)

    if self.new_descriptors:
      fyi.append('New Descriptors: %d' % len(self.new_descriptors))
    if self.changed_descriptors:
      fyi.append('Changed Descriptors: %d' % len(self.changed_descriptors))
    if self.unused_descriptors:
      fyi.append('Unused Descriptors: %d' % len(self.unused_descriptors))

    if self.created_count:
      fixed.append('Created Descriptors: %d' % self.created_count)
    if self.updated_count:
      fixed.append('Updated Descriptors: %d' % self.updated_count)
    if self.deleted_count:
      fixed.append('Deleted Descriptors: %d' % self.deleted_count)

    if self.missing_count:
      wrong.append('Missing Descriptors: %d' % self.missing_count)
    if self.outdated_count:
      wrong.append('Outdated Descriptors: %d' % self.outdated_count)
    if self.obsoleted_count:
      wrong.append('Obsolete Descriptors: %d' % self.obsoleted_count)

    if fyi:
      summary.append('* Issues Detected:\n  - ' + '\n  - '.join(fyi))
    if fixed:
      summary.append('* Issues Fixed:\n  - ' + '\n  - '.join(fixed))
    if wrong:
      summary.append('* Issues Remaining:\n  - ' + '\n  - '.join(wrong))

    if self.warnings:
      summary.append('* Warnings: %d' % self.warnings)
    if self.errors:
      summary.append('* Errors: %d' % self.errors)
    return '\n'.join(summary)


class BatchProcessor(object):
  """Helper class for managing events in batch."""

  @property
  def project(self):
    return self.__project

  def __init__(self, project, stackdriver,
               audit_results, action,
               data_list, invocation_factory, get_name):
    """Constructor.

    Args:
      data_list: [object] The data to operate on.
    """
    self.__project = project
    self.__stackdriver = stackdriver
    self.__audit_results = audit_results
    self.__action = action
    self.__data_list = data_list
    self.__num_data = len(self.__data_list)
    self.__invocation_factory = invocation_factory
    self.__get_name = get_name

    self.batch_response = [None] * self.__num_data
    self.bad_data = []
    self.good_data = []
    self.was_ok = [None] * self.__num_data

  def handle_batch_response(self, index_str, response, exception):
    """Record an individual response.

    Args:
      index_str: [string] The index in the batch response corresponds to
         the index in the original query so the mapping is 1:1.
      response: [HttpResponse] The response from the request, which succeeded.
      exception: [Exception] The exception from the request, which failed.
    """
    index = int(index_str)
    name = self.__get_name(self.__data_list[index])

    if exception:
      try:
        if exception.resp.status == 404:
          logging.info('Ignoring 404 on %s batched %r',
                       self.__action, name)
          exception = None
      except:
        pass

    audit_results = self.__audit_results
    if exception:
      self.bad_data.append(self.__data_list[index])
      self.was_ok[index] = False
      status = 'FAILED'
      details = ': ' + str(exception)
      self.batch_response[index] = 'ERROR {0}'.format(
          cgi.escape(str(exception)))
      logging.error(exception)
    else:
      self.good_data.append(self.__data_list[index])
      status = 'OK'
      details = '.'
      self.was_ok[index] = True
      self.batch_response[index] = 'OK {0}'.format(
          cgi.escape(str(response)))

    internal_name_prefix = (
        'projects/{project}/metricDescriptors/'
        .format(project=self.__stackdriver.project))

    audit_results.lines.append(
        '  - {status}: {action} {name!r}{details}'.format(
            status=status, action=self.__action,
            name=name[len(internal_name_prefix):],
            details=details))

  def process(self):
    """Process all the data by sending one or more batches."""
    batch = self.__stackdriver.stub.new_batch_http_request()
    max_batch = 100
    count = 0

    for data in self.__data_list:
      invocation = self.__invocation_factory(data)
      batch.add(invocation, callback=self.handle_batch_response,
                request_id=str(count))
      count += 1
      if count % max_batch == 0:
        decorator = ('final batch'
                     if count == len(self.__data_list)
                     else 'batch')
        logging.info('Executing %s of %d', decorator, max_batch)
        batch.execute()
        batch = self.__stackdriver.stub.new_batch_http_request()

    if count % max_batch:
      logging.info('Executing final batch of %d', count % max_batch)
      batch.execute()

  def response_to_text(self):
    text = ['{0}  {1}'.format(self.__get_name(self.__data_list[i]),
                              self.batch_response[i])
            for i in range(self.__num_data)]
    text.append('')
    text.append('{0} {1} of {2}'.format(self.__action,
                                        len(self.good_data), self.__num_data))
    return '\n'.join(text)


class MetricDescriptorManager(object):
  """Managed metric descriptors from spectator meter specifications."""

  SERVICE_LIST = [
      'clouddriver', 'deck', 'echo', 'fiat', 'front50',
      'gate', 'halyard', 'igor', 'kayenta', 'monitoring-service',
      'rosco'
  ]

  TAG_TYPE_MAP = {
      ''.__class__: 'STRING',
      True.__class__: 'BOOL',
      int(0).__class__: 'INT64',
      None.__class__: 'STRING'
  }

  NON_CUMULATIVE_KIND_MAP = {
      'Gauge': 'GAUGE',
      'Summary': 'DISTRIBUTION'
  }

  VALUE_TYPE_MAP = {
      'BOOL': 'BOOL',
      'REAL': 'DOUBLE',
      'SCALAR': 'INT64',
  }

  # Only recognize units stackdriver can handle.
  # Other units (e.g. "requests") will be ignored.
  UNIT_MAP = {
      'bytes': 'By',
      'nanoseconds': 'ns',
      'milliseconds': 'ms'
  }

  @property
  def spectator_response_processor(self):
    """For testing only"""
    return self.__response_processor

  def __init__(self, stackdriver, spectator_response_processor):
    """Helper function to initialize command state.

    We'll add additional state rather than passing params around.
    """
    # For getting service meter specifications.
    spectator_options = spectator_response_processor.spectator_options
    self.__metric_name_prefix = determine_metric_prefix(
        stackdriver.stackdriver_options)
    self.__stackdriver = stackdriver
    self.__response_processor = spectator_response_processor
    self.__summary_is_distribution = spectator_options.get(
        'summarize_compound_kinds')
    self.__distributions_also_have_count = stackdriver.stackdriver_options.get(
        'distributions_also_have_count')
    # When you are familiar with the internal metrics, using the display name
    # get's confusing so let's require that to be explicitly enabled.
    self.__add_display_name = stackdriver.stackdriver_options.get('add_display_name')

    self.__internal_name_prefix = (
        'projects/{project}/metricDescriptors/'
        .format(project=self.__stackdriver.project))

  def name_to_type(self, name):
    """Determine Custom Descriptor type name for the given metric type name."""
    return self.__metric_name_prefix + name

  def distribution_to_counter(self, name):
    """Converts a distribution name (or type) into a corresponding counter.
    
    The counter is used for convienence in determine the count in the distribution.
    """
    return name + '_count'

  def fetch_all_descriptors(self, project):
    """Get all the spinnaker descriptors already known in Stackdriver."""
    project_name = 'projects/' + (project or self.__stackdriver.project)
    found = {}

    def partition(descriptor):
      descriptor_type = descriptor['type']
      if descriptor_type.startswith(self.__metric_name_prefix):
        found[descriptor_type] = descriptor

    self.foreach_descriptor(partition, name=project_name)
    return found

  def foreach_descriptor(self, func, **args):
    """Apply a function to each metric descriptor known to Stackdriver."""
    api = self.__stackdriver.stub.projects().metricDescriptors()
    request = api.list(**args)

    count = 0
    while request:
      logging.info('Fetching metricDescriptors')
      response = request.execute()
      for elem in response.get('metricDescriptors', []):
        count += 1
        func(elem)
      request = api.list_next(request, response)
    return count

  def spectator_meter_name_to_descriptors(self, service, spectator_name):
    """Return desired descriptor[s] given a spectator meter name.

    Args:
      service: [string] The spectator service name.
      spectator_name: [string] The meter name in the spectator response.
    Returns:
      A list of stackdriver descriptors derived from an explicitly provided
      tranform specification on the spectator_name.

      If there is none, including if meter transforms are not being used,
      then None.

      Composite spectator meters may result in multiple descriptors.
      For example a Timer will have __count and __totalTime descriptors.
    """
    rulebase = self.__response_processor.determine_service_metric_transformer(
        service).rulebase
    rule = rulebase.get(spectator_name)
    if rule is None:
      return None
    return self.__transform_rule_to_descriptors(spectator_name, rule)

  def _determine_value_type(self, rule):
    """Determine stackdriver value type from rule's value value."""
    want = self.VALUE_TYPE_MAP.get(rule.value_type)
    if want is None:
      logging.warning('Unrecognized value type for metric rule %r', rule)
      want = 'DOUBLE'
    return want

  def __transform_rule_to_descriptors(self, spectator_name, rule):
    """Derive MetricDescriptor object implied by a transform rule.

    In practice a rule may imply multiple metrics. This happens for
    "compound" spectator metrics where there is a "statistic" tag
    that will be broken out into the individual components. For example
    a spectator Timer will result in a stackdriver __count and __totalTime.

    Returns:
      List of MetricDescriptor objects
    """
    meter_name = rule.determine_meter_name(spectator_name)
    base_stackdriver_type = self.name_to_type(meter_name)
    spec = rule.rule_specification
    meter_kind = spec.get('kind')

    want = {
        'type': base_stackdriver_type,
        'name': self.__internal_name_prefix + base_stackdriver_type,
        'metricKind': self.NON_CUMULATIVE_KIND_MAP.get(meter_kind,
                                                       'CUMULATIVE'),
        'valueType': self._determine_value_type(rule),
        'labels': self.__derive_labels(spec),
    }
    unit = self.UNIT_MAP.get(spec.get('unit'))
    if unit:
      want['unit'] = unit
    if self.__add_display_name and spec.get('display_name'):
      displayName = spec.get('display_name')
    else:
      displayName = 'Spinnaker ' + meter_name
    want['displayName'] = displayName

    if spec.get('docs'):
      want['description'] = spec.get('docs')

    result = []
    meter_is_timer = meter_kind in ['Timer', 'PercentileTimer']
    meter_is_distribution = meter_kind in ['DistributionSummary',
                                           'PercentileDistributionSummary']
    if self.__summary_is_distribution and meter_is_timer:
      want['unit'] = 'ns'
      self.__append_summary(meter_name, want, result)
    elif self.__summary_is_distribution and meter_is_distribution:
      self.__append_summary(meter_name, want, result)

    elif (meter_is_timer or meter_is_distribution):
      if meter_is_timer:
        totalSuffix = 'totalTime'
        displayNameSuffix = 'total time'
        unit = "ns"
      else:
        totalSuffix = 'totalAmount'
        displayNameSuffix = 'total'
        unit = None

      if not rule.discard_tag_value('statistic', 'count'):
        component = dict(want)
        component['name'] += '__count'
        component['type'] += '__count'
        component['description'] = 'Number of measurements in {timer}.'.format(
            timer='%s__%s' % (meter_name, totalSuffix))
        if component.get('displayName'):
          component['displayName'] += ' count'
        result.append(component)

      if not rule.discard_tag_value('statistic', totalSuffix):
        component = dict(want)
        component['name'] += '__' + totalSuffix
        component['type'] += '__' + totalSuffix
        if unit:
          component['unit'] = unit
        if component.get('displayName'):
          component['displayName'] += ' ' + displayNameSuffix
        result.append(component)

    else:
      result.append(want)

    if (meter_kind.startswith('Percentile')
        and not self.__summary_is_distribution):
      # Only consider "percentile" dimension if not using distributions.
      if not rule.discard_tag_value('statistic', 'percentile'):
        component = dict(want)
        component['name'] += '__percentile'
        component['type'] += '__percentile'
        component['description'] = (
            'Percentile bucket time referenced by {summary}.'.format(
                summary='%s__count' % meter_name))
        result.append(component)

    return result

  def __append_summary(self, meter_name, want, result):
    if self.__distributions_also_have_count:
      # Add an implied metric which is just a counter.
      # This is to workaround a temporary shortcoming querying the counts.
      # Eventually this will be deprecated.
      component = dict(want)
      component['description'] = (
          'Counter mirroring number of measurements in %s.' % meter_name)
      component['type'] = self.distribution_to_counter(component['type'])
      component['name'] = self.distribution_to_counter(component['name'])

      if 'unit' in component:
        del component['unit']
      component['valueType'] = 'INT64'
      component['metricKind'] = 'CUMULATIVE'
      if component.get('displayName'):
        component['displayName'] += ' count'
      result.append(component)

    want['valueType'] = 'DISTRIBUTION'
    want['metricKind'] = 'CUMULATIVE'
    result.append(want)

  def __derive_labels(self, spec):
    result = {'spin_service': 'STRING', 'spin_variant': 'STRING'}
    for name in spec.get('tags') or []:
      result[name] = 'STRING'
    for name, value in spec.get('add_tags', {}).items():
      result[name] = self.TAG_TYPE_MAP[value.__class__]
    for info in spec.get('change_tags', []):
      to_name_list = info['to']
      to_type = info['type']
      if not isinstance(to_name_list, list):
        to_name_list = [to_name_list]
        to_type = [to_type]
      for index, name in enumerate(to_name_list):
        result[name] = {'INT': 'INT64'}.get(to_type[index],
                                            to_type[index])

    if spec.get('per_account', False) and 'account' in result:
      del(result['account'])
    if spec.get('per_application', False) and 'application' in result:
      del(result['application'])

    normalized_result = []
    for key, value_type in result.items():
      label_descriptor = {'key': key}
      if value_type != 'STRING':
        label_descriptor['valueType'] = value_type
      normalized_result.append(label_descriptor)
    return sorted(normalized_result)

  def replace_custom_metric_descriptor(self, metric_name, descriptor,
                                       new_descriptor=False):
    """Replace Stackdriver's custom metric descriptor definition.

    Args:
      metric_name: [String] The stackdriver metric name to replace.
      descriptor:  [dict] The custom metric descriptor definition
          payload.
    """
    stackdriver = self.__stackdriver
    api = stackdriver.stub.projects().metricDescriptors()
    if new_descriptor:
      logging.info('Creating descriptor %s', metric_name)
    else:
      try:
        logging.info('Deleting existing descriptor %s', metric_name)
        response = api.delete(name=metric_name).execute()
        logging.info('Delete response: %s', repr(response))
      except HttpError as err:
        logging.error('Could not delete descriptor %s', err)
        if err.resp.status != 404:
          return False
        else:
          logging.info("Ignore error.")
        logging.info('Updating descriptor as %s', descriptor)

    try:
      response = api.create(
          name=stackdriver.project_to_resource(stackdriver.project),
          body=descriptor).execute()
      logging.info('Response from create: %s', response)
      return True
    except HttpError as err:
      logging.error('Failed: %s', err)
      return False

  def delete_descriptors(self, descriptor_list, audit_results):
    if not descriptor_list:
      return
    project = self.__stackdriver.project
    projects_api = self.__stackdriver.stub.projects()
    delete_method = projects_api.metricDescriptors().delete

    def delete_invocation(descriptor):
      logging.info('batch DELETE %s', descriptor['name'])
      return delete_method(name=descriptor['name'])
    get_descriptor_name = lambda descriptor: descriptor['name']

    audit_results.lines.append(
        'Deleting %d descriptors' % len(descriptor_list))

    processor = BatchProcessor(
        project, self.__stackdriver, audit_results, 'Delete',
        descriptor_list, delete_invocation, get_descriptor_name)
    processor.process()
    audit_results.errors += len(processor.bad_data)
    audit_results.obsoleted_count += len(processor.bad_data)
    audit_results.deleted_count += len(processor.good_data)

    for descriptor in processor.good_data:
      del(audit_results.descriptor_map[descriptor['type']])

  def upsert_descriptors(self, audit_results):
    self.__update_descriptors(audit_results)
    self.__insert_descriptors(audit_results)

  def __insert_descriptors(self, audit_results):
    # pylint: disable=invalid-name
    descriptor_map = audit_results.new_descriptors
    if not descriptor_map:
      return
    audit_results.lines.append('Create {count} descriptors'.format(
        count=len(descriptor_map)))
    for actual_name, actual_want in descriptor_map.items():
      ok = self.replace_custom_metric_descriptor(
          actual_name, actual_want, new_descriptor=True)
      if ok:
        audit_results.descriptor_map[actual_name] = actual_want
        audit_results.created_count += 1
        status = 'OK'
      else:
        audit_results.missing_count += 1
        audit_results.errors += 1
        status = 'FAILED'

      audit_results.lines.append(
          '* {status}: CREATE {name!r}: {value!r}'
          .format(status=status,
                  name=actual_name, value=actual_want))

  def __update_descriptors(self, audit_results):
    # pylint: disable=invalid-name
    descriptor_map = audit_results.changed_descriptors
    if not descriptor_map:
      return
    audit_results.lines.append('Update {count} descriptors'.format(
        count=len(descriptor_map)))
    for actual_name, actual_want in descriptor_map.items():
      ok = self.replace_custom_metric_descriptor(
          actual_name, actual_want, new_descriptor=False)
      if ok:
        audit_results.descriptor_map[actual_name] = actual_want
        audit_results.updated_count += 1
        status = 'OK'
      else:
        audit_results.outdated_count += 1
        audit_results.errors += 1
        status = 'FAILED'

      audit_results.lines.append(
          '* {status}: UPDATE {name!r}: {value!r}'
          .format(status=status,
                  name=actual_name, value=actual_want))

  def audit_descriptors(self, options, service_list=None):
    stackdriver_options = options['stackdriver']
    audit_results = AuditResults(self.__stackdriver)
    mode = stackdriver_options.get('manage_descriptors') or 'none'
    mode = mode.lower()
    delete = mode in ['full', 'delete']
    create = mode in ['full', 'create']

    logging.debug(
        'Managing stackdriver descriptors with'
        ' mode=%s create=%s, delete=%s in services=%s',
        mode, create, delete, service_list)

    if service_list is None:
      service_list = self.SERVICE_LIST
    for service in service_list:
      self.audit_service(service, audit_results)
    audit_results.unused_descriptors = {
        key: descriptor
        for key, descriptor in audit_results.descriptor_map.items()
        if key not in audit_results.seen
    }

    if delete:
      self.delete_descriptors(audit_results.unused_descriptors.values(),
                              audit_results)
    elif audit_results.unused_descriptors:
      audit_results.lines.append((
          'WARNING: %d Descriptors are no longer needed (delete disabled):'
          '\n  - ' % len(audit_results.unused_descriptors)
          ) + '\n  - '.join([
              item['type']
              for item in audit_results.unused_descriptors.values()]))
      audit_results.obsoleted_count += len(
          audit_results.unused_descriptors)
      audit_results.warnings += len(audit_results.unused_descriptors)

    if create:
      self.upsert_descriptors(audit_results)
    else:
      if audit_results.new_descriptors:
        audit_results.lines.append((
            'WARNING: Missing %d descriptors (create disabled):'
            '\n  + ' % len(audit_results.new_descriptors)
            ) + '\n  + '.join([
                item['type']
                for item in audit_results.new_descriptors.values()]))
        audit_results.warnings += len(audit_results.new_descriptors)
        audit_results.missing_count += len(
            audit_results.new_descriptors)

      if audit_results.changed_descriptors:
        audit_results.lines.append((
            'WARNING: %d descriptors are outdated (create disabled):'
            '\n  + ' % len(audit_results.changed_descriptors)
            ) + '\n  + '.join([
                item['type']
                for item in audit_results.changed_descriptors.values()]))
        audit_results.warnings += len(audit_results.changed_descriptors)
        audit_results.outdated_count += len(
            audit_results.changed_descriptors)

    return audit_results

  def audit_service(self, service, audit_results):
    """Update (or insert) metric descriptors for the given service.

    Args:
      service: [string] The name of the service whose metrics to update.
      audit_results: [AuditResults] The audit results to update with
        results from this service.
    """

    rulebase = self.__response_processor.determine_service_metric_transformer(
        service).rulebase
    for key, rule_list in rulebase.items():
      descriptors = []
      for rule in rule_list:
        descriptors.extend(self.__transform_rule_to_descriptors(key, rule))
      self.__do_audit(service, descriptors, audit_results)

  def __do_audit(self, service, descriptors, audit_results):
    for actual_want in descriptors:
      actual_name = actual_want['name']
      actual_type = actual_want['type']
      already_saw = audit_results.seen.get(actual_type)

      if not self.__diff_descriptor(service, actual_want, audit_results):
        audit_results.seen[actual_type] = service
        continue

      if already_saw:
        audit_results.warnings += 1
        audit_results.lines.append(
            'WARNING: {name} conflicts with {service}\n'
            '   want {want!r}\n'
            '   have {have!r}\n'
            .format(name=actual_name, service=service,
                    want=actual_want,
                    have=audit_results.descriptor_map.get(actual_type)))

  def __diff_descriptor(self, service, want, audit_results):
    descriptor = (audit_results.new_descriptors.get(want['name'])
                  or audit_results.changed_descriptors.get(want['name'])
                  or audit_results.descriptor_map.get(want['type']))
    if not descriptor:
      audit_results.new_descriptors[want['name']] = want
      return True

    result = False
    for key, expect in want.items():
      value = descriptor.get(key)
      if isinstance(expect, list):
        expect = sorted(expect)
        if isinstance(value, list):
          value = sorted(value)
      if value != expect:
        # pylint: disable=logging-format-interpolation
        logging.info('{service} expected {key!r} in {type!r}'
                     ' to be {expect!r} not {found!r}\n'
                     .format(service=service, key=key,
                             type=want['type'], expect=expect,
                             found=value))
        result = True

    if result:
      audit_results.changed_descriptors[want['name']] = want

    return result
