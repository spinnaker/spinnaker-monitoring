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

import collections
import copy
import logging
import os
import shutil
import tempfile
import unittest
import yaml
from googleapiclient.errors import HttpError

import mock
from mock import Mock

import google_service
import stackdriver_service


ResponseStatus = collections.namedtuple('ResponseStatus',
                                        ['status', 'reason'])
StackdriverResponse = collections.namedtuple(
    'StackdriverResponse', ['resp', 'content'])


def meter_name_to_descriptor_type(name):
  """Return Stackdriver MetricDescriptor type for a given meter name."""
  return 'custom.googleapis.com/spinnaker/' + name


def meter_name_to_descriptor_name(name):
  """Return Stackdriver MetricDescriptor name for a given meter name."""
  return ('projects/test-project/metricDescriptors/'
          + meter_name_to_descriptor_type(name))


class StackdriverMetricsServiceTest(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.base_temp_dir = tempfile.mkdtemp(prefix='stackdriver_test')

  @classmethod
  def tearDownClass(cls):
    shutil.rmtree(cls.base_temp_dir)

  def setUp(self):
    self.maxDiff = None
    self.filter_dir = os.path.join(
        self.base_temp_dir, self._testMethodName, 'filters')
    logging.debug('setUp %r', self._testMethodName)
    self.__do_setup()

  def __do_setup(self):
    project = 'test-project'
    instance = 'test-instance'
    options = {'project': project,
               'zone': 'us-central1-f',
               'instance_id': instance,
               'config_dir': '/notfound',
               'spectator': {'metric_filter_dir': self.filter_dir}
    }

    self.options = options
    self.mockStub = mock.create_autospec(['projects'])
    self.mockProjects = mock.create_autospec(
        ['metricDescriptors', 'timeSeries'])
    self.mockMetricDescriptors = mock.create_autospec(
        ['create', 'delete', 'get', 'list', 'list_next'])
    self.mockTimeSeries = mock.create_autospec(['create'])
    self.mockStub.projects = Mock(return_value=self.mockProjects)
    self.mockProjects.metricDescriptors = Mock(
        return_value=self.mockMetricDescriptors)
    self.mockProjects.timeSeries = Mock(return_value=self.mockTimeSeries)

    # pylint: disable=invalid-name
    self.mockCreateTimeSeries = Mock(spec=['execute'])
    self.mockCreateDescriptor = Mock(spec=['execute'])
    self.mockGetDescriptor = Mock(spec=['execute'])
    self.mockDeleteDescriptor = Mock(spec=['execute'])
    self.mockListDescriptors = Mock(spec=['execute'])

    self.mockMetricDescriptors.create = Mock(
        return_value=self.mockCreateDescriptor)
    self.mockMetricDescriptors.delete = Mock(
        return_value=self.mockDeleteDescriptor)
    self.mockMetricDescriptors.get = Mock(
        return_value=self.mockGetDescriptor)
    self.mockMetricDescriptors.list = Mock(
        return_value=self.mockListDescriptors)
    self.mockMetricDescriptors.list_next = Mock(return_value=None)

    self.mockTimeSeries.create = Mock(return_value=self.mockCreateTimeSeries)

    self.service = stackdriver_service.StackdriverMetricsService(
        lambda: self.mockStub, options)

  def test_record_counter_metric_double(self):
    self._do_test_add_metric('Counter', 'CUMULATIVE', 'DOUBLE',
                             12.0, {'doubleValue': 12.0})

  def test_record_counter_metric_scalar(self):
    self._do_test_add_metric('Counter', 'CUMULATIVE', 'INT64',
                             12, {'int64Value': 12})

  def test_record_counter_metric_bool(self):
    self._do_test_add_metric('Gauge', 'GAUGE', 'BOOL',
                             True, {'boolValue': True})
    self._do_test_add_metric('Gauge', 'GAUGE', 'BOOL',
                             False, {'boolValue': False})

  def test_record_gauge_metric(self):
    self._do_test_add_metric('Gauge', 'GAUGE', 'DOUBLE',
                             21.0, {'doubleValue': 21.0})

  def test_record_summary_metric(self):
    self.options['spectator'] = {'summarize_compound_kinds': True}
    self.service = stackdriver_service.StackdriverMetricsService(
        lambda: self.mockStub, self.options)
    bucketOptions = {
        'explicitBuckets': {'bounds': [0]}
    }
    self._do_test_add_metric('Timer', 'CUMULATIVE', 'DISTRIBUTION',
                             {'count': 4, 'totalTime': 201},
                             {'distributionValue': {
                                 'bucketOptions': bucketOptions,
                                 'bucketCounts': [4],
                                 'count': 4,
                                 'mean': 50.25
                             }})

  def _do_test_add_metric(self,
                          spectator_kind, stackdriver_kind,
                          stackdriver_value_type, raw_value, expect_value):
    result = []

    startTime = 1548685300000
    service = 'TestService'

    test_metric_instance = {
        'values': [{'t': startTime + 12345, 'v': raw_value}],
        'tags': [{'key': 'key1', 'value': 'value1'},
                 {'key': 'key2', 'value': 'value2'}]
    }

    test_metric_entry = {
        'kind': spectator_kind,
        'values': [test_metric_instance]
    }
    service_response = {
        'applicationName': service,
        'startTime': startTime,
        'metrics': {
            'TestMetric': test_metric_entry
        }
    }
    service_map = {
        'TestService': [
            service_response
        ]
    }

    self.service._update_monitored_resources(service_map)
    self.service.add_metric_to_timeseries(
        service,
        'TestMetric', test_metric_instance, test_metric_entry, service_response,
        result)

    # The dates here are the string equivalents of our hardcoded int
    interval = {'endTime': '2019-01-28T14:21:52Z'}
    if stackdriver_kind != 'GAUGE':
      interval['startTime'] = '2019-01-28T14:21:40Z'

    self.assertEquals(
        [{
            'metricKind': stackdriver_kind,
            'valueType': stackdriver_value_type,
            'metric': {
                'labels': {'key1': 'value1', 'key2': 'value2'},
                'type': 'custom.googleapis.com/spinnaker/TestService/TestMetric'
            },
            'resource': {
                'type': 'gce_instance',
                'labels': {
                    'instance_id': 'test-instance',
                    'project_id': 'test-project',
                    'zone': 'us-central1-f'
                }
            },
            'points': [{
                'interval': interval,
                'value': expect_value
            }]
        }],
        result)

  def __write_transforms(self, filename):
    xforms = {'monitoring': {'transforms' : {
        'spectator.timer': {
            'rename': 'test_system/test_timer',
            'kind': 'Timer',
            'tags': ['tag_a', 'tag_b'],
            'change_tags': [{
                'from': 'success_orig',
                'to': 'success',
                'type': 'BOOL'
            }]
        },

        'spectator.gauge': {
            'rename': 'test_system/test_gauge',
            'kind': 'Gauge',
            'unit': 'bytes',
            'docs': 'Sample documentation.'
        },

        'spectator.counter': {
            'rename': 'test_system/test_counter',
            'kind': 'Counter',
            'docs': 'Counter documentation.'
        },

        'spectator.summary': {
            'rename': 'test_system/test_summary',
            'kind': 'Summary',
            'docs': 'Summary documentation.'
        },
    }}}
    os.makedirs(self.filter_dir)
    with open(os.path.join(self.filter_dir, filename), 'w') as stream:
      yaml.safe_dump(xforms, stream)

    timer_type = meter_name_to_descriptor_type('test_system/test_timer')
    timer_name = meter_name_to_descriptor_name('test_system/test_timer')

    timer_descriptor = {
        'valueType': 'DOUBLE',
        'metricKind': 'CUMULATIVE',
        'name': timer_name,
        'type': timer_type,
        'labels': [
            {'key': 'spin_service'},
            {'key': 'spin_variant'},
            {'key': 'tag_a'},
            {'key': 'tag_b'},
            {'key': 'success', 'valueType': 'BOOL'}
        ],
    }

    result = {}

    descriptor = dict(timer_descriptor)
    descriptor['name'] = timer_name + '__count'
    descriptor['type'] = timer_type + '__count'
    descriptor['description'] = (
        'Number of measurements in test_system/test_timer__totalTime.')
    result[descriptor['name']] = descriptor

    descriptor = dict(timer_descriptor)
    descriptor['name'] = timer_name + '__totalTime'
    descriptor['type'] = timer_type + '__totalTime'
    descriptor['unit'] = 'ns'
    result[descriptor['name']] = descriptor

    gauge = {
        'valueType': 'DOUBLE',
        'metricKind': 'GAUGE',
        'name': meter_name_to_descriptor_name('test_system/test_gauge'),
        'type': meter_name_to_descriptor_type('test_system/test_gauge'),
        'description': 'Sample documentation.',
        'unit': 'By',
        'labels': [
            {'key': 'spin_service'},
            {'key': 'spin_variant'}
        ]
    }
    result[gauge['name']] = gauge

    counter = {
        'valueType': 'DOUBLE',
        'metricKind': 'CUMULATIVE',
        'name': meter_name_to_descriptor_name('test_system/test_counter'),
        'type': meter_name_to_descriptor_type('test_system/test_counter'),
        'description': 'Counter documentation.',
        'labels': [
            {'key': 'spin_service'},
            {'key': 'spin_variant'}
        ]
    }
    result[counter['name']] = counter

    summary = {
        'valueType': 'DOUBLE',
        'metricKind': 'DISTRIBUTION',
        'name': meter_name_to_descriptor_name('test_system/test_summary'),
        'type': meter_name_to_descriptor_type('test_system/test_summary'),
        'description': 'Summary documentation.',
        'labels': [
            {'key': 'spin_service'},
            {'key': 'spin_variant'}
        ]
    }
    result[summary['name']] = summary

    unused = {
        'valueType': 'DOUBLE',
        'metricKind': 'CUMULATIVE',
        'name': meter_name_to_descriptor_name('test_system/extra'),
        'type': meter_name_to_descriptor_type('test_system/extra'),
        'description': 'Unused Descriptor.',
        'labels': [
            {'key': 'spin_service'},
            {'key': 'spin_variant'}
        ]
    }
    result[unused['name']] = unused

    return result

  def get_descriptor_subset(self, from_map, names):
    result = {}
    for name in names:
      key = meter_name_to_descriptor_name(name)
      result[key] = from_map[key]
    return result

  def prepare_audit_scenario(self):
    expected_descriptors = self.__write_transforms('default.yml')

    # Setup eagerly loads transforms, but we didnt create them 'til now
    # so redo the setup.
    self.__do_setup()

    gauge_name = meter_name_to_descriptor_name('test_system/test_gauge')
    old_gauge = dict(expected_descriptors[gauge_name])
    expect_same = {gauge_name: dict(expected_descriptors[gauge_name])}

    summary_name = meter_name_to_descriptor_name('test_system/test_summary')
    summary = expected_descriptors[summary_name]
    timer_name = meter_name_to_descriptor_name('test_system/test_timer')
    timer_count = expected_descriptors[timer_name + '__count']
    timer_total = expected_descriptors[timer_name + '__totalTime']
    expect_new = {
        summary['name']: summary,
        timer_count['name']: timer_count,
        timer_total['name']: timer_total
    }

    counter_name = meter_name_to_descriptor_name('test_system/test_counter')
    old_counter = dict(expected_descriptors[counter_name])
    del(old_counter['description'])
    expect_changed = {counter_name: dict(expected_descriptors[counter_name])}

    unused_name = meter_name_to_descriptor_name('test_system/extra')
    unused = dict(expected_descriptors[unused_name])
    expect_unused = {unused['type']: unused}

    self.mockListDescriptors.execute.return_value = {
        'metricDescriptors': [old_gauge, old_counter, unused]
    }

    return (expect_same, expect_new, expect_changed, expect_unused)

  def test_audit_readonly(self):
    expect_same, expect_new, expect_changed, expect_unused = (
        self.prepare_audit_scenario()
    )

    manager = self.service.descriptor_manager
    options = google_service.normalize_options({})
    audit = manager.audit_descriptors(options)

    self.assertEquals(expect_new.keys(), audit.new_descriptors.keys())
    self.assertEquals(expect_new, audit.new_descriptors)
    self.assertEquals(expect_changed.keys(), audit.changed_descriptors.keys())
    self.assertEquals(expect_changed, audit.changed_descriptors)
    self.assertEquals(expect_unused.keys(), audit.unused_descriptors.keys())
    self.assertEquals(expect_unused, audit.unused_descriptors)

    self.assertEquals(0, audit.num_fixed_issues)
    self.assertEquals(
        set(expect_same.keys()), audit.unchanged_descriptor_names)
    self.assertEquals(3, audit.missing_count)
    self.assertEquals(0, audit.created_count)
    self.assertEquals(1, audit.outdated_count)
    self.assertEquals(0, audit.updated_count)
    self.assertEquals(1, audit.obsoleted_count)
    self.assertEquals(0, audit.deleted_count)
    self.assertEquals(5, audit.num_unresolved_issues)
    self.assertEquals(5, audit.warnings)
    self.assertEquals(0, audit.errors)

    self.assertEquals(0, self.mockStub.projects.list.call_count)
    self.assertEquals(1, self.mockMetricDescriptors.list.call_count)
    self.assertEquals(0, self.mockMetricDescriptors.get.call_count)
    self.assertEquals(0, self.mockMetricDescriptors.delete.call_count)
    self.assertEquals(0, self.mockMetricDescriptors.create.call_count)

  def test_audit_create_only(self):
    expect_same, expect_new, expect_changed, expect_unused = (
        self.prepare_audit_scenario()
    )

    manager = self.service.descriptor_manager
    options = google_service.normalize_options(
        {'manage_stackdriver_descriptors': 'create'}
    )
    audit = manager.audit_descriptors(options)

    self.mockCreateDescriptor.execute.return_value = [
    ]

    # This delete is part of an update
    self.mockDeleteDescriptor.execute.return_value = [
    ]

    self.assertEquals(expect_new.keys(), audit.new_descriptors.keys())
    self.assertEquals(expect_new, audit.new_descriptors)
    self.assertEquals(expect_changed.keys(), audit.changed_descriptors.keys())
    self.assertEquals(expect_changed, audit.changed_descriptors)
    self.assertEquals(expect_unused.keys(), audit.unused_descriptors.keys())
    self.assertEquals(expect_unused, audit.unused_descriptors)

    self.assertEquals(4, audit.num_fixed_issues)
    self.assertEquals(
        set(expect_same.keys()), audit.unchanged_descriptor_names)
    self.assertEquals(0, audit.missing_count)
    self.assertEquals(3, audit.created_count)
    self.assertEquals(0, audit.outdated_count)
    self.assertEquals(1, audit.updated_count)
    self.assertEquals(1, audit.obsoleted_count)
    self.assertEquals(0, audit.deleted_count)
    self.assertEquals(1, audit.num_unresolved_issues)
    self.assertEquals(1, audit.warnings)
    self.assertEquals(0, audit.errors)

    self.assertEquals(0, self.mockStub.projects.list.call_count)
    self.assertEquals(1, self.mockMetricDescriptors.list.call_count)
    self.assertEquals(0, self.mockMetricDescriptors.get.call_count)
    self.assertEquals(1, self.mockMetricDescriptors.delete.call_count)
    self.assertEquals(4, self.mockMetricDescriptors.create.call_count)

  def test_audit_update_failure(self):
    expect_same, expect_new, expect_changed, expect_unused = (
        self.prepare_audit_scenario()
    )
    # This delete is part of an update
    self.mockMetricDescriptors.delete.side_effect = HttpError(
        ResponseStatus(400, 'Injected Error'), 'Injected Error')
    self.mockCreateDescriptor.execute.return_value = []

    manager = self.service.descriptor_manager
    options = google_service.normalize_options(
        {'manage_stackdriver_descriptors': 'create'}
    )
    audit = manager.audit_descriptors(options)

    self.assertEquals(expect_new.keys(), audit.new_descriptors.keys())
    self.assertEquals(expect_new, audit.new_descriptors)
    self.assertEquals(expect_changed.keys(), audit.changed_descriptors.keys())
    self.assertEquals(expect_changed, audit.changed_descriptors)
    self.assertEquals(expect_unused.keys(), audit.unused_descriptors.keys())
    self.assertEquals(expect_unused, audit.unused_descriptors)

    self.assertEquals(3, audit.num_fixed_issues)
    self.assertEquals(
        set(expect_same.keys()), audit.unchanged_descriptor_names)
    self.assertEquals(0, audit.missing_count)
    self.assertEquals(3, audit.created_count)
    self.assertEquals(1, audit.outdated_count)
    self.assertEquals(0, audit.updated_count)
    self.assertEquals(1, audit.obsoleted_count)
    self.assertEquals(0, audit.deleted_count)
    self.assertEquals(2, audit.num_unresolved_issues) # update and delete
    self.assertEquals(1, audit.warnings) # delete
    self.assertEquals(1, audit.errors)   # update

    self.assertEquals(0, self.mockStub.projects.list.call_count)
    self.assertEquals(1, self.mockMetricDescriptors.list.call_count)
    self.assertEquals(0, self.mockMetricDescriptors.get.call_count)
    self.assertEquals(1, self.mockMetricDescriptors.delete.call_count)
    self.assertEquals(3, self.mockMetricDescriptors.create.call_count)

  def test_audit_create_failure(self):
    expect_same, expect_new, expect_changed, expect_unused = (
        self.prepare_audit_scenario()
    )

    # This delete is part of an update
    self.mockMetricDescriptors.create.side_effect = HttpError(
        ResponseStatus(400, 'Injected Error'), 'Injected Error')
    self.mockDeleteDescriptor.execute.return_value = {}

    manager = self.service.descriptor_manager
    options = google_service.normalize_options(
        {'manage_stackdriver_descriptors': 'create'}
    )
    audit = manager.audit_descriptors(options)
    self.assertEquals(expect_new.keys(), audit.new_descriptors.keys())
    self.assertEquals(expect_new, audit.new_descriptors)
    self.assertEquals(expect_changed.keys(), audit.changed_descriptors.keys())
    self.assertEquals(expect_changed, audit.changed_descriptors)
    self.assertEquals(expect_unused.keys(), audit.unused_descriptors.keys())
    self.assertEquals(expect_unused, audit.unused_descriptors)

    self.assertEquals(0, audit.num_fixed_issues)
    self.assertEquals(
        set(expect_same.keys()), audit.unchanged_descriptor_names)
    self.assertEquals(3, audit.missing_count)
    self.assertEquals(0, audit.created_count)
    self.assertEquals(1, audit.outdated_count)
    self.assertEquals(0, audit.updated_count)
    self.assertEquals(1, audit.obsoleted_count)
    self.assertEquals(0, audit.deleted_count)
    self.assertEquals(5, audit.num_unresolved_issues)
    self.assertEquals(1, audit.warnings) # delete
    self.assertEquals(4, audit.errors)

    self.assertEquals(0, self.mockStub.projects.list.call_count)
    self.assertEquals(1, self.mockMetricDescriptors.list.call_count)
    self.assertEquals(0, self.mockMetricDescriptors.get.call_count)
    self.assertEquals(1, self.mockMetricDescriptors.delete.call_count)
    self.assertEquals(4, self.mockMetricDescriptors.create.call_count)


if __name__ == '__main__':
  unittest.main()
