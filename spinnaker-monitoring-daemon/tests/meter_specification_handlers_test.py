# Copyright 2018 Google Inc. All Rights Reserved.
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

import copy
import unittest

from meter_specification_handler import (
    compute_meter_diff,
    union_keys)


TEST_COUNTER = {
  'kind': 'Counter',
  'name': 'test.counter',
  'tags': ['first', 'second', 'third']
}
 
TEST_COUNTER_COMPLEX = {
  'kind': 'Counter',
  'name': 'test.counter',
  'tags': {
    'first': {'summary': 'First Summary'},
    'second': {'summary': 'Second Summary'},
    'third': {'summary': 'Third Summary'}
  }
}
 
TEST_GAUGE = {
  'kind': 'Gauge',
  'name': 'test.gauge',
  'tags': ['first', 'second', 'third']
}

class FreeFunctionTest(unittest.TestCase):
  def test_meter_diff_ok(self):
    self.assertEquals(
        [], compute_meter_diff(TEST_COUNTER, TEST_COUNTER))
    self.assertEquals(
        [], compute_meter_diff(TEST_COUNTER_COMPLEX, TEST_COUNTER_COMPLEX))

  def test_meter_diff_different(self):
    test = dict(TEST_COUNTER)
    test['kind'] = 'Gauge'
    self.assertEquals(["Modified kind='Gauge'"],
                      compute_meter_diff(TEST_COUNTER, test))

    test = dict(TEST_COUNTER)
    test['name'] = 'test.gauge'
    self.assertEquals(["Modified name='test.gauge'"],
                      compute_meter_diff(TEST_COUNTER, test))

    test = dict(TEST_COUNTER)
    test['viewpoints'] = ['a', 'b']
    self.assertEquals(["Added viewpoints=['a', 'b']"],
                      compute_meter_diff(TEST_COUNTER, test))

    test = dict(TEST_COUNTER)
    del test['kind']
    self.assertEquals(["Removed kind"],
                      compute_meter_diff(TEST_COUNTER, test))

    test = dict(TEST_COUNTER)
    test['tags'] = list(test['tags'])
    test['tags'].append('extra')
    self.assertEquals(["Added set(['extra']) to tags"],
                      compute_meter_diff(TEST_COUNTER, test))

    test['tags'] = test['tags'][:-2]
    self.assertEquals(["Removed set(['third']) from tags"],
                      compute_meter_diff(TEST_COUNTER, test))

    test = dict(TEST_COUNTER_COMPLEX)
    test['tags'] = dict(test['tags'])
    test['tags']['extra'] = 'EXTRA'

    expect = ["Added tags.extra='EXTRA'"]
    self.assertEquals(expect,
                      compute_meter_diff(TEST_COUNTER_COMPLEX, test))

    expect = ['Changed type of "tags" from list to dict with value=%r' % (
        TEST_COUNTER_COMPLEX['tags'])]
    self.assertEquals(expect,
                      compute_meter_diff(TEST_COUNTER, TEST_COUNTER_COMPLEX))

  def test_meter_diff_complex(self):
    expect = [
        "Modified kind='Gauge'",
        "Modified name='test.gauge'",
        'Changed type of "tags" from dict to list with value=%r' % (
            TEST_GAUGE['tags'])
    ]
    self.assertEquals(expect,
                      compute_meter_diff(TEST_COUNTER_COMPLEX, TEST_GAUGE))

  def union_keys(self):
    self.assertEquals(set(['a', 'b', 'c']),
                      union_keys({'a': 1, 'b': 2}, {'c': 1}))

    self.assertEquals(set(['a', 'b', 'c']),
                      union_keys({'a': 1}, {'b': 2}, {'c': 1}))

    self.assertEquals(set(['a', 'b', 'c']),
                      union_keys({'a': 1, 'b': 2, 'c': 1}, {}))
    
    self.assertEquals(set(['a', 'b', 'c']),
                      union_keys({'a': 1, 'b': 2, 'c': 1}, None))
    

if __name__ == '__main__':
  unittest.main()
