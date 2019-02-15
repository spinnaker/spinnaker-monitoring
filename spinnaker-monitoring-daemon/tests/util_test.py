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
import os
import shutil
import unittest
from tempfile import mkdtemp

import util


class UtilTest(unittest.TestCase):
  def test_load_without_override(self):
    temp_dir = mkdtemp()
    try:
      with open(os.path.join(temp_dir, 'spinnaker-monitoring.yml'), 'w') as stream:
        stream.write("""
            root:
              num: 1
              string: STRING
              dict:
                one: 1
                changed: false
        """)
      got = util.merge_options_and_yaml_from_dirs({}, [temp_dir])
    finally:
      shutil.rmtree(temp_dir)

    expect = {
        'root': {
            'num': 1,
            'string': 'STRING',
            'dict': {
                'one': 1,
                'changed': False
            }
        }
    }
    self.assertEquals(expect, got)

  def test_load_with_override(self):
    temp_dir = mkdtemp()
    try:
      with open(os.path.join(temp_dir, 'spinnaker-monitoring.yml'), 'w') as stream:
        stream.write("""
            root:
              num: 1
              string: STRING
              dict:
                one: 1
                changed: false
        """)
      with open(os.path.join(temp_dir, 'spinnaker-monitoring-local.yml'), 'w') as stream:
        stream.write("""
            extra: EXTRA
            root:
              string: CHANGED
              dict:
                changed: true
                more: MORE
        """)
      got = util.merge_options_and_yaml_from_dirs({}, [temp_dir])
    finally:
      shutil.rmtree(temp_dir)

    expect = {
        'extra': 'EXTRA',
        'root': {
            'num': 1,
            'string': 'CHANGED',
            'dict': {
                'one': 1,
                'changed': True,
                'more': 'MORE'
            }
        }
    }
    self.assertEquals(expect, got)


if __name__ == '__main__':
  unittest.main()

