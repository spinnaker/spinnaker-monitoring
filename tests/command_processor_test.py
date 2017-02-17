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

import mock
import unittest

import command_processor


class CommandProcessorTest(unittest.TestCase):
  def test_process_command(self):
    mock_a = mock.Mock()
    mock_a.command_name = 'CommandA'
    mock_a.process_commandline_request = mock.Mock()
    mock_b = mock.Mock()
    mock_b.command_name = 'CommandB'
    mock_b.process_commandline_request = mock.Mock()
    registry = [mock_a, mock_b]
    options = {}

    command_processor.process_command('CommandB', options, registry)
    self.assertEquals(0, mock_a.process_commandline_request.call_count)
    self.assertEquals(1, mock_b.process_commandline_request.call_count)
    mock_b.process_commandline_request.assert_called_with(options)

  def test_process_command_not_found(self):
    mock_a = mock.Mock()
    mock_a.command_name = 'CommandA'
    with self.assertRaises(ValueError):
        command_processor.process_command('CommandB', {}, [mock_a])

  def accepts_content_type(self):
    request = mock.Mock()
    request.headers = {'accept': 'text/html'}
    self.assertTrue(CommandHandler.accepts_content_type(request, 'text/html'))

    request.headers = {'accept': 'text/plain,text/html'}
    self.assertTrue(CommandHandler.accepts_content_type(request, 'text/html'))

  def does_not_implicitly_accept_content_type(self):
    request = mock.Mock()
    self.assertFalse(CommandHandler.accepts_content_type(request, 'text/html'))

  def does_not_accept_content_type(self):
    request = mock.Mock()
    request.headers = {'accept': 'text/plain'}
    self.assertFalse(CommandHandler.accepts_content_type(request, 'text/html'))


if __name__ == '__main__':
  # pylint: disable=invalid-name
  loader = unittest.TestLoader()
  suite = loader.loadTestsFromTestCase(CommandProcessorTest)
  unittest.TextTestRunner(verbosity=2).run(suite)

