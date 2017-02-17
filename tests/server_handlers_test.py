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
from server_handlers import MonitorCommandHandler


class FakeFactory(object):
  def __init__(self, name):
    self.__name = name
    self.called_enabled = 0
    self.called_create = 0
    self.instance = mock.Mock()
    self.handler = mock.Mock()

  def enabled(self, options):
    self.called_enabled += 1
    return options.get(self.__name, False)

  def __call__(self, options, handler_list):
    self.called_create += 1
    handler_list.append(self.handler)
    return self.instance


class ServerHandlersTest(unittest.TestCase):
  def test_monitor(self):
    all_handlers = []
    monitor_handler = MonitorCommandHandler(
        all_handlers, '/web/path', 'command_name', 'HELP')
    factory_a = FakeFactory('serviceA')
    factory_b = FakeFactory('serviceB')
    factory_c = FakeFactory('serviceC')
    MonitorCommandHandler.register_metric_service_factory(factory_a)
    MonitorCommandHandler.register_metric_service_factory(factory_b)
    MonitorCommandHandler.register_metric_service_factory(factory_c)
    list = monitor_handler.make_metric_services({'serviceA': True, 'serviceC': True})
    self.assertEquals(1, factory_a.called_enabled)
    self.assertEquals(1, factory_a.called_create)
    self.assertEquals(1, factory_b.called_enabled)
    self.assertEquals(0, factory_b.called_create)
    self.assertEquals(1, factory_c.called_enabled)
    self.assertEquals(1, factory_c.called_create)
    self.assertEquals([factory_a.instance, factory_c.instance], list)
    self.assertEquals([factory_a.handler, factory_c.handler], all_handlers)


if __name__ == '__main__':
  # pylint: disable=invalid-name
  loader = unittest.TestLoader()
  suite = loader.loadTestsFromTestCase(ServerHandlersTest)
  unittest.TextTestRunner(verbosity=2).run(suite)

