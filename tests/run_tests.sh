#!/bin/bash
#
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

# USAGE:
#
# To run these tests, it is assumed that you have the python dependencies
# installed in your environment. From the root spinnaker-monitoring directory:
# 
#    pip install -r requirements.txt
#

# Add the spinnaker-monitoring sources we are testing to the PYTHONPATH
export PYTHONPATH=$PYTHONPATH:"$(dirname $0)/../spinnaker-monitoring"


declare -a PASSED
declare -a FAILED

for test in "$(dirname $0)"/*_test.py; do
  echo "Running $test"
  if python "$test"; then
      PASSED=("${PASSED[@]}" "$test")
  else
      FAILED=("${FAILED[@]}" "$test")
  fi
done

echo ""
echo "FINAL SUMMARY:"
echo "--------------"
for elem in ${PASSED[@]}; do
    echo "  PASSED: $elem"
done

if [[ -z $FAILED ]]; then
  echo ""
  echo "PASSED all ${#PASSED[@]} tests"
  exit 0
else
  echo ""
  for elem in ${FAILED[@]}; do
    echo "  FAILED: $elem"
  done
  echo ""
  echo "FAILED ${#FAILED[@]} tests"
  exit 1
fi

