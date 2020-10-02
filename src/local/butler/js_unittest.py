# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""js_unittest.py runs JS tests under src/appengine"""

import os
import re
import sys
import time

from selenium import webdriver

from local.butler import common

_SUITE_SEPARATOR = '=' * 80
_TEST_SEPARATOR = '-' * 80


def _parse_error_report(driver):
  """Parse failed test report from Mocha HTML result"""
  error_report = ''

  # Remove the replay buttons next to test names
  for elem in driver.find_elements_by_css_selector('#mocha-report .suite h2 a'):
    driver.execute_script('arguments[0].remove()', elem)

  suites = driver.find_elements_by_css_selector('#mocha-report .suite .suite')
  for suite in suites:
    failed_tests = suite.find_elements_by_css_selector('.test.fail')
    if not failed_tests:
      continue

    suite_name = suite.find_element_by_css_selector('h1').text.strip()

    error_report += '\n\n%s\n' % _SUITE_SEPARATOR
    error_report += '%s\n' % suite_name

    for failed_test in failed_tests:
      name = failed_test.find_element_by_css_selector('h2').text.strip()
      trace = failed_test.find_element_by_css_selector('.error').text.strip()
      trace = re.sub('^', '| ', trace)
      trace = re.sub('\n', '\n| ', trace)

      error_report += '%s\n' % _TEST_SEPARATOR
      error_report += 'Failed test: %s\n' % name
      error_report += '%s\n' % trace

  return error_report


def execute(args):
  """Run Javascript unit tests. Here are the steps:

     1. Execute the HTML with chromedriver.
     2. Read the test result from the HTML."""
  test_filepath = os.path.join('src', 'appengine', 'private', 'test.html')
  print('Running chromedriver on %s' % test_filepath)

  chrome_options = webdriver.ChromeOptions()
  chrome_options.add_argument('--allow-file-access-from-files')

  is_ci = os.getenv('TEST_BOT_ENVIRONMENT')
  if is_ci:
    # Turn off sandbox since running under root, with trusted tests.
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--headless')

  driver = webdriver.Chrome(
      executable_path=common.get_chromedriver_path(),
      chrome_options=chrome_options)

  try:
    driver.get('file://%s' % os.path.abspath(test_filepath))

    # Wait for tests to be completed.
    while True:
      success_count = driver.execute_script(
          'return WCT._reporter.stats.passes;')
      failure_count = driver.execute_script(
          'return WCT._reporter.stats.failures;')
      sys.stdout.write(
          '\rSuccess: %d, Failure: %d' % (success_count, failure_count))
      sys.stdout.flush()

      is_complete = driver.execute_script('return WCT._reporter.complete;')
      if is_complete:
        break

      time.sleep(0.1)

    sys.stdout.write('\r' + (' ' * 70))
    sys.stdout.flush()

    success_count = int(
        driver.find_element_by_css_selector('#mocha-stats .passes em').text)
    failure_count = int(
        driver.find_element_by_css_selector('#mocha-stats .failures em').text)
    error_report = _parse_error_report(driver)

    if error_report:
      print(error_report)

    print()
    print(_SUITE_SEPARATOR)
    print('Test results:')
    print('| Success: %d' % success_count)
    print('| Failure: %d' % failure_count)
    print(_SUITE_SEPARATOR)
    print()

    if args.persist:
      # pylint: disable=eval-used
      eval(
          input('--persist is used. Leave the browser open.'
                ' Press ENTER to close it:'))
  finally:
    driver.quit()

  if failure_count > 0:
    sys.exit(1)
