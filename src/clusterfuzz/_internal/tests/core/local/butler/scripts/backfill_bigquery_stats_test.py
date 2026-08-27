# Copyright 2026 Google LLC
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
"""Tests for backfill_bigquery_stats."""

import argparse
import os
import shutil
import tempfile
import unittest
from unittest import mock

from local.butler.scripts import backfill_bigquery_stats


class BackfillBigQueryStatsTest(unittest.TestCase):
  """Tests for backfill_bigquery_stats functions."""

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp()
    self.dates_file = os.path.join(self.temp_dir, 'dates.txt')
    self.log_file = os.path.join(self.temp_dir, 'backfill_execution.log')
    self.failed_dates_file = os.path.join(self.temp_dir, 'failed_dates.txt')

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_load_dates_from_file_valid(self):
    """Tests loading valid dates, skipping headers, comments, and empty lines."""
    content = (
        'missing_date\n'
        '# Comment line\n'
        '\n'
        '2025-03-20\n'
        '2025-03-21\n'
        '   \n'
        '2025-03-22\n')
    with open(self.dates_file, 'w') as f:
      f.write(content)

    dates = backfill_bigquery_stats.load_dates_from_file(self.dates_file)
    self.assertEqual(dates, ['2025-03-20', '2025-03-21', '2025-03-22'])

  def test_load_dates_from_file_duplicates_and_invalid(self):
    """Tests skipping duplicate and invalid dates."""
    content = (
        '2025-03-20\n'
        '2025-03-20\n'
        'invalid-date\n'
        '2025-13-45\n'
        '2025-03-21\n')
    with open(self.dates_file, 'w') as f:
      f.write(content)

    dates = backfill_bigquery_stats.load_dates_from_file(self.dates_file)
    self.assertEqual(dates, ['2025-03-20', '2025-03-21'])

  def test_load_dates_from_file_not_found(self):
    """Tests FileNotFoundError when file does not exist."""
    with self.assertRaises(FileNotFoundError):
      backfill_bigquery_stats.load_dates_from_file('/nonexistent/path/dates.txt')

  def test_update_dates_file(self):
    """Tests atomic rewrite of input dates file."""
    with open(self.dates_file, 'w') as f:
      f.write('2025-03-20\n2025-03-21\n')

    backfill_bigquery_stats.update_dates_file(self.dates_file, ['2025-03-21'])

    with open(self.dates_file, 'r') as f:
      content = f.read().splitlines()

    self.assertEqual(content, ['2025-03-21'])

  def test_write_failed_dates(self):
    """Tests writing failed dates to file."""
    backfill_bigquery_stats.write_failed_dates(
        ['2025-03-21', '2025-03-22'], output_path=self.failed_dates_file)

    self.assertTrue(os.path.exists(self.failed_dates_file))
    with open(self.failed_dates_file, 'r') as f:
      lines = f.read().splitlines()

    self.assertEqual(lines, ['2025-03-21', '2025-03-22'])

  @mock.patch('clusterfuzz._internal.cron.load_bigquery_stats.main')
  def test_run_backfill_all_success(self, mock_load_main):
    """Tests backfill execution when all dates succeed."""
    mock_load_main.return_value = True

    with open(self.dates_file, 'w') as f:
      f.write('2025-03-20\n2025-03-21\n')

    successful, failed = backfill_bigquery_stats.run_backfill(
        ['2025-03-20', '2025-03-21'],
        dates_file=self.dates_file,
        log_file=self.log_file)

    self.assertEqual(successful, ['2025-03-20', '2025-03-21'])
    self.assertEqual(failed, [])
    self.assertEqual(mock_load_main.call_count, 2)
    mock_load_main.assert_has_calls([
        mock.call(['--date', '2025-03-20']),
        mock.call(['--date', '2025-03-21']),
    ])

    # File should be empty on completion.
    with open(self.dates_file, 'r') as f:
      self.assertEqual(f.read().strip(), '')

  @mock.patch('clusterfuzz._internal.cron.load_bigquery_stats.main')
  def test_run_backfill_with_failure(self, mock_load_main):
    """Tests backfill execution when one date fails."""
    mock_load_main.side_effect = [True, False]

    with open(self.dates_file, 'w') as f:
      f.write('2025-03-20\n2025-03-21\n')

    with mock.patch('local.butler.scripts.backfill_bigquery_stats.write_failed_dates') as mock_write_failed:
      successful, failed = backfill_bigquery_stats.run_backfill(
          ['2025-03-20', '2025-03-21'],
          dates_file=self.dates_file,
          log_file=self.log_file)

      self.assertEqual(successful, ['2025-03-20'])
      self.assertEqual(failed, ['2025-03-21'])
      mock_write_failed.assert_called_once_with(['2025-03-21'])

  @mock.patch('clusterfuzz._internal.cron.load_bigquery_stats.main')
  def test_run_backfill_with_exception(self, mock_load_main):
    """Tests backfill execution isolating exceptions and continuing."""
    mock_load_main.side_effect = [RuntimeError('Network failure'), True]

    with open(self.dates_file, 'w') as f:
      f.write('2025-03-20\n2025-03-21\n')

    successful, failed = backfill_bigquery_stats.run_backfill(
        ['2025-03-20', '2025-03-21'],
        dates_file=self.dates_file,
        log_file=self.log_file)

    self.assertEqual(successful, ['2025-03-21'])
    self.assertEqual(failed, ['2025-03-20'])
    self.assertEqual(mock_load_main.call_count, 2)

  @mock.patch('clusterfuzz._internal.cron.load_bigquery_stats.main')
  def test_run_backfill_keyboard_interrupt(self, mock_load_main):
    """Tests backfill handling KeyboardInterrupt gracefully."""
    mock_load_main.side_effect = KeyboardInterrupt

    with open(self.dates_file, 'w') as f:
      f.write('2025-03-20\n2025-03-21\n')

    successful, failed = backfill_bigquery_stats.run_backfill(
        ['2025-03-20', '2025-03-21'],
        dates_file=self.dates_file,
        log_file=self.log_file)

    self.assertEqual(successful, [])
    self.assertEqual(failed, [])

  @mock.patch('local.butler.scripts.backfill_bigquery_stats.run_backfill')
  def test_execute(self, mock_run_backfill):
    """Tests execute entry point from Butler."""
    with open(self.dates_file, 'w') as f:
      f.write('2025-03-20\n')

    args = argparse.Namespace(
        script_args=['--dates-file', self.dates_file, '--log-file', self.log_file])
    backfill_bigquery_stats.execute(args)

    mock_run_backfill.assert_called_once_with(
        ['2025-03-20'], dates_file=self.dates_file, log_file=self.log_file)
