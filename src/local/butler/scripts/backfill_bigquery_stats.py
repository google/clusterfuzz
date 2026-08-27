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
"""Sequential BigQuery stats backfill runner."""

import argparse
import datetime
import os
import tempfile
import time

from clusterfuzz._internal.cron import load_bigquery_stats
from clusterfuzz._internal.metrics import logs


def load_dates_from_file(filepath: str) -> list[str]:
  """Reads and validates YYYY-MM-DD dates from a text file."""
  if not os.path.exists(filepath):
    raise FileNotFoundError(f'Dates file not found: {filepath}')

  dates = []
  seen = set()
  with open(filepath, 'r') as f:
    for line_num, line in enumerate(f, start=1):
      line = line.strip()
      if not line or line.startswith('#') or line.lower() == 'missing_date':
        continue

      try:
        parsed_date = datetime.datetime.strptime(line, '%Y-%m-%d').date()
        date_str = parsed_date.strftime('%Y-%m-%d')
        if date_str not in seen:
          seen.add(date_str)
          dates.append(date_str)
        else:
          logs.warning(f'Line {line_num}: Duplicate date {date_str} skipped.')
      except ValueError:
        logs.warning(
            f'Line {line_num}: Skipping invalid date format "{line}". '
            'Expected YYYY-MM-DD.')

  return dates


def update_dates_file(filepath: str, remaining_dates: list[str]) -> None:
  """Atomically updates the input file with remaining unprocessed dates."""
  target_dir = os.path.dirname(os.path.abspath(filepath)) or '.'
  with tempfile.NamedTemporaryFile('w', dir=target_dir, delete=False) as temp_f:
    for date_str in remaining_dates:
      temp_f.write(f'{date_str}\n')
    temp_filename = temp_f.name

  os.replace(temp_filename, filepath)


def write_failed_dates(failed_dates: list[str],
                       output_path: str = 'failed_dates.txt') -> None:
  """Writes failed dates to a file for straightforward re-execution."""
  if not failed_dates:
    return

  with open(output_path, 'w') as f:
    for date_str in failed_dates:
      f.write(f'{date_str}\n')

  logs.info(
      f'Wrote {len(failed_dates)} failed date(s) to "{output_path}" for retry.')


def run_backfill(
    dates: list[str],
    dates_file: str,
    log_file: str = 'backfill_execution.log') -> tuple[list[str], list[str]]:
  """Sequentially executes load_bigquery_stats for each date in the list."""
  total_dates = len(dates)
  logs.info(f'Starting sequential backfill for {total_dates} date(s).')

  successful_dates = []
  failed_dates = []
  total_start_time = time.time()

  try:
    with open(log_file, 'a') as log_out:
      log_out.write(
          f'\n--- Backfill Session Started: {datetime.datetime.utcnow().isoformat()}Z ---\n'
      )
      log_out.write(f'Target Dates ({total_dates}): {", ".join(dates)}\n\n')
      log_out.flush()

      for index, date_str in enumerate(dates, start=1):
        logs.info(
            f'[{index}/{total_dates}] >>> Starting ingestion for {date_str}...')
        date_start_time = time.time()

        try:
          success = load_bigquery_stats.main(['--date', date_str])
          elapsed_mins = (time.time() - date_start_time) / 60.0

          if success:
            msg = f'[{index}/{total_dates}] SUCCESS for {date_str} (Duration: {elapsed_mins:.1f}m)'
            logs.info(msg)
            successful_dates.append(date_str)
          else:
            msg = f'[{index}/{total_dates}] FAILED for {date_str} (Duration: {elapsed_mins:.1f}m)'
            logs.error(msg)
            failed_dates.append(date_str)

        except Exception as e:
          elapsed_mins = (time.time() - date_start_time) / 60.0
          msg = f'[{index}/{total_dates}] EXCEPTION for {date_str} (Duration: {elapsed_mins:.1f}m): {e}'
          logs.error(msg)
          failed_dates.append(date_str)

        log_out.write(f'{msg}\n')
        log_out.flush()

        # Update input queue file removing the completed date.
        remaining_dates = dates[index:]
        update_dates_file(dates_file, remaining_dates)

      total_duration_hrs = (time.time() - total_start_time) / 3600.0
      summary = (
          '\n============================================================\n'
          '               BACKFILL EXECUTION SUMMARY\n'
          '============================================================\n'
          f'Total Dates Processed : {total_dates}\n'
          f'Total Execution Time  : {total_duration_hrs:.2f} hours\n'
          f'Successful Dates ({len(successful_dates)}) : {successful_dates}\n'
          f'Failed Dates     ({len(failed_dates)}) : {failed_dates}\n'
          '============================================================\n')
      logs.info(summary)
      log_out.write(summary)
      log_out.flush()

  except KeyboardInterrupt:
    logs.warning(
        '\nBackfill interrupted by user! '
        f'Unprocessed dates remain in "{dates_file}". Resume anytime with:\n'
        f'  python butler.py run backfill_bigquery_stats --script_args --dates-file {dates_file}'
    )

  write_failed_dates(failed_dates)
  return successful_dates, failed_dates


def execute(args):
  """Butler script entry point."""
  parser = argparse.ArgumentParser(
      description='Sequential BigQuery Stats Backfill Tool')
  parser.add_argument(
      '--dates-file',
      required=True,
      help='Path to text/CSV file containing YYYY-MM-DD dates (one per line).')
  parser.add_argument(
      '--log-file',
      default='backfill_execution.log',
      help='Path to execution log file.')

  parsed_args = parser.parse_args(args.script_args or [])
  dates = load_dates_from_file(parsed_args.dates_file)
  if not dates:
    logs.error(f'No valid dates found in file: {parsed_args.dates_file}')
    return

  run_backfill(
      dates, dates_file=parsed_args.dates_file, log_file=parsed_args.log_file)
