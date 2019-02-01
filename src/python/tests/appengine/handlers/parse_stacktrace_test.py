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
"""parse_stacktrace tests."""
import unittest
import webapp2
import webtest

from crash_analysis.stack_parsing import stack_analyzer
from datastore import data_types
from handlers import parse_stacktrace
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'crash_analysis.stack_parsing.stack_analyzer.get_crash_data',
    ])

    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', parse_stacktrace.Handler)]))

  def test_succeed(self):
    """Test invoking parse()."""
    dummy_state = stack_analyzer.StackAnalyzerState()
    dummy_state.crash_type = 'type'
    dummy_state.crash_address = 'address'
    dummy_state.crash_state = 'state'
    dummy_state.crash_stacktrace = 'orig_trace'
    self.mock.get_crash_data.return_value = dummy_state
    resp = self.app.post_json('/', {'stacktrace': 'test', 'job': 'job_type'})

    self.assertEqual(200, resp.status_int)
    self.assertEqual('type', resp.json['crash_type'])
    self.assertEqual('address', resp.json['crash_address'])
    self.assertEqual('state', resp.json['crash_state'])
    self.mock.get_crash_data.assert_called_once_with(
        'test', symbolize_flag=False)


@test_utils.with_cloud_emulators('datastore')
class ParseTest(unittest.TestCase):
  """Test parse."""

  def setUp(self):
    job = data_types.Job()
    job.name = 'test_job'
    job.environment_string = 'REPORT_OOMS_AND_HANGS = True'
    job.put()

  def test_parse(self):
    """Test parsing a stacktrace."""
    s = """
[0608/134419:WARNING:diagnostics_writer.cc(208)] [FAIL] 014 PathUserData (Cannot obtain size for: /mnt/scratch0/tmp/user_profile_0)
[0608/134419:WARNING:diagnostics_writer.cc(208)] [FAIL] 013 PathLocalState (Path not found: /mnt/scratch0/tmp/user_profile_0/Local State)
[0608/134419:WARNING:diagnostics_writer.cc(208)] [FAIL] 019 JSONPreferences (File not found)
[0608/134419:WARNING:diagnostics_writer.cc(208)] [FAIL] 019 JSONLocalState (File not found)
[0608/134419:WARNING:diagnostics_writer.cc(208)] [FAIL] 002 SQLiteIntegrityWebData (File not found)
[0608/134419:WARNING:diagnostics_writer.cc(208)] [FAIL] 002 SQLiteIntegrityCookie (File not found)
[0608/134419:WARNING:diagnostics_writer.cc(208)] [FAIL] 002 SQLiteIntegrityHistory (File not found)
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished 17 tests.
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Install type
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Chrome version test
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: User data path
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Local state path
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: App dictionaries directory path
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Resources path
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Available disk space
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: User preferences integrity
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Local state integrity
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Bookmark file
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Web Data database
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Cookie database
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: History database
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Thumbnails database
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: Database tracker database
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: NSS certificate database
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished Recovery for: NSS Key database
[0608/134419:WARNING:diagnostics_writer.cc(208)] Finished All Recovery operations.
==1==WARNING: no internal or external symbolizer found.
Xlib:  extension "RANDR" missing on display ":1".
[21462:21462:0608/134421:ERROR:sandbox_linux.cc(338)] InitializeSandbox() called with multiple threads in process gpu-process
[21429:21429:0608/134422:ERROR:wallpaper_manager.cc(646)] User is ephemeral or guest! Fallback to default wallpaper.
[21429:21429:0608/134422:FATAL:profile_helper.cc(148)] Check failed: !user_id_hash.empty().
#0 0x7fbb66e69351 __interceptor_backtrace
#1 0x7fbb6863f280 base::debug::StackTrace::StackTrace()
#2 0x7fbb686acde9 logging::LogMessage::~LogMessage()
#3 0x7fbb7b5d792f chromeos::ProfileHelper::GetUserProfileDir()
#4 0x7fbb7b5d7726 chromeos::ProfileHelper::GetProfilePathByUserIdHash()
#5 0x7fbb7b25fd13 chromeos::UserSessionManager::OverrideHomedir()
#6 0x7fbb7b32bcb3 chromeos::ChromeUserManagerImpl::NotifyOnLogin()
#7 0x7fbb82fc35a9 user_manager::UserManagerBase::UserLoggedIn()
#8 0x7fbb7b075386 chromeos::ChromeBrowserMainPartsChromeos::PreProfileInit()
#9 0x7fbb7f260285 ChromeBrowserMainParts::PreMainMessageLoopRunImpl()
#10 0x7fbb7f25eaad ChromeBrowserMainParts::PreMainMessageLoopRun()
#11 0x7fbb7b074524 chromeos::ChromeBrowserMainPartsChromeos::PreMainMessageLoopRun()
#12 0x7fbb77d17557 content::BrowserMainLoop::PreMainMessageLoopRun()
#13 0x7fbb783ce483 content::StartupTaskRunner::RunAllTasksNow()
#14 0x7fbb77d10a11 content::BrowserMainLoop::CreateStartupTasks()
#15 0x7fbb7722680f content::BrowserMainRunnerImpl::Initialize()
#16 0x7fbb77225318 content::BrowserMain()
#17 0x7fbb685374c7 content::RunNamedProcessTypeMain()
#18 0x7fbb6853993c content::ContentMainRunnerImpl::Run()
#19 0x7fbb68534cac content::ContentMain()
#20 0x7fbb66ee8983 ChromeMain
#21 0x7fbb5e7acf45 __libc_start_main
#22 0x7fbb66e2892d <unknown>
"""
    self.assertEqual({
        'crash_state': ('!user_id_hash.empty() in profile_helper.cc\n'
                        'chromeos::ProfileHelper::GetUserProfileDir\n'
                        'chromeos::ProfileHelper::GetProfilePathByUserIdHash\n'
                       ),
        'crash_address':
            '',
        'crash_type':
            'CHECK failure',
    }, parse_stacktrace.parse(s, 'test_job'))

  def test_parse_oom(self):
    """Test parsing OOMs."""
    s = """
WARNING: Failed to find function "__sanitizer_print_stack_trace".
Dictionary: 40 entries
INFO: Seed: 2196577505
INFO: Loaded 2 modules (554656 guards): [0x7f36df4630f0, 0x7f36df47d9f8), [0x80bac0, 0xa0ec38),
/home/user/projects/chromium/src/out/clusterfuzz_6265986639724544_e79e858ded5b3c99d94fa74ffabeec16ef2b2a78/pdf_codec_tiff_fuzzer: Running 1 inputs 100 time(s) each.
Running: /home/user/.clusterfuzz/testcases/6265986639724544_testcase/testcase
==95537== ERROR: libFuzzer: out-of-memory (used: 2786Mb; limit: 2048Mb)
   To change the out-of-memory limit use -rss_limit_mb=<N>

MS: 0 ; base unit: 0000000000000000000000000000000000000000
SUMMARY: libFuzzer: out-of-memory
"""
    self.assertEqual({
        'crash_state': 'NULL',
        'crash_address': '',
        'crash_type': 'Out-of-memory'
    }, parse_stacktrace.parse(s, 'test_job'))
