import argparse
import os
import sys
import time
import traceback
import subprocess
import traceback

original_init = subprocess.Popen.__init__

def debug_init(self, *args, **kwargs):
    print(f"DEBUG: subprocess.Popen args: {args}")
    print(f"DEBUG: subprocess.Popen kwargs: {kwargs}")
    traceback.print_stack()
    original_init(self, *args, **kwargs)

subprocess.Popen.__init__ = debug_init

# Add clusterfuzz to sys.path if provided
def setup_path(clusterfuzz_src):
    if clusterfuzz_src:
        sys.path.insert(0, os.path.join(clusterfuzz_src, 'third_party'))
        sys.path.insert(0, clusterfuzz_src)
    
    # Try to import clusterfuzz
    try:
        from clusterfuzz._internal.bot import testcase_manager
        from clusterfuzz._internal.system import environment
        from clusterfuzz._internal.metrics import logs
        from clusterfuzz._internal.crash_analysis import crash_result
        print(f"DEBUG: testcase_manager file: {testcase_manager.__file__}")
        # print(f"DEBUG: dir(testcase_manager): {dir(testcase_manager)}")
        return testcase_manager, environment, logs, crash_result
    except ImportError as e:
        print(f"Error: Could not import clusterfuzz modules: {e}")
        print(f"sys.path: {sys.path}")
        sys.exit(1)

def _setup_environment(environment, logs, args):
    """Sets up the environment."""
    # Set BOT_TMPDIR
    bot_tmpdir = args.bot_tmpdir
    if not os.path.exists(bot_tmpdir):
        os.makedirs(bot_tmpdir)
    environment.set_value('BOT_TMPDIR', bot_tmpdir)
    environment.set_value('TEST_TMPDIR', bot_tmpdir)
    environment.set_value('WARMUP_TIMEOUT', 60)

    # Create config dir and dummy project.yaml
    # Must be outside BOT_TMPDIR because clear_temp_directory clears it
    config_dir = '/tmp/cf_config'
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    
    with open(os.path.join(config_dir, 'project.yaml'), 'w') as f:
        f.write('stacktrace:\n  stack_frame_ignore_regexes: []\n')
    
    environment.set_value('CONFIG_DIR_OVERRIDE', config_dir)
    environment.set_value('ROOT_DIR', os.getcwd())
    
    # Create logs dir
    logs_dir = os.path.join(bot_tmpdir, 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    environment.set_value('LOG_DIR', logs_dir)

    # Set USER_PROFILE_ROOT_DIR
    user_profile_root = os.path.join(bot_tmpdir, 'user_profiles')
    if not os.path.exists(user_profile_root):
        os.makedirs(user_profile_root)
    environment.set_value('USER_PROFILE_ROOT_DIR', user_profile_root)

    # Set other required env vars
    environment.set_value('INPUT_DIR', os.path.dirname(args.testcase_path))
    environment.set_value('APP_DIR', os.path.dirname(args.target_binary))
    
    crash_stacktraces_dir = os.path.join(bot_tmpdir, 'crash_stacktraces')
    if not os.path.exists(crash_stacktraces_dir):
        os.makedirs(crash_stacktraces_dir)
    environment.set_value('CRASH_STACKTRACES_DIR', crash_stacktraces_dir)
    
    # Set optional env vars to avoid NoneType errors
    for var in ['FUZZER_DIR', 'FUZZ_DATA', 'DATA_BUNDLES_DIR', 'FUZZERS_DIR', 'FUZZ_INPUTS', 'FUZZ_INPUTS_DISK', 'BUILDS_DIR', 'BUILD_URLS_DIR']:
        if not environment.get_value(var):
            environment.set_value(var, '')

    # Configure logging to stdout
    try:
        logs.configure('run_bot')
    except Exception as e:
        print(f"Warning: logs.configure failed: {e}")

def _verify_reproduction(testcase_manager, environment, crash_result_module, args):
    """Verifies reproduction."""
    target_binary = args.target_binary
    testcase_path = args.testcase_path
    
    print(f"Verifying reproduction for {target_binary} with {testcase_path}")

    # Create a mock FuzzTarget
    class MockFuzzTarget:
        def __init__(self, engine, binary):
            self.engine = engine
            self.binary = binary
            self.project = 'test_project'
    
    # Monkeypatch LibFuzzerRunner to debug
    from clusterfuzz._internal.bot.fuzzers import libfuzzer
    print(f"DEBUG: libfuzzer module: {libfuzzer}")
    
    # Check libFuzzer engine
    try:
        from clusterfuzz._internal.bot.fuzzers.libFuzzer import engine as libFuzzer_engine
        print(f"DEBUG: libFuzzer_engine module: {libFuzzer_engine}")
        print(f"DEBUG: libFuzzer_engine.libfuzzer: {getattr(libFuzzer_engine, 'libfuzzer', 'Not found')}")
        if hasattr(libFuzzer_engine, 'libfuzzer'):
             print(f"DEBUG: libFuzzer_engine.libfuzzer == libfuzzer: {libFuzzer_engine.libfuzzer == libfuzzer}")
    except ImportError as e:
        print(f"DEBUG: Could not import libFuzzer engine: {e}")

    original_run_single_testcase = libfuzzer.LibFuzzerRunner.run_single_testcase
    
    def mocked_run_single_testcase(self, testcase_path, timeout=None, additional_args=None):
        sys.stderr.write(f"DEBUG: Mocked run_single_testcase called with testcase_path={testcase_path}, additional_args={additional_args}\n")
        sys.stderr.write(f"DEBUG: self._executable_path={self._executable_path}\n")
        sys.stderr.write(f"DEBUG: self._default_args={self._default_args}\n")
        return original_run_single_testcase(self, testcase_path, timeout, additional_args)
        
    libfuzzer.LibFuzzerRunner.run_single_testcase = mocked_run_single_testcase

    # Monkeypatch ModifierProcessRunnerMixin to debug
    from clusterfuzz._internal.system import new_process
    original_mixin_get_command = new_process.ModifierProcessRunnerMixin.get_command
    
    def mocked_mixin_get_command(self, additional_args=None):
        cmd = original_mixin_get_command(self, additional_args)
        sys.stderr.write(f"DEBUG: ModifierProcessRunnerMixin.get_command returning: {cmd}\n")
        sys.stderr.write(f"DEBUG: self._executable_path: {self._executable_path}\n")
        return cmd
        
    new_process.ModifierProcessRunnerMixin.get_command = mocked_mixin_get_command

    # Monkeypatch LibFuzzerRunner.__init__
    original_libfuzzer_init = libfuzzer.LibFuzzerRunner.__init__
    
    def mocked_libfuzzer_init(self, executable_path, default_args=None):
        sys.stderr.write(f"DEBUG: LibFuzzerRunner.__init__ called with executable_path={executable_path}, default_args={default_args}\n")
        original_libfuzzer_init(self, executable_path, default_args)
        
    libfuzzer.LibFuzzerRunner.__init__ = mocked_libfuzzer_init

    # Monkeypatch TestcaseRunner.run
    original_testcase_runner_run = testcase_manager.TestcaseRunner.run
    
    def mocked_testcase_runner_run(self, round_number):
        sys.stderr.write(f"DEBUG: TestcaseRunner.run called. is_black_box={self._is_black_box}\n")
        result = original_testcase_runner_run(self, round_number)
        print(f"DEBUG: mocked_testcase_runner_run: result.return_code: {result.return_code}")
        return result
        
    testcase_manager.TestcaseRunner.run = mocked_testcase_runner_run

    # Monkeypatch LibFuzzerEngine.reproduce
    from clusterfuzz._internal.bot.fuzzers.libFuzzer import engine as libFuzzer_engine
    original_engine_reproduce = libFuzzer_engine.Engine.reproduce
    
    def mocked_engine_reproduce(self, target_path, input_path, arguments, max_time):
        sys.stderr.write(f"DEBUG: LibFuzzerEngine.reproduce called with target_path={target_path}\n")
        result = original_engine_reproduce(self, target_path, input_path, arguments, max_time)
        print(f"DEBUG: mocked_engine_reproduce: result.return_code: {result.return_code}")
        return result
        
    libFuzzer_engine.Engine.reproduce = mocked_engine_reproduce

    fuzz_target = MockFuzzTarget(engine='libFuzzer', binary=target_binary)
    
    # Create a mock Testcase
    class MockTestcase:
        def __init__(self):
            self.crash_type = None
            self.crash_state = None
            self.security_flag = False
            self.gestures = []
            self.flaky_stack = False
    
    testcase = MockTestcase()
    
    # Set up environment for the testcase
    environment.set_value('APP_NAME', os.path.basename(target_binary))
    environment.set_value('APP_PATH', target_binary)
    environment.set_value('USE_MINIJAIL', False)
    environment.set_value('APP_ARGS', '')
    environment.set_value('BUILD_DIR', os.path.dirname(target_binary))
    environment.set_value('JOB_NAME', 'libfuzzer_asan')  # Required for get_memory_tool_name

    # Monkeypatch testcase_manager.engine_reproduce
    original_tm_engine_reproduce = testcase_manager.engine_reproduce
    
    def mocked_tm_engine_reproduce(engine_impl, target_name, testcase_path, arguments, timeout):
        sys.stderr.write(f"DEBUG: testcase_manager.engine_reproduce called with target_name={target_name}, testcase_path={testcase_path}\\n")
        sys.stderr.write(f"DEBUG: engine_impl={engine_impl}\\n")
        sys.stderr.write(f"DEBUG: type(engine_impl)={type(engine_impl)}\\n")
        sys.stderr.write(f"DEBUG: dir(engine_impl)={dir(engine_impl)}\\n")
        
        # Patch reproduce on the instance
        original_reproduce = engine_impl.reproduce
        def mocked_instance_reproduce(target_path, input_path, arguments, timeout):
            sys.stderr.write(f"DEBUG: INSTANCE engine_impl.reproduce called with target_path={target_path}, input_path={input_path}\\n")
            return original_reproduce(target_path, input_path, arguments, timeout)
        
        engine_impl.reproduce = mocked_instance_reproduce
        
        sys.stderr.write(f"DEBUG: is_trusted_host={environment.is_trusted_host()}\\n")
        return original_tm_engine_reproduce(engine_impl, target_name, testcase_path, arguments, timeout)
        
    testcase_manager.engine_reproduce = mocked_tm_engine_reproduce

    # Monkeypatch engine_common.find_fuzzer_path
    from clusterfuzz._internal.bot.fuzzers import engine_common
    original_find_fuzzer_path = engine_common.find_fuzzer_path
    def mocked_find_fuzzer_path(build_directory, fuzzer_name):
        sys.stderr.write(f"DEBUG: find_fuzzer_path called with build_directory={build_directory}, fuzzer_name={fuzzer_name}\\n")
        if os.path.isabs(fuzzer_name) and os.path.exists(fuzzer_name):
            sys.stderr.write(f"DEBUG: fuzzer_name is absolute and exists. Returning it.\\n")
            return fuzzer_name
        
        # Debug listing
        if os.path.exists(build_directory):
            sys.stderr.write(f"DEBUG: Listing {build_directory}: {os.listdir(build_directory)}\\n")
        else:
            sys.stderr.write(f"DEBUG: {build_directory} does not exist!\\n")

        path = original_find_fuzzer_path(build_directory, fuzzer_name)
        sys.stderr.write(f"DEBUG: find_fuzzer_path returning {path}\\n")
        return path
    engine_common.find_fuzzer_path = mocked_find_fuzzer_path

    # Monkeypatch UnicodeProcessRunner.run_and_wait
    from clusterfuzz._internal.system import new_process
    original_upr_run_and_wait = new_process.UnicodeProcessRunner.run_and_wait
    def mocked_upr_run_and_wait(self, additional_args=None, **kwargs):
        sys.stderr.write(f"DEBUG: UnicodeProcessRunner.run_and_wait called with additional_args={additional_args}\\n")
        return original_upr_run_and_wait(self, additional_args=additional_args, **kwargs)
    new_process.UnicodeProcessRunner.run_and_wait = mocked_upr_run_and_wait

    # Monkeypatch ProcessRunner.run
    original_pr_run = new_process.ProcessRunner.run
    def mocked_pr_run(self, additional_args=None, **kwargs):
        sys.stderr.write(f"DEBUG: ProcessRunner.run called with additional_args={additional_args}\\n")
        return original_pr_run(self, additional_args=additional_args, **kwargs)
    new_process.ProcessRunner.run = mocked_pr_run

    try:
        result = testcase_manager.test_for_crash_with_retries(
            fuzz_target=fuzz_target,
            testcase=testcase,
            testcase_path=testcase_path,
            test_timeout=60, # Default timeout
            compare_crash=False,
            crash_retries=3 # Retry 3 times
        )
        
        print(f"DEBUG: test_for_crash_with_retries returned: {result}")
        print(f"DEBUG: CrashResult details: return_code={result.return_code}, output={result.output}")

        if result.is_crash():
            print("Crash detected!")
            print(f"Crash Type: {result.get_type()}")
            print(f"Crash State: {result.get_state(symbolized=False)}")
            print(f"Crash Stacktrace: {result.get_stacktrace(symbolized=False)}")
            sys.exit(0)
        else:
            print("No crash detected.")
            print(f"Return Code: {result.return_code}")
            print(f"Output: {result.output}")
            sys.exit(1)
            
    except Exception:
        print(f"Error during reproduction: {traceback.format_exc()}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Verify reproduction using ClusterFuzz testcase_manager.')
    parser.add_argument('--target_binary', required=True, help='Path to the target binary')
    parser.add_argument('--testcase_path', required=True, help='Path to the testcase')
    parser.add_argument('--clusterfuzz_src', help='Path to clusterfuzz source code')
    parser.add_argument('--bot_tmpdir', default='/tmp/bot', help='Temporary directory for bot')
    args = parser.parse_args()

    testcase_manager, environment, logs, crash_result_module = setup_path(args.clusterfuzz_src)
    _setup_environment(environment, logs, args)
    # Register fuzzing engines
    from clusterfuzz._internal.bot.fuzzers import init
    init.run()
    
    from clusterfuzz.fuzz import engine
    print(f"DEBUG: engine.get('libFuzzer'): {engine.get('libFuzzer')}")

    _verify_reproduction(testcase_manager, environment, crash_result_module, args)

if __name__ == '__main__':
    main()
