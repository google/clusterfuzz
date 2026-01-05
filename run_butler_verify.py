import os
import subprocess
import shutil
import sys

def main():
    root_dir = '/usr/local/google/home/matheushunsche/projects/clusterfuzz'
    butler_path = os.path.join(root_dir, 'butler.py')
    reproduce_py_path = os.path.join(root_dir, 'src/local/butler/reproduce.py')
    
    build_dir = os.path.join(root_dir, 'build_out')
    os.makedirs(build_dir, exist_ok=True)
    
    dummy_fuzzer_src = os.path.join(root_dir, 'dummy_fuzzer.py')
    dummy_fuzzer_dst = os.path.join(build_dir, 'dummy_fuzzer.py')
    shutil.copy(dummy_fuzzer_src, dummy_fuzzer_dst)
    os.chmod(dummy_fuzzer_dst, 0o755)
    
    testcase_path = os.path.join(root_dir, 'testcase')
    with open(testcase_path, 'w') as f:
        f.write('CRASH')
        
    config_dir = os.path.join(root_dir, 'config')
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, 'project.yaml'), 'w') as f:
        f.write('env: {}\n')

    bot_dir = os.path.join(root_dir, 'bot')
    os.makedirs(bot_dir, exist_ok=True)
    with open(os.path.join(bot_dir, 'env.yaml'), 'w') as f:
        f.write('env: {}\n')

    src_path = os.path.join(root_dir, 'src')
    
    cmd = [
        'docker', 'run', '--rm',
        '-v', f'{butler_path}:/data/clusterfuzz/butler.py',
        '-v', f'{src_path}:/data/clusterfuzz/src',
        '-v', f'{config_dir}:/data/clusterfuzz/src/appengine/config',
        '-v', f'{bot_dir}:/data/clusterfuzz/bot',
        '-v', f'{testcase_path}:/tmp/testcase',
        '-v', f'{build_dir}:/tmp/build',
        '-e', 'ROOT_DIR=/data/clusterfuzz',
        '-e', 'PYTHONPATH=/data/clusterfuzz/src',
        '-e', 'TEST_BOT_ENVIRONMENT=1',
        '-e', 'CRASH_RETRIES=1',
        'gcr.io/clusterfuzz-images/base:latest',
        'bash', '-c',
        'chmod +x /tmp/build/dummy_fuzzer.py && cd /data/clusterfuzz && grep -n "DEBUG" /data/clusterfuzz/src/clusterfuzz/_internal/system/new_process.py; python3.11 butler.py --local-logging reproduce --testcase-path /tmp/testcase --target-name dummy_fuzzer.py --job-name libfuzzer_asan --revision 1 --build-dir /tmp/build --config-dir /data/clusterfuzz/src/appengine/config; cat /tmp/fuzzer.log'
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
    print("Return Code:", result.returncode)

if __name__ == '__main__':
    main()
