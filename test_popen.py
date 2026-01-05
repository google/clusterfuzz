import subprocess
import sys

cmd = ['/usr/local/google/home/matheushunsche/projects/clusterfuzz/dummy_fuzzer.py', '-runs=3', '/tmp/crash_testcase']
print(f"Running: {cmd}")
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
stdout, _ = p.communicate()
print("Output:")
print(stdout.decode())
