import os
import sys

# Add the 'src' directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Set the necessary environment variables
os.environ['ROOT_DIR'] = os.path.abspath('.')
os.environ['APP_CONFIG_DIR'] = '../clusterfuzz-config/configs/external/'

from clusterfuzz._internal.cron import schedule_fuzz

if __name__ == '__main__':
  print("Executing schedule_fuzz.main() from run_schedule_fuzz_directly.py")
  schedule_fuzz.main()
