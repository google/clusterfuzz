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
"""Start host."""

import os
import shutil
import socket
import subprocess
import sys
import threading
import time

MNT_DIR = '/mnt/scratch0'
SRC_DIR = os.path.join(MNT_DIR, 'clusterfuzz')
BOT_BASEDIR = os.path.join(MNT_DIR, 'bots')

NUM_WORKERS_PER_HOST = int(os.environ['NUM_WORKERS_PER_HOST'])


def setup_environment():
  """Set up host environment."""
  os.environ['QUEUE_OVERRIDE'] = 'LINUX_UNTRUSTED'
  os.environ['WORKER_ROOT_DIR'] = os.path.join(MNT_DIR, 'clusterfuzz')
  os.environ['WORKER_BOT_TMPDIR'] = os.path.join(MNT_DIR, 'tmp')

  if not os.path.exists(BOT_BASEDIR):
    os.mkdir(BOT_BASEDIR)


def start_bot_instance(instance_num):
  """Set up bot directory."""
  env = os.environ.copy()

  host_name = os.getenv('HOSTNAME', socket.gethostname())
  bot_name = '%s-%d' % (host_name, instance_num)
  env['BOT_NAME'] = bot_name
  env['HOST_INSTANCE_NAME'] = host_name
  env['HOST_INSTANCE_NUM'] = str(instance_num)

  bot_directory = os.path.join(BOT_BASEDIR, bot_name)
  bot_root_directory = os.path.join(bot_directory, 'clusterfuzz')
  tmp_directory = os.path.join(bot_directory, 'tmp')
  if not os.path.exists(bot_directory):
    os.mkdir(bot_directory)
    os.mkdir(tmp_directory)

  env['ROOT_DIR'] = bot_root_directory
  env['BOT_TMPDIR'] = tmp_directory
  env['PYTHONPATH'] = os.path.join(bot_root_directory, 'src')

  if os.path.exists(bot_root_directory):
    shutil.rmtree(bot_root_directory)

  shutil.copytree(SRC_DIR, bot_root_directory)

  while True:
    bot_proc = subprocess.Popen(
        sys.executable + ' src/python/bot/startup/run.py 2>&1 > console.txt',
        shell=True,
        env=env,
        cwd=bot_root_directory)
    bot_proc.wait()
    print('Instance %i exited.' % instance_num, file=sys.stderr)


def main():
  setup_environment()

  for i in range(NUM_WORKERS_PER_HOST):
    print('Starting bot %i.' % i)
    thread = threading.Thread(target=start_bot_instance, args=(i,))
    thread.start()

  while True:
    # sleep forever
    time.sleep(1000)


if __name__ == '__main__':
  main()
