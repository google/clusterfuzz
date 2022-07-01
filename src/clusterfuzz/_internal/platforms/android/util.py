
import os

from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.metrics import logs


def get_device_path(local_path):
  """Return device path for the given local path."""
  root_directory = environment.get_root_directory()
  return os.path.join(android.constants.DEVICE_FUZZING_DIR,
                      os.path.relpath(local_path, root_directory))

def get_local_path(device_path):
  """Return local path for the given device path."""
  if not device_path.startswith(android.constants.DEVICE_FUZZING_DIR + '/'):
    logs.log_error('Bad device path: ' + device_path)
    return None

  root_directory = environment.get_root_directory()
  return os.path.join(
      root_directory,
      os.path.relpath(device_path, android.constants.DEVICE_FUZZING_DIR))

def get_device_corpus_paths(self, corpus_directories):
  """Return device paths for the given corpus directories."""
  return [get_device_path(path) for path in corpus_directories]





