# Copyright 2020 Google LLC
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
"""Utility functions for models."""

from builtins import chr
from builtins import map
from builtins import next
from builtins import object
from builtins import range
from builtins import str

import numpy as np
import os
import random
import sys
import tensorflow as tf

from bot.fuzzers.ml import constants


def validate_model_dir(model_dir):
  """Check if the model directory exists"""
  return os.path.exists(model_dir)


def random_element_from_list(sequence):
  """Returns a random element from a list."""
  return random.SystemRandom().choice(sequence)


def get_files_list(directory):
  """Returns a list of files in a directory (recursively)."""
  files_list = []
  for (root, _, files) in os.walk(directory):
    for filename in files:
      file_path = os.path.join(root, filename)
      if not os.path.isfile(file_path):
        continue
      files_list.append(file_path)

  return files_list


def get_files_info(directory, rtn_all_bytes=False):
  """Returns a list of files info in a directory (recursively).

  Args:
      directory: Directory path.
      rtn_all_bytes: Whether or not return all bytes.

  Returns:
      A list of file info. Each element is a dictionary with keys 'first_byte'
      and 'file_length'. Note that the list excludes empty files (zero length).
      If rtn_all_bytes is True, also return 'all_bytes' as key and
      all bytes from the file as value.
  """
  files_list = get_files_list(directory)
  files_info_list = []

  # Get files info. Ignore empty files.
  for file_path in files_list:
    file_size = os.path.getsize(file_path)
    if not file_size:
      continue
    if rtn_all_bytes:
      with open(file_path, 'rb') as f:
        all_bytes = f.read()
      all_bytes = encode_text(all_bytes)
      files_info_list.append({
          'first_byte': all_bytes[0],
          'file_size': file_size,
          'all_bytes': all_bytes
      })
    else:
      with open(file_path, 'rb') as f:
        first_byte = ord(f.read(1))
      files_info_list.append({'first_byte': first_byte, 'file_size': file_size})

  return files_info_list


def encode_text(bytes_data):
  """Encode byte string to a list of integers.

  Args:
    bytes_data: Byte string.

  Returns:
    An encoded list of integers representing code points.
  """
  if sys.version_info.major == 3:
    return list(bytes_data)

  return list(map(ord, bytes_data))


def decode_to_text(encoded_list):
  """Decode an encoded list.

  Args:
    encoded_list: Encoded list of code points.

  Returns:
    A string of decoded data.
  """
  return ''.join([chr(c) for c in encoded_list])


def sample_from_probabilities(probabilities):
  """Randomly choose one byte from topn bytes based on their probabilities.

  Roll the dice to produce a random integer in the [0..ALPHA_SIZE] range,
  according to the provided probabilities. If topn is specified, only the
  topn highest probabilities are taken into account.

  Args:
    probabilities: A list of size ALPHA_SIZE with individual probabilities.
    topn: The number of highest probabilities to consider. Defaults to all of
          them.

  Returns:
    A random integer.
  """
  p = np.squeeze(probabilities)
  p = p / np.sum(p)
  return np.random.choice(constants.ALPHA_SIZE, 1, p=p)[0]


def minibatch_sequencer(raw_data,
                        batch_size,
                        sequence_size,
                        nb_epochs,
                        rtn_diff_xy=True):
  """Divide data into batches and return one batch for training each time.

  Divide the data into batches of sequences so that all the sequences
  in one batch continue in the next batch. This is a generator that will
  keep returning batches until the input data has been seen nb_epochs times.
  Sequences are continued even between epochs, apart from one,
  the one corresponding to the end of raw_data.

  The remainder at the end of raw_data that does not fit in an full batch is
  ignored.

  Args:
      raw_data: The training text.
      batch_size: The size of a training minibatch.
      sequence_size: The unroll size of the RNN.
      nb_epochs: Number of epochs to train on.

  Yields:
      x: One batch of training sequences.
      y: One batch of target sequences, i.e. training sequences shifted by 1.
      epoch: The current epoch number (starting at 0).
  """
  data = np.array(raw_data)
  data_len = data.shape[0]

  # Using (data_len-1) because we must provide for the sequence
  # Shifted by 1 if rtn_diff_xy is True.
  nb_batches = (data_len - rtn_diff_xy) // (batch_size * sequence_size)
  assert nb_batches > 0, ('Not enough data, even for a single batch. Try using '
                          'a smaller batch_size.')
  rounded_data_len = nb_batches * batch_size * sequence_size
  xdata = np.reshape(data[0:rounded_data_len],
                     [batch_size, nb_batches * sequence_size])
  ydata = np.reshape(data[rtn_diff_xy:rounded_data_len + rtn_diff_xy],
                     [batch_size, nb_batches * sequence_size])

  for epoch in range(nb_epochs):
    for batch in range(nb_batches):
      x = xdata[:, batch * sequence_size:(batch + 1) * sequence_size]
      y = ydata[:, batch * sequence_size:(batch + 1) * sequence_size]
      yield x, y, epoch


def find_input(index, input_ranges):
  """Find the input name given the index of training data."""
  return next(input['name']
              for input in input_ranges
              if input['start'] <= index < input['end'])


def find_input_index(index, input_ranges):
  """Find the input index given the index of training data."""
  return next(i for i, input in enumerate(input_ranges)
              if input['start'] <= index < input['end'])


def print_learning_learned_comparison(x, y, losses, input_ranges, batch_loss,
                                      batch_accuracy, epoch_size, index, epoch):
  """Display utility for printing learning statistics."""
  print()

  # epoch_size in number of batches.
  batch_size = x.shape[0]
  sequence_len = x.shape[1]
  start_index_in_epoch = index % (epoch_size * batch_size * sequence_len)
  for k in range(batch_size):
    index_in_epoch = index % (epoch_size * batch_size * sequence_len)
    decx = repr(decode_to_text(x[k]))
    decy = repr(decode_to_text(y[k]))
    formatted_decx = '{: <40.40}'.format(decx)
    formatted_decy = '{: <40.40}'.format(decy)
    inputname = find_input(index_in_epoch, input_ranges)
    formatted_inputname = '{: <10.20}'.format(inputname)
    epoch_string = '{:6d}'.format(index) + ' (epoch {}) '.format(epoch)
    loss_string = 'loss: {:.5f}'.format(losses[k])
    print_string = epoch_string + formatted_inputname + ' | {} | {} | {}'
    print(print_string.format(formatted_decx, formatted_decy, loss_string))
    index += sequence_len

  format_string = '{:-^' + str(len(epoch_string)) + '}'
  format_string += '{:-^' + str(len(formatted_inputname)) + '}'
  format_string += '{:-^' + str(len(formatted_decx) + 4) + '}'
  format_string += '{:-^' + str(len(formatted_decy) + 4) + '}'
  format_string += '{:-^' + str(len(loss_string)) + '}'
  footer = format_string.format('INDEX', 'INPUT NAME',
                                'TRAINING SEQUENCE (truncated)',
                                'PREDICTED SEQUENCE (truncated)', 'LOSS')
  print(footer)

  # Print statistics
  batch_index = start_index_in_epoch // (batch_size * sequence_len)
  batch_string = 'batch {}/{} in epoch {},'.format(batch_index, epoch_size,
                                                   epoch)
  stats = '{: <28} batch loss: {:.5f}, batch accuracy: {:.5f}'.format(
      batch_string, batch_loss, batch_accuracy)
  print('\nTRAINING STATS: {}'.format(stats))


class Progress(object):
  """Text mode progress bar.

  Usage:
    p = Progress(30)
    p.step()
    p.step()
    p.step(start=True) # to restart form 0%

  The progress bar displays a new header at each restart.
  """

  def __init__(self, maxi, size=100, msg=''):
    """Initialize class.

    Args:
      maxi: The number of steps required to reach 100%.
      size: The number of characters taken on the screen by the progress bar.
      msg: The message displayed in the header of the progress bar.
    """
    self.maxi = maxi

    self.p = self.__start_progress(maxi)()
    self.header_printed = False
    self.msg = msg
    self.size = size

  def step(self, reset=False):
    """Print one step of progress bar."""
    if reset:
      self.__init__(self.maxi, self.size, self.msg)
    if not self.header_printed:
      self.__print_header()
    next(self.p)

  def __print_header(self):
    """Print progress bar header."""
    format_string = '\n0%{: ^' + str(self.size - 6) + '}100%'
    print(format_string.format(self.msg))
    self.header_printed = True

  def __start_progress(self, maxi):
    """Progress bar printer."""

    def print_progress():
      """Yields the number of dots printed."""
      # Bresenham's algorithm. Yields the number of dots printed.
      # This will always print 100 dots in max invocations.
      dx = maxi
      dy = self.size
      d = dy - dx
      for _ in range(maxi):
        k = 0
        while d >= 0:
          print('=', end=' ')
          sys.stdout.write('')
          sys.stdout.flush()
          k += 1
          d -= dx
        d += dy
        yield k

    return print_progress


def read_data_files(directory):
  """Read data files (recursively) and split to training and validation sets.

  Optionally set aside the last file as validation data. No validation
  data is returned if there are 5 files or less.

  Args:
    directory: Directory path.
    validation: If True, sets the last file aside as validation data.

  Returns:
    Training data, validation data, list of loaded file names with ranges
    if validation is true.
  """
  code_text = []
  input_ranges = []
  input_list = get_files_list(directory)
  for input_file in input_list:
    with open(input_file, 'rb') as f:
      start = len(code_text)
      code_text.extend(encode_text(f.read()))
      end = len(code_text)
      input_ranges.append({
          'start': start,
          'end': end,
          'name': input_file.rsplit('/', 1)[-1]
      })

  print('Loaded {} corpus files.'.format(len(input_list)))

  if not input_ranges:
    sys.exit('No training data has been found. Aborting.')

  return code_text


def print_data_info(data_len, epoch_size):
  """Print training data statistics, such as size, batches."""
  data_len_mb = data_len / 1024.0 / 1024.0
  print('Training text size is {:.2f}MB'.format(data_len_mb) +
        'There will be {} batches per epoch'.format(epoch_size))


def print_validation_header(validation_start, input_ranges):
  """Print validation header."""
  input_index = find_input_index(validation_start, input_ranges)
  inputs = ''
  for i in range(input_index, len(input_ranges)):
    inputs += input_ranges[i]['name']
    if i < len(input_ranges) - 1:
      inputs += ', '
  print(inputs)


def print_validation_stats(loss, accuracy):
  """Print validation results, including loss and accuracy."""
  print('VALIDATION STATS:                                  ' +
        'loss: {:.5f},       accuracy: {:.5f}'.format(loss, accuracy))


def print_text_generation_header():
  """Print generation header."""
  print('\n{:-^138}'.format(' Generating random text from learned state '))


def print_text_generation_footer():
  """Print generation footer."""
  print('\n{:-^138}'.format(' End of generation '))


def compute_batch_loss_and_acc_value(true_value,
                                     prediction,
                                     loss,
                                     all_stats=False):
  """Compute batch loss and accuracy value with true value and prediction.

  Args:
    true_value: True value of the batch, shape should be (batch_size, seq_len).
    prediction: Output of the model, shape is (batch_size, seq_len, alpha_size).
    loss: Loss function.
    all_stats: Whether or not return prediction_value and sequence loss
  """

  # Prediction shape should be (batch_size, sequence_length, alpha_size),
  # so we predict the value to be the one with maximal probability.
  # loss_value shape is (batch_size, seq_length)
  pred_value = np.argmax(prediction, axis=2)
  loss_value = loss(true_value, prediction)

  # If all_stats is True,
  # we return pred_value, seq_loss, batch_loss, acc_value,
  # otherwise return batch_loss, acc_value.
  if all_stats:
    return pred_value, np.mean(loss_value, axis=1), \
      np.mean(loss_value), np.mean(pred_value == true_value)
  return np.mean(loss_value), np.mean(pred_value == true_value)


def tensorboard_write(writer, batch_loss, acc_value, steps):
  """Write batch_loss and acc_value into writer."""
  with writer.as_default():
    tf.summary.scalar("batch_loss", batch_loss, step=steps)
    tf.summary.scalar("acc_value", acc_value, step=steps)
    writer.flush()


def save_model(model, model_dir, model_name):
  """Save model to model_dir/model_name."""
  saved_model_path = os.path.join(model_dir, model_name)
  model.save(saved_model_path)
  print(f"Save model: {model_name}")


def save_weights(model, model_dir, model_name):
  saved_model_path = os.path.join(model_dir, model_name + ".h5")
  model.save_weights(saved_model_path)
  print(f"Save model weight: {model_name + '.h5'}")


def model_is(model_name, expected_name):
  """Check if current model is expected model."""
  return model_name.upper().startswith(expected_name)
