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
"""Utility functions for ml rnn model."""

import os
import random
import sys

import numpy as np
import tensorflow as tf

from clusterfuzz._internal.bot.fuzzers.ml.rnn import constants


def build_model(num_rnn_cells, dropout_pkeep, batch_size, debug):
  """Build the RNN model.

  Since we use the Keras sequential model and we use different batch sizes for
  train, validation and demo output generation, we use this function to rebatch
  the model.

  Args:
    num_rnn_cells: number of RNN cells to use.
    dropout_pkeep: probability of keeping a node in dropout.
    batch_size: batch size used by the model layer.
    debug: if True, print a summary of the model.

  Returns:
    Keras Sequential RNN model.
  """
  dropout_pdrop = 1 - dropout_pkeep
  model = tf.keras.Sequential([
      tf.keras.layers.Embedding(
          constants.ALPHA_SIZE,
          constants.ALPHA_SIZE,
          batch_input_shape=[batch_size, None]),
      tf.keras.layers.GRU(
          num_rnn_cells,
          return_sequences=True,
          stateful=True,
          dropout=dropout_pdrop),
      tf.keras.layers.Dense(constants.ALPHA_SIZE),
  ])

  # Display a summary of the model to debug shapes.
  if debug:
    model.summary()

  return model


def validate_model_path(model_path):
  """RNN model consists of two files. This validates if they all exist."""
  model_exists = (
      os.path.exists(model_path + constants.MODEL_DATA_SUFFIX) and
      os.path.exists(model_path + constants.MODEL_INDEX_SUFFIX))
  return model_exists


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


def get_files_info(directory):
  """Returns a list of files info in a directory (recursively).

  Args:
    directory: Directory path.

  Returns:
    A list of file info. Each element is a dictionary with keys 'first_byte'
    and 'file_length'. Note that the list excludes empty files (zero length).
  """
  files_list = get_files_list(directory)
  files_info_list = []

  # Get files info. Ignore empty files.
  for file_path in files_list:
    file_size = os.path.getsize(file_path)
    if not file_size:
      continue
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
  return list(bytes_data)


def decode_to_text(encoded_list):
  """Decode an encoded list.

  Args:
    encoded_list: Encoded list of code points.

  Returns:
    A string of decoded data.
  """
  return ''.join([chr(c) for c in encoded_list])


def sample_from_probabilities(probabilities, topn=constants.ALPHA_SIZE):
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
  p[np.argsort(p)[:-topn]] = 0
  p = p / np.sum(p)
  return np.random.choice(constants.ALPHA_SIZE, 1, p=p)[0]


def rnn_minibatch_sequencer(raw_data, batch_size, sequence_size, nb_epochs):
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
  # shifted by 1 too.
  nb_batches = (data_len - 1) // (batch_size * sequence_size)
  assert nb_batches > 0, ('Not enough data, even for a single batch. Try using '
                          'a smaller batch_size.')
  rounded_data_len = nb_batches * batch_size * sequence_size
  xdata = np.reshape(data[0:rounded_data_len],
                     [batch_size, nb_batches * sequence_size])
  ydata = np.reshape(data[1:rounded_data_len + 1],
                     [batch_size, nb_batches * sequence_size])

  for epoch in range(nb_epochs):
    for batch in range(nb_batches):
      x = xdata[:, batch * sequence_size:(batch + 1) * sequence_size]
      y = ydata[:, batch * sequence_size:(batch + 1) * sequence_size]

      # To continue the text from epoch to epoch (do not reset rnn state!).
      x = np.roll(x, -epoch, axis=0)
      y = np.roll(y, -epoch, axis=0)
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
          print('=', end='')
          sys.stdout.write('')
          sys.stdout.flush()
          k += 1
          d -= dx
        d += dy
        yield k

    return print_progress


def read_data_files(directory, validation=False):
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

  # For validation, use roughly 90K of text,
  # but no more than 10% of the entire text
  # and no more than 1 input in 5 => no validation at all for 5 files or fewer.

  # 10% of the text is how many files?
  total_len = len(code_text)
  validation_len = 0
  nb_inputs1 = 0
  for one_input in reversed(input_ranges):
    validation_len += one_input['end'] - one_input['start']
    nb_inputs1 += 1
    if validation_len > total_len // 10:
      break

  # 90K of text is how many inputs?
  validation_len = 0
  nb_inputs2 = 0
  for one_input in reversed(input_ranges):
    validation_len += one_input['end'] - one_input['start']
    nb_inputs2 += 1
    if validation_len > 90 * 1024:
      break

  # 20% of the inputs is how many inputs?
  nb_inputs3 = len(input_ranges) // 5

  # Pick the smallest.
  nb_inputs = min(nb_inputs1, nb_inputs2, nb_inputs3)

  if nb_inputs == 0 or not validation:
    cutoff = len(code_text)
  else:
    cutoff = input_ranges[-nb_inputs]['start']
  validation_text = code_text[cutoff:]
  code_text = code_text[:cutoff]
  return code_text, validation_text, input_ranges


def print_data_stats(data_len, validation_len, epoch_size):
  """Print training data statistics, such as size, batches."""
  data_len_mb = data_len / 1024.0 / 1024.0
  validation_len_kb = validation_len / 1024.0
  print('Training text size is {:.2f}MB with {:.2f}KB set aside for validation.'
        .format(data_len_mb, validation_len_kb) +
        'There will be {} batches per epoch'.format(epoch_size))


def print_validation_header(validation_start, input_ranges):
  """Print validation header."""
  input_index = find_input_index(validation_start, input_ranges)
  inputs = ''
  for i in range(input_index, len(input_ranges)):
    inputs += input_ranges[i]['name']
    if i < len(input_ranges) - 1:
      inputs += ', '


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
