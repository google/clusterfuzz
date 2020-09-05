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
"""RNN score insert generator."""

from tensorflow import keras
import numpy as np
from scipy.special import softmax

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.rnn_model import RNNModel

class RNNScoreInsertGenerator:
  """Generate inputs using RNN model with insert strategy.
  In this strategy, we are using RNN model as a score function.
  For example we want to insert after a3 in  [a1 a2 a3 a4 a5 a6],
  we will use [a1 a2 a3 0-255 a4 a5] as input
  and [a2 a3 0-255 a4 a5 a6] as output
  and compute the log likelihood.
  After we get 256 log likelihood,
  we use softmax result as probability for each outcome
  and sample the byte based on this probability."""
  def __init__(self, hidden_layer_number, hidden_state_size,
               pkeep, model_weights_path,
               input_dir, pos_change, predict_window_size,
               batch_size, temperature, insert_nums):
    self.model = RNNModel(
        constants.ALPHA_SIZE,
        hidden_state_size=hidden_state_size,
        hidden_layer_number=hidden_layer_number,
        pkeep=pkeep,
        batch_size=constants.ALPHA_SIZE,
        temperature=temperature)
    self.model.build(input_shape=(constants.ALPHA_SIZE, None))
    self.model.load_weights(model_weights_path)

    self.pos_change = pos_change
    self.predict_window_size = predict_window_size
    self.batch_size = batch_size
    self.insert_nums = insert_nums

    assert self.pos_change > 0, \
      "pos_change must be greater than 0 in RNN score insert strategy."
    assert self.predict_window_size > 0, \
      "predict_window_size must be greater than 0 in RNN score insert strategy."
    assert self.insert_nums > 0, \
      "insert_nums must be greater than 0 in RNN score insert strategy."
    self.corpus_files_info = utils.get_files_info(input_dir, pos_change != 0)
    assert self.corpus_files_info, "Corpus not exists"

  def generate(self):
    """Main part for generation."""
    new_files_bytes = []
    loss = keras.losses.SparseCategoricalCrossentropy(
        reduction=keras.losses.Reduction.NONE)
    for i in range(self.batch_size):
      print(f"file {i + 1}/{self.batch_size}", end='\r')
      random_file_info = utils.random_element_from_list(self.corpus_files_info)
      file_size = random_file_info["file_size"]
      cur_bytes = random_file_info["all_bytes"].copy()
      # modify position cannot be the last position
      mod_positions = sorted(
          np.random.choice(file_size - 1, self.pos_change, replace=False))

      insert_bytes = np.zeros((self.pos_change, self.insert_nums), dtype=np.int)
      insert_times = np.zeros(self.pos_change, dtype=np.int)
      for pos_idx, pos in enumerate(mod_positions):
        st_pos = max(0, pos - np.random.choice(self.predict_window_size))
        ed_pos = min(file_size, st_pos + self.predict_window_size)
        st_pos = ed_pos - self.predict_window_size
        # ed_pos must be > pos + 1
        if ed_pos <= pos + 1:
          ed_pos, st_pos = pos + 2, pos + 2 - self.predict_window_size

        input_bytes = np.zeros(
            (constants.ALPHA_SIZE, self.predict_window_size),
            dtype=np.int)
        target_bytes = np.zeros(
            (constants.ALPHA_SIZE, self.predict_window_size),
            dtype=np.int)
        # insert the byte right after pos.
        for c in range(constants.ALPHA_SIZE):
          input_bytes[c, : pos - st_pos + 1] = cur_bytes[st_pos : pos + 1]
          input_bytes[c, pos - st_pos + 1] = c
          input_bytes[c, pos - st_pos + 2 : ] = cur_bytes[pos + 1 : ed_pos - 1]
          target_bytes[c, : pos - st_pos] = cur_bytes[st_pos + 1 : pos + 1]
          target_bytes[c, pos - st_pos] = c
          target_bytes[c, pos - st_pos + 1 : ] = cur_bytes[pos + 1 : ed_pos]

        insert_times[pos_idx] = self.insert_nums
        original_next_byte = cur_bytes[pos + 1]

        for insert_idx in range(self.insert_nums):
          self.model.reset_states()
          predictions = self.model(input_bytes)

          loss_value = loss(target_bytes, predictions).numpy().sum(axis=1)
          prob = softmax(-loss_value)
          # sum(prob) might be a little bit greater than 1
          # so we need to adjust it
          prob /= np.sum(prob) + 1e-6
          predicted_byte = np.argmax(np.random.multinomial(1, prob))
          insert_bytes[pos_idx][insert_idx] = predicted_byte
          if prob[predicted_byte] < prob[original_next_byte]:
            insert_times[pos_idx] = insert_idx
            break

          input_bytes[:, pos - st_pos + 1] = predicted_byte
          target_bytes[:, pos - st_pos] = predicted_byte
          for c in range(constants.ALPHA_SIZE):
            input_bytes[c, : pos - st_pos + 1] = \
              input_bytes[c, 1 : pos - st_pos + 2]
            input_bytes[c, pos - st_pos + 1] = c
            target_bytes[c, : pos - st_pos] = \
              target_bytes[c, 1 : pos - st_pos + 1]
            target_bytes[c, pos - st_pos] = c

      cur_insert_idx = 0
      new_file_bytes = []
      for j in range(file_size):
        new_file_bytes.append(cur_bytes[j])
        if cur_insert_idx < self.pos_change \
          and j == mod_positions[cur_insert_idx]:
          for k in range(insert_times[cur_insert_idx]):
            new_file_bytes.append(insert_bytes[cur_insert_idx][k])
          cur_insert_idx += 1

      new_files_bytes.append(bytearray(new_file_bytes))

    return new_files_bytes
