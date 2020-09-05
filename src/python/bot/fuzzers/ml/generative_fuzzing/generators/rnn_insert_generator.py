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
"""RNN insert generator."""
import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.rnn_model import RNNModel

class RNNInsertGenerator:
  """Generate inputs using RNN model and insert strategy.
  pos_change and predict_window_size must be > 0.
  Insert `insert_nums` bytes at every position."""
  def __init__(self, hidden_layer_number, hidden_state_size,
               pkeep, model_weights_path, input_dir, pos_change,
               predict_window_size, batch_size, temperature, insert_nums):
    self.model = RNNModel(
        constants.ALPHA_SIZE,
        hidden_state_size=hidden_state_size,
        hidden_layer_number=hidden_layer_number,
        pkeep=pkeep,
        batch_size=batch_size,
        temperature=temperature)
    self.model.build(input_shape=(batch_size, None))
    self.model.load_weights(model_weights_path)

    self.pos_change = pos_change
    self.predict_window_size = predict_window_size
    self.batch_size = batch_size
    self.insert_nums = insert_nums

    assert self.pos_change > 0, \
      "pos_change must be > 0 in insert strategy"
    assert self.predict_window_size > 0, \
      "predict_window_size must be > 0 in insert strategy"

    self.corpus_files_info = utils.get_files_info(input_dir, True)
    assert self.corpus_files_info, "Corpus not exists"

  def generate(self):
    """Main part for generation."""
    modify_positions = []
    len_modify_positions = []
    file_bytes_list = []
    for i in range(self.batch_size):
      random_file_info = utils.random_element_from_list(self.corpus_files_info)
      file_size = random_file_info["file_size"]
      file_bytes_list.append(random_file_info["all_bytes"])
      if self.pos_change + self.predict_window_size > file_size:
        mod_positions = np.random.choice(
            file_size - 1, self.pos_change, replace=False) + 1
      else:
        mod_positions = np.random.choice(
            file_size - self.predict_window_size,
            self.pos_change,
            replace=False) + self.predict_window_size
      modify_positions.append(sorted(mod_positions))
      len_modify_positions.append(len(mod_positions))

    previous_bytes = np.zeros(
        (self.batch_size, self.predict_window_size),
        dtype=np.int)
    input_bytes = np.zeros((self.batch_size, 1), dtype=np.int)

    original_byte = np.zeros(self.batch_size, dtype=np.int)
    truncate_len = np.zeros(
        (self.batch_size, self.pos_change),
        dtype=np.int)

    predictions = np.zeros(
        (self.batch_size, self.pos_change, self.insert_nums),
        dtype=np.int)
    for j in range(self.pos_change):
      print(f"{j + 1}/{self.pos_change}", end='\r')

      self.model.reset_states()

      for i in range(self.batch_size):
        for offset in range(self.predict_window_size):
          previous_bytes[i][offset] = \
            file_bytes_list[i][max(0, modify_positions[i][j] - \
              self.predict_window_size + offset)]
        original_byte[i] = file_bytes_list[i][modify_positions[i][j]]

      prediction = self.model(previous_bytes, training=False)
      for i in range(self.batch_size):
        predict_byte = utils.sample_from_probabilities(
            prediction[i][-1].numpy())
        input_bytes[i][0] = predictions[i][j][0] = predict_byte
        if prediction[i][-1][original_byte[i]] > \
          prediction[i][-1][predict_byte]:
          truncate_len[i][j] = 0
        else:
          truncate_len[i][j] = self.insert_nums

      for insert_idx in range(1, self.insert_nums):
        # prediction shape is (batch_size, 1, alpha_size)
        prediction = self.model(input_bytes)
        for i in range(self.batch_size):
          predict_byte = utils.sample_from_probabilities(
              prediction[i].numpy())
          input_bytes[i][0] = predictions[i][j][insert_idx] = predict_byte
          if truncate_len[i][j] == self.insert_nums and \
            prediction[i][0][original_byte[i]] > \
              prediction[i][0][predict_byte]:
            truncate_len[i][j] = insert_idx

    new_files_bytes = []
    for i in range(self.batch_size):
      new_file_bytes = []
      cur_idx = 0
      for j in range(len(file_bytes_list[i])):
        if cur_idx < len_modify_positions[i] and \
          j == modify_positions[i][cur_idx]:
          for insert_idx in range(truncate_len[i][cur_idx]):
            new_file_bytes.append(predictions[i][cur_idx][insert_idx])
          cur_idx += 1
        new_file_bytes.append(file_bytes_list[i][j])
      new_files_bytes.append(bytearray(new_file_bytes))

    return new_files_bytes
