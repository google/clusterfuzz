import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.rnn_model import RNNModel

class RNNMKGenerator:
  """Generate inputs using RNN model and mk strategy.
  pos_change and predict_window_size must be > 0.
  Mutate `min(200, log(file_size) * pos_change)` number of bytes."""
  def __init__(self, hidden_layer_number, hidden_state_size, pkeep, model_weights_path,
                input_dir, pos_change, predict_window_size, batch_size, temperature):
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

    assert self.pos_change > 0, "pos_change must be > 0 in MK strategy"
    assert self.predict_window_size > 0, "predict_window_size must be > 0 in MK strategy"

    self.corpus_files_info = utils.get_files_info(input_dir, True)
    assert self.corpus_files_info, "Corpus not exists"

  def generate(self):
    new_files_bytes = []
    modify_positions = []
    len_modify_positions = []
    for i in range(self.batch_size):
      random_file_info = utils.random_element_from_list(self.corpus_files_info)
      file_size = random_file_info["file_size"]
      new_files_bytes.append(random_file_info["all_bytes"].copy())
      # Need to sample `min(200, int(log(file_size) * self.pos_change))` numbers
      num_of_mutate = min(200, int(np.log(file_size) * self.pos_change))
      if self.predict_window_size + num_of_mutate >= file_size:
        mod_positions = np.random.choice(file_size - 1, num_of_mutate, replace=False) + 1
      else:
        mod_positions = np.random.choice(file_size - self.predict_window_size, num_of_mutate, replace=False) + self.predict_window_size
      modify_positions.append(sorted(mod_positions))
      len_modify_positions.append(len(mod_positions))

    pos_change = max(len_modify_positions)
    input_bytes = np.zeros((self.batch_size, self.predict_window_size), dtype=np.int)

    for j in range(pos_change):
      print(f"{j + 1}/{pos_change}", end='\r')

      self.model.reset_states()

      for i in range(self.batch_size):
        for offset in range(self.predict_window_size):
          if j < len_modify_positions[i]:
            input_bytes[i][offset] = new_files_bytes[i][max(0, modify_positions[i][j] - self.predict_window_size + offset)]
      prediction = self.model(input_bytes, training=False)

      for i in range(self.batch_size):
        predicted_byte = utils.sample_from_probabilities(prediction[i][-1].numpy())
        if j < len_modify_positions[i]:
          new_files_bytes[i][modify_positions[i][j]] = predicted_byte

    for i in range(self.batch_size):
      new_files_bytes[i] = bytearray(new_files_bytes[i])

    return new_files_bytes
