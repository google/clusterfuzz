from tensorflow import keras
import numpy as np
from scipy.special import softmax

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.rnn_model import RNNModel

class RNNScoreGenerator:
  """Generate inputs using RNN model.
  In this strategy, we are using RNN model as a score function.
  For example we want to replace a3 in  [a1 a2 a3 a4 a5 a6],
  we will use [a1 a2 0-255 a4 a5] as input and [a2 0-255 a4 a5 a6] as output
  and compute the log likelihood.
  After we get 256 log likelihood, we use softmax result as probability for each outcome
  and sample the byte based on this probability."""
  def __init__(self, hidden_layer_number, hidden_state_size, pkeep, model_weights_path,
                input_dir, pos_change, predict_window_size, batch_size, temperature):
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

    assert self.pos_change > 0, "pos_change must be greater than 0 in RNN score strategy."
    self.corpus_files_info = utils.get_files_info(input_dir, pos_change != 0)
    assert self.corpus_files_info, "Corpus not exists"

  def generate(self):
    new_files_bytes = []
    loss = keras.losses.SparseCategoricalCrossentropy(reduction=keras.losses.Reduction.NONE)
    for i in range(self.batch_size):
      print(f"file {i + 1}/{self.batch_size}", end='\r')
      random_file_info = utils.random_element_from_list(self.corpus_files_info)
      first_byte, file_size = random_file_info["first_byte"], random_file_info["file_size"]
      cur_bytes = random_file_info["all_bytes"].copy()
      mod_positions = np.random.choice(file_size - 1, self.pos_change, replace=False) + 1
      for pos in mod_positions:
        st_pos = max(0, pos - np.random.choice(self.predict_window_size))
        ed_pos = min(file_size, st_pos + self.predict_window_size)
        st_pos = ed_pos - self.predict_window_size
        target_bytes = np.array([cur_bytes[st_pos:ed_pos] for i in range(256)])
        for i in range(256):
          target_bytes[i, pos - st_pos] = i
        input_bytes = np.copy(target_bytes)
        input_bytes[:, 1:] = target_bytes[:, :-1]
        if st_pos > 0:
          input_bytes[:, 0] = cur_bytes[st_pos - 1]
        else:
          input_bytes[:, 0] = 0

        self.model.reset_states()
        predictions = self.model(input_bytes)

        loss_value = loss(target_bytes, predictions).numpy().sum(axis=1)
        prob = softmax(-loss_value)
        # sum(prob) might be a little bit greater than 1
        # so we need to adjust it
        prob /= np.sum(prob) + 1e-6
        cur_bytes[pos] = np.argmax(np.random.multinomial(1, prob))
      new_files_bytes.append(cur_bytes)

    for i in range(self.batch_size):
      new_files_bytes[i] = bytearray(new_files_bytes[i])

    return new_files_bytes
