import sys
import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.vae_model import VAEModel

class VAEGenerator:
  """Generate inputs using VAE model.
  we use m strategy and mask one byte among `seq_len` bytes to predict the corresponding byte.
  Use batch generation."""
  def __init__(self, batch_size, seq_len, model_weights_path, pos_change, input_dir, temperature):
    self.model = VAEModel(
      batch_size=batch_size,
      seq_len=seq_len,
      temperature=temperature)
    self.model.build(input_shape=(batch_size, seq_len))
    try:
      self.model.load_weights(model_weights_path)
    except Exception:
      print('Incompatible model weights. Please make sure the parameters are matched with training ones.')
      sys.exit(0)

    self.batch_size = batch_size
    self.seq_len = seq_len
    self.pos_change = pos_change

    assert pos_change > 0, "pos_change must be greater than zero in VAE model."
    self.corpus_files_info = utils.get_files_info(input_dir, True)
    assert self.corpus_files_info, "Corpus not exists"

  def generate(self):
    new_files_bytes = []
    start_positions = []
    for i in range(self.batch_size):
      while True:
        random_file_info = utils.random_element_from_list(self.corpus_files_info)
        file_size = random_file_info["file_size"]
        if file_size >= self.seq_len:
          break
      new_files_bytes.append(random_file_info["all_bytes"].copy())
      # Need to sample `pos_change` numbers from 0 to file_size - seq_len
      if file_size - self.seq_len >= self.pos_change:
        st_positions = np.random.choice(file_size - self.seq_len + 1, self.pos_change, replace=False)
      else:
        st_positions = np.minimum(np.maximum(0, file_size - self.seq_len), np.random.choice(file_size, self.pos_change, replace=False))
      start_positions.append(st_positions)

    input_bytes = np.zeros((self.batch_size, self.seq_len), dtype=np.int)

    for j in range(self.pos_change):
      print(f"{j + 1}/{self.pos_change}", end='\r')

      for i in range(self.batch_size):
        input_bytes[i] = new_files_bytes[i][start_positions[i][j] : start_positions[i][j] + self.seq_len]

      prediction = self.model(input_bytes, training=False)

      for i in range(self.batch_size):
        mod_pos = np.random.choice(self.seq_len, 1)[0]
        predicted_byte = utils.sample_from_probabilities(prediction[0].numpy()[i, mod_pos])
        new_files_bytes[i][start_positions[i][j] + mod_pos] = predicted_byte

    for i in range(self.batch_size):
      new_files_bytes[i] = bytearray(new_files_bytes[i])

    return new_files_bytes
