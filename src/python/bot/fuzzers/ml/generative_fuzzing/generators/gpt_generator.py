import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.gpt_model import GPTModel

class GPTGenerator:
  """Generate inputs using GPT model.
  When pos_change < 0,
  we use mk strategy.
  When pos_change > 0,
  we use m strategy and feed previous `seq_len` bytes.
  Use batch generation."""
  def __init__(self, hidden_layer_number, d_model, num_heads, dff, alpha_size, seq_len, pkeep, model_weights_path,
                input_dir, pos_change, batch_size, temperature):
    self.model = GPTModel(
      hidden_layer_number=hidden_layer_number,
      d_model=d_model,
      num_heads=num_heads,
      dff=dff,
      ALPHA_SIZE=alpha_size,
      seq_len=seq_len,
      pkeep=pkeep,
      batch_size=batch_size,
      temperature=temperature)
    self.model.build(input_shape=(batch_size, seq_len))
    self.model.load_weights(model_weights_path)

    self.pos_change = pos_change
    self.batch_size = batch_size
    self.seq_len = seq_len

    assert pos_change > 0, "pos_change must be greater than 0 in GPT model."
    self.corpus_files_info = utils.get_files_info(input_dir, True)
    assert self.corpus_files_info, "Corpus not exists"

  def generate(self):
    new_files_bytes = []
    corpus_files_length = []
    modify_positions = []
    len_modify_positions = []
    for i in range(self.batch_size):
      random_file_info = utils.random_element_from_list(self.corpus_files_info)
      file_size = random_file_info["file_size"]
      new_files_bytes.append(random_file_info["all_bytes"].copy())
      corpus_files_length.append(file_size)
      # Need to sample `pos_change` numbers from seq_len to file_size - 1
      if file_size - self.seq_len >= self.pos_change:
        mod_positions = np.random.choice(file_size - self.seq_len, self.pos_change, replace=False) + self.seq_len
      else:
        mod_positions = np.random.choice(file_size - 1, self.pos_change, replace=False) + 1
      modify_positions.append(sorted(mod_positions))
      len_modify_positions.append(len(mod_positions))

    input_bytes = np.zeros((self.batch_size, self.seq_len), dtype=np.int)

    for j in range(self.pos_change):
      print(f"{j + 1}/{self.pos_change}", end='\r')

      for i in range(self.batch_size):
        for offset in range(self.seq_len):
          input_bytes[i][offset] = new_files_bytes[i][max(0, modify_positions[i][j] - self.seq_len + offset)]
      prediction = self.model(input_bytes, training=False)

      for i in range(self.batch_size):
        predicted_byte = utils.sample_from_probabilities(prediction[i][-1].numpy())
        new_files_bytes[i][modify_positions[i][j]] = predicted_byte

    for i in range(self.batch_size):
      new_files_bytes[i] = bytearray(new_files_bytes[i])

    return new_files_bytes
