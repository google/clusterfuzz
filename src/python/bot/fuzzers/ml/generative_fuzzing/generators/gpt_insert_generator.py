import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.gpt_model import GPTModel

class GPTInsertGenerator:
  """Generate inputs using GPT model and insert strategy.
  We use m strategy and feed previous `seq_len` bytes to the model to predict the next byte to insert in the sequence.
  Use batch generation."""
  def __init__(self, hidden_layer_number, d_model, num_heads, dff, alpha_size, seq_len, pkeep, model_weights_path,
                input_dir, pos_change, batch_size, temperature, insert_nums):
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
    self.insert_nums = insert_nums

    assert self.seq_len > 0, "sequence length must be greater than 0 in GPT model."
    assert self.pos_change > 0, "pos_change must be greater than 0 in GPT model."
    self.corpus_files_info = utils.get_files_info(input_dir, True)
    assert self.corpus_files_info, "Corpus not exists"

  def generate(self):
    file_bytes_list = []
    modify_positions = []
    len_modify_positions = []
    for i in range(self.batch_size):
      random_file_info = utils.random_element_from_list(self.corpus_files_info)
      file_size = random_file_info["file_size"]
      file_bytes_list.append(random_file_info["all_bytes"].copy())
      # Need to sample `pos_change` numbers from seq_len to file_size - 1
      if file_size - self.seq_len >= self.pos_change:
        mod_positions = np.random.choice(file_size - self.seq_len, self.pos_change, replace=False) + self.seq_len
      else:
        mod_positions = np.maximum(self.seq_len, np.random.choice(file_size - 1, self.pos_change, replace=False) + 1)
      modify_positions.append(sorted(mod_positions))
      len_modify_positions.append(len(mod_positions))

    input_bytes = np.zeros((self.batch_size, self.seq_len), dtype=np.int)
    original_bytes = np.zeros(self.batch_size, dtype=np.int)
    predictions = np.zeros((self.batch_size, self.pos_change, self.insert_nums), dtype=np.int)
    truncate_len = np.zeros((self.batch_size, self.pos_change), dtype=np.int)

    for j in range(self.pos_change):
      print(f"{j + 1}/{self.pos_change}", end='\r')

      for i in range(self.batch_size):
        original_bytes[i] = file_bytes_list[i][modify_positions[i][j]]
        truncate_len[i][j] = self.insert_nums
        for offset in range(self.seq_len):
          input_bytes[i][offset] = file_bytes_list[i][modify_positions[i][j] - self.seq_len + offset]

      for insert_idx in range(self.insert_nums):
        prediction = self.model(input_bytes, training=False)
        input_bytes[:, : -1] = input_bytes[:, 1:]
        for i in range(self.batch_size):
          predicted_byte = utils.sample_from_probabilities(prediction[i][-1].numpy())
          predictions[i][j] = input_bytes[i, -1] = predicted_byte
          if truncate_len[i][j] == self.insert_nums and \
            prediction[i][-1][original_bytes[i]] >= prediction[i][-1][predicted_byte]:
            truncate_len[i][j] = insert_idx

    new_files_bytes = []
    for i in range(self.batch_size):
      new_file_bytes = []
      pos_change_idx = 0
      for j in range(len(file_bytes_list[i])):
        while pos_change_idx < self.pos_change and j == modify_positions[i][pos_change_idx]:
          if pos_change_idx > 0 or modify_positions[i][pos_change_idx-1] != modify_positions[i][pos_change_idx]:
            for insert_idx in range(truncate_len[i][pos_change_idx]):
              new_file_bytes.append(predictions[i][pos_change_idx][insert_idx])
          pos_change_idx += 1
        new_file_bytes.append(file_bytes_list[i][j])
      assert pos_change_idx == self.pos_change, "error in monotonic insertion"
      new_files_bytes.append(bytearray(new_file_bytes))

    return new_files_bytes
