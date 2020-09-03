import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.bert_model import BERTModel

"""Generate inputs using BERT model.
we use m strategy and feed `seq_len` bytes.
Use batch generation."""
class BERTMaskGenerator:
    def __init__(self, hidden_layer_number, d_model, num_heads, dff, seq_len, pkeep, model_weights_path,
                    input_dir, pos_change, batch_size, temperature):
        self.model = BERTModel(
                        hidden_layer_number=hidden_layer_number,
                        d_model=d_model,
                        num_heads=num_heads,
                        dff=dff,
                        seq_len=seq_len,
                        pkeep=pkeep,
                        batch_size=batch_size,
                        temperature=temperature)
        self.model.build(input_shape=(batch_size, seq_len))
        self.model.load_weights(model_weights_path)

        self.pos_change = pos_change
        self.batch_size = batch_size
        self.seq_len = seq_len
        assert self.seq_len > 0, "sequence length must be greater than 0 in BERT model."

        assert pos_change > 0, "pos_change must be greater than zero in BERT model."
        self.corpus_files_info = utils.get_files_info(input_dir, True)
        assert self.corpus_files_info, "Corpus not exists"

    def generate(self):
        new_files_bytes = []
        corpus_files_length = []
        start_positions = []
        for i in range(self.batch_size):
            random_file_info = utils.random_element_from_list(self.corpus_files_info)
            file_size = random_file_info["file_size"]
            new_files_bytes.append(random_file_info["all_bytes"].copy())
            corpus_files_length.append(file_size)
            # Need to sample `pos_change` numbers from 0 to file_size - seq_len
            if file_size - self.seq_len >= self.pos_change:
                st_positions = np.random.choice(file_size - self.seq_len + 1, self.pos_change, replace=False)
            else:
                st_positions = np.minimum(file_size - self.seq_len, np.random.choice(file_size, self.pos_change, replace=False))
            start_positions.append(st_positions)

        input_bytes = np.zeros((self.batch_size, self.seq_len), dtype=np.int)

        for j in range(self.pos_change):
            print(f"{j + 1}/{self.pos_change}", end='\r')

            mod_positions = []
            for i in range(self.batch_size):
                input_bytes[i] = new_files_bytes[i][start_positions[i][j] : start_positions[i][j] + self.seq_len]
                mod_pos = np.random.choice(self.seq_len)
                mod_positions.append(mod_pos)
                input_bytes[i][mod_pos] = constants.BERT_MASK_VALUE

            prediction = self.model(input_bytes, training=False)

            for i in range(self.batch_size):
                predicted_byte = utils.sample_from_probabilities(prediction[i][mod_positions[i]])
                new_files_bytes[i][start_positions[i][j] + mod_positions[i]] = predicted_byte

        for i in range(self.batch_size):
            new_files_bytes[i] = bytearray(new_files_bytes[i])

        return new_files_bytes
