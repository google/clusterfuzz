import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.bert_model import BERTModel

"""Generate inputs using BERT model and insert strategy.
We use m strategy and feed `seq_len` bytes with one byte masked to be predicted.
Use batch generation."""
class BERTBatchInsertGenerator:
    def __init__(self, hidden_layer_number, d_model, num_heads, dff, seq_len, pkeep, model_weights_path,
                    input_dir, pos_change, batch_size, temperature, insert_nums):
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
        self.insert_nums = insert_nums

        assert self.seq_len > 0, "sequence length must be greater than 0 in BERT model."
        assert self.pos_change > 0, "pos_change must be greater than 0 in BERT model."
        self.corpus_files_info = utils.get_files_info(input_dir, True)
        assert self.corpus_files_info, "Corpus not exists"

    def generate(self):
        file_bytes_list = []
        start_positions = []
        for i in range(self.batch_size):
            random_file_info = utils.random_element_from_list(self.corpus_files_info)
            file_size = random_file_info["file_size"]
            file_bytes_list.append(random_file_info["all_bytes"].copy())
            # Need to sample `pos_change` numbers from 0 to file_size - seq_len + 1.
            # Since there is one MASK byte in the sequence, we only need seq_len - 1 bytes for every window.
            if file_size - self.seq_len + 2 >= self.pos_change:
                st_positions = np.random.choice(file_size - self.seq_len + 2, self.pos_change, replace=False)
            else:
                st_positions = np.minimum(file_size - self.seq_len + 1, np.random.choice(file_size, self.pos_change, replace=False))
            start_positions.append(st_positions)

        input_bytes = np.zeros((self.batch_size, self.seq_len), dtype=np.int)
        mod_positions = np.zeros(self.batch_size, dtype=np.int)
        modify_positions = np.zeros((self.batch_size, self.pos_change), dtype=np.int)
        predictions = np.zeros((self.batch_size, self.pos_change, self.insert_nums), dtype=np.int)

        for j in range(self.pos_change):
            print(f"{j + 1}/{self.pos_change}", end='\r')

            for i in range(self.batch_size):
                st_idx = start_positions[i][j]
                mod_positions[i] = np.random.choice(self.seq_len - 1)
                modify_positions[i][j] = st_idx + mod_positions[i]
                # insert bytes right after modify_positions[i][j]
                input_bytes[i][:mod_positions[i] + 1] = file_bytes_list[i][st_idx : st_idx + mod_positions[i] + 1]
                input_bytes[i][mod_positions[i] + 1] = constants.BERT_MASK_VALUE
                input_bytes[i][mod_positions[i] + 2 :] = file_bytes_list[i][st_idx + mod_positions[i] + 1 : st_idx + self.seq_len - 1]
            
            for insert_idx in range(self.insert_nums):
                prediction = self.model(input_bytes, training=False)
                for i in range(self.batch_size):
                    input_bytes[i][:mod_positions[i]] = input_bytes[i][1 : mod_positions[i] + 1]
                    predicted_byte = utils.sample_from_probabilities(prediction[i][mod_positions[i] + 1].numpy())
                    predictions[i][j][insert_idx] = predicted_byte
                    input_bytes[i][mod_positions[i]] = predicted_byte

        new_files_bytes = []
        for i in range(self.batch_size):
            new_file_bytes = []
            pos_change_idx = 0
            pos_change_array = sorted(
                                    [(j, modify_positions[i][j]) for j in range(self.pos_change)],
                                    key=lambda x: (x[1], x[0]))
            for j in range(len(file_bytes_list[i])):
                new_file_bytes.append(file_bytes_list[i][j])
                while pos_change_idx < self.pos_change and j == pos_change_array[pos_change_idx][1]:
                    if pos_change_idx == 0 or pos_change_array[pos_change_idx-1][1] != pos_change_array[pos_change_idx][1]:
                        for insert_idx in range(self.insert_nums):
                            new_file_bytes.append(predictions[i][pos_change_array[pos_change_idx][0]][insert_idx])
                    pos_change_idx += 1
            assert pos_change_idx == self.pos_change, "error in monotonic insertion"
            new_files_bytes.append(bytearray(new_file_bytes))

        return new_files_bytes
