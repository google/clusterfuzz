import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.rnn_model import RNNModel

"""Generate inputs using RNN model.
When pos_change < 0 or predict_window_size == 0,
we generate from scratch.
When pos_change > 0,
we feed previous `predict_window` bytes and use batch generation."""

class RNNGenerator:
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

        if self.pos_change < 0:
            self.predict_window_size = 0

        self.corpus_files_info = utils.get_files_info(input_dir, pos_change != 0)
        assert self.corpus_files_info, "Corpus not exists"

    def generate(self):
        new_files_bytes = []
        corpus_files_length = []
        modify_positions = []
        mod_positions = []
        file_list = []
        # cur_modify_pos_index accelerates the predicting process.
        # We can check if the current position needs to be replaced by predict value or not
        # within O(1) instead of O(# of modify positions).
        cur_modify_pos_index = []
        len_modify_positions = []
        for i in range(self.batch_size):
            random_file_info = utils.random_element_from_list(self.corpus_files_info)
            first_byte, file_size = random_file_info["first_byte"], random_file_info["file_size"]
            if self.predict_window_size == 0:
                file_size = min(file_size, constants.DEFAULT_MAX_LENGTH)
                new_files_bytes.append([first_byte])
                file_list.append(random_file_info)
            else:
                new_files_bytes.append(random_file_info["all_bytes"].copy())
            corpus_files_length.append(file_size)
            if self.pos_change > 0:
                # Need to sample `pos_change` numbers from predict_window_size to file_size - 1
                if file_size - self.predict_window_size >= self.pos_change:
                    mod_positions = np.random.choice(file_size - self.predict_window_size, self.pos_change, replace=False) + self.predict_window_size
                else:
                    mod_positions = np.random.choice(file_size - 1, self.pos_change, replace=False) + 1
            elif self.pos_change < 0:
                # Need to sample `file_size/(-pos_change)` numbers from 1 to file_size - 1
                mod_positions = np.random.choice(file_size - 1, file_size // (-self.pos_change), replace=False) + 1
            modify_positions.append(sorted(mod_positions))
            len_modify_positions.append(len(mod_positions))
            cur_modify_pos_index.append(0)

        if self.predict_window_size == 0:
            max_length = min(constants.DEFAULT_MAX_LENGTH, max(corpus_files_length))
            input_bytes = np.array(new_files_bytes)

            # Reset hidden states each time to generate new inputs, so that
            # different rounds will not interfere with each other.
            self.model.reset_states()

            for pos in range(max_length - 1):
                print(f"{pos}/{max_length - 1}", end='\r')

                prediction = self.model(input_bytes, training=False)

                for i in range(self.batch_size):
                    if self.pos_change == 0 or \
                        (cur_modify_pos_index[i] < len_modify_positions[i] and pos + 1 == modify_positions[i][cur_modify_pos_index[i]]) or \
                        pos + 1 >= corpus_files_length[i]:
                        if cur_modify_pos_index[i] < len_modify_positions[i] and pos + 1 == modify_positions[i][cur_modify_pos_index[i]]:
                            cur_modify_pos_index[i] += 1
                        predicted_byte = utils.sample_from_probabilities(prediction[i].numpy())
                    else:
                        predicted_byte = file_list[i]["all_bytes"][pos + 1]
                    new_files_bytes[i].append(predicted_byte)
                    input_bytes[i][0] = predicted_byte
        else:
            pos_change = len_modify_positions[0]
            max_length = max(corpus_files_length)
            input_bytes = np.zeros((self.batch_size, self.predict_window_size), dtype=np.int)

            for j in range(pos_change):
                print(f"{j + 1}/{pos_change}", end='\r')

                self.model.reset_states()

                for i in range(self.batch_size):
                    for offset in range(self.predict_window_size):
                        input_bytes[i][offset] = new_files_bytes[i][max(0, modify_positions[i][j] - self.predict_window_size + offset)]
                prediction = self.model(input_bytes, training=False)

                for i in range(self.batch_size):
                    predicted_byte = utils.sample_from_probabilities(prediction[i][-1].numpy())
                    new_files_bytes[i][modify_positions[i][j]] = predicted_byte

        # If we feed the whole sequence to the model,
        # the inference file might be larger than the original file.
        # So the length of new file is the minimal value of max_length and the original file length.
        for i in range(self.batch_size):
            new_file_length = min(max_length, corpus_files_length[i])
            new_files_bytes[i] = bytearray(new_files_bytes[i][:new_file_length])

        return new_files_bytes
