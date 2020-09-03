import numpy as np

from bot.fuzzers.ml import utils
from bot.fuzzers.ml import constants

from bot.fuzzers.ml.models.rnn_model import RNNModel

"""Generate inputs by random mutations.
Randomly replace some bytes.
pos_change cannot be 0."""

class RandomGenerator:
    def __init__(self, input_dir, pos_change, batch_size):
        self.pos_change = pos_change
        self.batch_size = batch_size
        assert self.pos_change != 0, "pos_change cannot be 0"

        self.corpus_files_info = utils.get_files_info(input_dir, pos_change != 0)
        assert self.corpus_files_info, "Corpus too small"

    def generate(self):
        new_files_bytes = []
        mod_positions = []
        for i in range(self.batch_size):
            random_file_info = utils.random_element_from_list(self.corpus_files_info)
            file_size = random_file_info["file_size"]
            new_files_bytes.append(random_file_info["all_bytes"].copy())
            if self.pos_change > 0:
                # Need to sample `pos_change` numbers from predict_window_size to file_size - 1
                mod_positions = np.random.choice(file_size, self.pos_change, replace=False)
            elif self.pos_change < 0:
                # Need to sample `file_size/(-pos_change)` numbers from 1 to file_size - 1
                mod_positions = np.random.choice(file_size, file_size // (-self.pos_change), replace=False)
            for j in range(len(mod_positions)):
                new_files_bytes[i][mod_positions[j]] = np.random.choice(constants.ALPHA_SIZE)
            new_files_bytes[i] = bytearray(new_files_bytes[i])

        return new_files_bytes
