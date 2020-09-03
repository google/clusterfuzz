import numpy as np
import tensorflow as tf
from tensorflow.keras import layers

from bot.fuzzers.ml import constants

class RNNModel(tf.keras.Model):
    def __init__(self, ALPHA_SIZE, hidden_state_size, hidden_layer_number, pkeep, batch_size, temperature = 1.0, seed = 0):
        """Initialize RNN model

        Args:
            ALPHA_SIZE: size of the alphabet that we work with
            hidden_state_size: size of each hidden layer
            hidden_layer_number: number of hidden layers
            pkeep: keeping rate
            batch_size: size of a mini batch
            temperature: when prediction, it stands for
                         whether we want the probability distribution to be close to uniform or argmax
            seed: graph-level default random seed
        """
        super(RNNModel, self).__init__()

        # Set graph-level random seed, so any random sequence generated in this
        # graph is repeatable. It could also be removed or set as other seed.
        tf.random.set_seed(seed)

        self.num_layers = hidden_layer_number
        self.temperature = temperature

        self.embedding = layers.Embedding(
                            ALPHA_SIZE,
                            constants.EMBEDDING_DIM,
                            input_shape=[batch_size, None])
        self.gru_layers = []
        for i in range(self.num_layers):
            self.gru_layers.append(layers.GRU(
                                    hidden_state_size,
                                    dropout=1-pkeep,
                                    return_sequences=True,
                                    stateful=True,
                                    recurrent_initializer="glorot_uniform"))
        self.linear = layers.Dense(ALPHA_SIZE)
        self.softmax = layers.Softmax()

    def call(self, x, training):
        x = self.embedding(x)

        for i in range(self.num_layers):
            x = self.gru_layers[i](x)

        x = self.linear(x)
        if training:
            x = self.softmax(x)
        else:
            x = self.softmax(x / self.temperature)

        return x
