import numpy as np
import tensorflow as tf
from tensorflow.keras import layers
import tensorflow.keras.backend as K

from bot.fuzzers.ml import constants


def vae_mask(inp):
    x = inp.copy()
    y = []
    for i in range(x.shape[0]):
        pos = np.random.choice(x.shape[1], 1)[0]
        y.append([x[i, pos]])
        x[i, pos] = constants.MASK_VALUE
    y = np.array(y)
    return x, y


def vae_loss(y_true, y_pred, mu, log_var):
    rc_loss = tf.keras.losses.sparse_categorical_crossentropy(y_true, y_pred)
    rc_loss = K.sum(rc_loss)

    kl_div = .5 * (K.exp(log_var) + K.square(mu) - 1 - log_var)
    kl_div = K.sum(kl_div)

    # average loss for token
    return (rc_loss + kl_div) / (mu.shape[0] * mu.shape[1])


class VAEModel(tf.keras.Model):
    def __init__(self, batch_size, seq_len, temperature = 1.0, seed = 0):
        """Initialize VAE model

        Args:
            ALPHA_SIZE: size of the alphabet that we work with
            batch_size: size of a mini batch
            temperature: when prediction, it stands for
                         whether we want the probability distribution to be close to uniform or argmax
            seed: graph-level default random seed
        """
        super(VAEModel, self).__init__()

        # Set graph-level random seed, so any random sequence generated in this
        # graph is repeatable. It could also be removed or set as other seed.
        tf.random.set_seed(seed)

        self.batch_size = batch_size
        self.seq_len = seq_len
        self.temperature = temperature

        self.embedding = layers.Embedding(
                            constants.ALPHA_SIZE,
                            constants.EMBEDDING_DIM,
                            input_shape=[batch_size, seq_len])

        # Flatten the shape
        # from (batch_size, seq_len, ALPHA_SIZE) to (batch_size, seq_len * ALPHA_SIZE).
        self.enc_reshape = layers.Reshape((-1,))

        # Encoder
        self.enc_fc1 = layers.Dense(768, activation="relu")
        self.enc_fc21 = layers.Dense(384)
        self.enc_fc22 = layers.Dense(384)

        # Decoder
        self.dec_fc1 = layers.Dense(768, activation="relu")
        self.dec_fc2 = layers.Dense(seq_len * constants.ALPHA_SIZE)

        # Reshape from (batch_size, seq_len * ALPHA_SIZE) to (batch_size, seq_len, ALPHA_SIZE)
        self.dec_reshape = layers.Reshape((seq_len, constants.ALPHA_SIZE))

        self.softmax = layers.Softmax()

    def encoder(self, x):
        h = self.enc_fc1(x)

        mu = self.enc_fc21(h)
        log_var = self.enc_fc22(h)

        return mu, log_var

    def decoder(self, z):
        x = self.dec_fc1(z)
        x = self.dec_fc2(x)
        return x

    def reparameterize(self, mu, log_var):
        eps = tf.random.normal(log_var.shape)
        std = tf.exp(log_var) ** 0.5
        z = mu + std * eps
        return z

    def call(self, x, training):
        # (batch_size, seq_len) -> (batch_size, seq_len * ALPHA_SIZE)
        x = self.embedding(x)
        x = self.enc_reshape(x)

        # (batch_size, seq_len * ALPHA_SIZE) -> (batch_size, z_dim=384)
        mu, log_var = self.encoder(x)

        # reparameterization trick
        z = self.reparameterize(mu, log_var)
        pred = self.decoder(z)

        # Output shape is (batch_size, seq_len, ALPHA_SIZE)
        pred = self.dec_reshape(pred)

        if training:
            pred = self.softmax(pred)
        else:
            pred = self.softmax(pred / self.temperature)

        return pred, mu, log_var
