import numpy as np
import tensorflow as tf
from tensorflow.keras import layers

from bot.fuzzers.ml import constants


def get_angles(pos, i, d_model):
  """Compute the transformed angles with given formula from
  https://www.tensorflow.org/tutorials/text/transformer#positional_encoding.
  """
  angle_rates = 1 / np.power(10000, (2 * (i // 2)) / np.float32(d_model))
  return pos * angle_rates


def positional_encoding(positions, d_model):
  """Create positional encoding for (seq_len, d_model)

  Args:
    positions: length of the sequence.
    d_model: dimension of the model.

  Return:
    A positional encoding matrix with shape (1, positions, d_model).
  """
  angle_rads = get_angles(np.arange(positions)[:, np.newaxis],
                          np.arange(d_model)[np.newaxis, :],
                          d_model)
  angle_rads[:, 0::2] = np.sin(angle_rads[:, 0::2])
  angle_rads[:, 1::2] = np.cos(angle_rads[:, 1::2])

  pos_encoding = angle_rads[np.newaxis, ...]
  return tf.cast(pos_encoding, dtype=tf.float32)


def scaled_dot_product_attention(q, k, v, mask):
  """Calculate the attention weights.
  q, k, v must have same leading dimensions.
  k, v must have same seq_len. i.e. seq_len_k == seq_len_v
    
  Args:
    q: query matrix with shape (..., seq_len_q, dimension)
    k: key matrix with shape   (..., seq_len_k, dimension)
    v: value matrix with shape (..., seq_len_v, dimension_v)
    mask: Float tensor with shape broadcastable 
          to (..., seq_len_q, seq_len_k). Defaults to None.
      
  Returns:
    output, attention_weights
  """
  matmul_qk = tf.matmul(q, k, transpose_b=True)

  # scale matmul_qk
  dk = tf.cast(tf.shape(k)[-1], tf.float32)
  scaled_attention_logits = matmul_qk / tf.math.sqrt(dk)

  # add the mask to the scaled tensor.
  if mask is not None:
    scaled_attention_logits += (mask * -1e9)

  # software is normalized on the last axis (seq_len_k) so that the scores
  # add up to 1.
  attention_weights = tf.nn.softmax(scaled_attention_logits, axis=-1) # (..., seq_len_q, seq_len_k)

  output = tf.matmul(attention_weights, v) # (..., seq_len_q, depth_v)

  return output, attention_weights


class MultiHeadAttention(layers.Layer):
  def __init__(self, d_model, num_heads):
    assert d_model % num_heads == 0

    super(MultiHeadAttention, self).__init__()

    self.num_heads = num_heads
    self.d_model = d_model
    self.depth = d_model // num_heads

    self.wq = layers.Dense(d_model)
    self.wk = layers.Dense(d_model)
    self.wv = layers.Dense(d_model)

    self.dense = layers.Dense(d_model)

  def split_heads(self, x, batch_size):
    """Split the last dimension into (num_heads, depth).
    Transpose the result such that the shape is (batch_size, num_heads, seq_len, depth)
    """
    x = tf.reshape(x, (batch_size, -1, self.num_heads, self.depth))
    return tf.transpose(x, perm=[0, 2, 1, 3])

  def call(self, v, k, q, mask = None):
    batch_size = tf.shape(q)[0]

    q = self.wq(q) # (batch_size, seq_len, d_model)
    k = self.wk(k) # (batch_size, seq_len, d_model)
    v = self.wv(v) # (batch_size, seq_len, d_model)

    q = self.split_heads(q, batch_size) # (batch_size, num_heads, seq_len_q, depth)
    k = self.split_heads(k, batch_size) # (batch_size, num_heads, seq_len_k, depth)
    v = self.split_heads(v, batch_size) # (batch_size, num_heads, seq_len_v, depth)

    # scaled_attention.shape == (batch_size, num_heads, seq_len_q, depth)
    # attention_weights.shape == (batch_size, num_heads, seq_len_q, seq_len_k)
    scaled_attn, attn_weights = scaled_dot_product_attention(q, k, v, mask)

    # transform back to (batch_size, seq_len_q, num_heads, depth)
    scaled_attn = tf.transpose(scaled_attn, perm=[0, 2, 1, 3])

    # concat_attn.shape == (batch_size, seq_len_q, d_model)
    concat_attn = tf.reshape(scaled_attn, (batch_size, -1, self.d_model))

    # output.shape == (batch_size, seq_len_q, d_model)
    output = self.dense(concat_attn)

    return output, attn_weights


def point_wise_feed_forward_network(d_model, dff):
  return tf.keras.Sequential([
    layers.Dense(dff, activation="relu"), # (batch_size, seq_len, dff)
    layers.Dense(d_model) # (batch_size, seq_len, d_model)
  ])


class EncoderLayer(layers.Layer):
  def __init__(self, d_model, num_heads, dff, rate=.1):
    super(EncoderLayer, self).__init__()

    self.mha = MultiHeadAttention(d_model, num_heads)

    self.ffn = point_wise_feed_forward_network(d_model, dff)

    self.layernorm1 = layers.LayerNormalization(epsilon=1e-6)
    self.layernorm2 = layers.LayerNormalization(epsilon=1e-6)

    self.dropout1 = layers.Dropout(rate)
    self.dropout2 = layers.Dropout(rate)

  def call(self, x, training):
    """x.shape == (batch_size, input_seq_len, d_model)"""
    # (batch_size, target_seq_len, d_model)
    attn_output, attn_weights_block = self.mha(x, x, x)
    attn_output = self.dropout1(attn_output, training=training)
    output1 = self.layernorm1(attn_output + x)

    # (batch_size, target_seq_len, d_model)
    ffn_output = self.ffn(output1)
    ffn_output = self.dropout2(ffn_output, training=training)
    output2 = self.layernorm2(ffn_output + x)

    return output2, attn_weights_block


class BERTModel(tf.keras.Model):
  def __init__(self, hidden_layer_number, d_model, num_heads, dff, seq_len, pkeep, batch_size, temperature = 1.0, seed = 0):
    """Initialize BERT model

    Args:
      hidden_layer_number: number of hidden layers
      d_model: dimension of the each input
      num_heads: number of attention heads
      dff: size of FC layer
      seq_len: length of the input sequence
      pkeep: keeping rate
      batch_size: batch size
      temperature: when prediction, it stands for
                   whether we want the probability distribution to be close to uniform or argmax
      seed: graph-level default random seed
    """
    super(BERTModel, self).__init__()

    # Set graph-level random seed, so any random sequence generated in this
    # graph is repeatable. It could also be removed or set as other seed.
    tf.random.set_seed(seed)

    self.d_model = d_model
    self.num_layers = hidden_layer_number
    self.seq_len = seq_len
    self.batch_size = batch_size
    self.temperature = temperature

    self.pos_encoding = positional_encoding(self.seq_len, self.d_model)

    self.embedding = layers.Embedding(
      constants.BERT_ALPHA_SIZE,
      self.d_model,
      input_shape=[self.batch_size, None])
    self.dropout = layers.Dropout(1 - pkeep)

    self.enc_layers = []
    for i in range(self.num_layers):
        self.enc_layers.append(EncoderLayer(
          d_model=self.d_model,
          num_heads=num_heads,
          dff=dff,
          rate=1-pkeep))

    self.linear = layers.Dense(constants.ALPHA_SIZE)
    self.softmax = layers.Softmax()


  def mask(self, x):
    output = x.copy()
    mask_pos = []
    for i in range(self.batch_size):
      pos = np.random.choice(self.seq_len)
      output[i, pos] = constants.BERT_MASK_VALUE
      mask_pos.append((i, pos))
    return output, mask_pos


  def call(self, x, training):
    x = self.embedding(x)
    x *= tf.math.sqrt(tf.cast(self.d_model, tf.float32))
    x += self.pos_encoding

    x = self.dropout(x)

    attn_weights = dict()
    for i in range(self.num_layers):
      x, blk = self.enc_layers[i](x, training)
      attn_weights[f"encoder_layer{i + 1}_block"] = blk

    x = self.linear(x)
    x = self.softmax(x / self.temperature)

    return x
