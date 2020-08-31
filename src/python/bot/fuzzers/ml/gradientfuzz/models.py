# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""libFuzzer Neural Smoothing - Model Architectures."""

__author__ = 'Ryan Cao (ryancao@google.com)'

import tensorflow.keras as keras
import tensorflow.keras.layers as layers


def make_model_from_layer(layer_class,
                          output_dim,
                          input_shape,
                          hidden_layer_dim=4096):
  """
    Sad hack we have to use to get around tf's graph generation and not being
    able to successfully subclass `keras.Model`. When subclassing keras.Model,
    the model is inherently unconnected, so `model.inputs` and `model.outputs`
    can't be used.

    Args:
        layer_class (keras.layers.Layer): Layer encapsulation of the actual
          model.
        output_dim (int): Number of branches as specified by dataset.
        input_shape (tuple): Input length as specified by dataset. (N.B.
            This won't matter for models that take in variable-length inputs.)
        hidden_layer_dim (int): Number of nodes in intermediate layer.
            (NEUZZ ONLY!)

    Returns:
        An uninitialized connected keras.Model object.
    """
  internal = layer_class(output_dim, input_shape, hidden_layer_dim)
  model_input = keras.Input(input_shape)
  model_output = internal(model_input)
  model = keras.Model(inputs=model_input, outputs=model_output)
  return model


class NEUZZModelOneHidden(keras.layers.Layer):
  """
    See page 7 of https://arxiv.org/pdf/1807.05620.pdf.
    """

  def __init__(self, output_dim, input_shape, hidden_layer_dim=4096):
    super(NEUZZModelOneHidden, self).__init__()
    self._hidden_layer_dim = hidden_layer_dim
    self._input_shape = input_shape
    self._output_dim = output_dim
    self._first_hidden_linear = layers.Dense(
        self._hidden_layer_dim, activation='relu')
    self._output_layer = layers.Dense(self._output_dim, activation='sigmoid')

  def call(self, inputs, **kwargs):
    x = self._first_hidden_linear(inputs)
    x = self._output_layer(x)
    return x


class NEUZZModelThreeHidden(keras.layers.Layer):
  """
  Three-hidden-layers feedforward model.
  """

  def __init__(self, output_dim, input_shape, hidden_layer_dim=4096):
    super(NEUZZModelThreeHidden, self).__init__()
    self._hidden_layer_dim = hidden_layer_dim
    self._input_shape = input_shape
    self._output_dim = output_dim
    self._first_hidden_linear = layers.Dense(
        self._hidden_layer_dim, activation='relu')
    self._second_hidden_linear = layers.Dense(
        self._hidden_layer_dim, activation='relu')
    self._third_hidden_linear = layers.Dense(
        self._hidden_layer_dim, activation='relu')
    self._output_layer = layers.Dense(self._output_dim, activation='sigmoid')

  def call(self, inputs, **kwargs):
    x = self._first_hidden_linear(inputs)
    x = self._second_hidden_linear(x)
    x = self._third_hidden_linear(x)
    x = self._output_layer(x)
    return x


class SimpleLSTMModel(keras.layers.Layer):
  """
  Takes inputs in one byte at a time via LSTM.
  """

  def __init__(self, output_dim, _, num_units=512):
    super(SimpleLSTMModel, self).__init__()
    self._output_dim = output_dim
    self._lstm_layer = keras.layers.LSTM(units=num_units)
    self._output_layer = layers.Dense(self._output_dim, activation='sigmoid')

  def call(self, inputs, **kwargs):
    x = self._lstm_layer(inputs)
    x = self._output_layer(x)
    return x


class SimpleGRUModel(keras.layers.Layer):
  """
  Takes inputs in one byte at a time via GRU.
  """

  def __init__(self, output_dim, _, num_units=512):
    super(SimpleGRUModel, self).__init__()
    self._output_dim = output_dim
    self._gru_layer = keras.layers.GRU(units=num_units)
    self._output_layer = layers.Dense(self._output_dim, activation='sigmoid')

  def call(self, inputs, **kwargs):
    x = self._gru_layer(inputs)
    x = self._output_layer(x)
    return x
