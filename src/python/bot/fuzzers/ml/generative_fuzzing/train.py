# Copyright 2020 Google LLC
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
"""Train ml rnn model."""
from builtins import next, range, str

import math
import os
import sys
import time
import tensorflow as tf
from tensorflow import keras
import numpy as np

from bot.fuzzers.ml import constants
from bot.fuzzers.ml import config
from bot.fuzzers.ml import utils

from bot.fuzzers.ml.models.rnn_model import RNNModel
from bot.fuzzers.ml.models.gpt_model import GPTModel
from bot.fuzzers.ml.models.bert_model import BERTModel
from bot.fuzzers.ml.models.vae_model import VAEModel, vae_mask, vae_loss


def validate_paths(args):
    """Validate paths.

    Args:
        args: Parsed arguments.

    Returns:
        True if all paths are valid, False otherwise.
    """
    if not os.path.exists(args.input_dir):
        print(
            'Input directory {} does not exist'.format(args.input_dir),
            file=sys.stderr)
        return False

    if not os.path.exists(args.model_weight_dir):
        os.mkdir(args.model_weight_dir)

    if not os.path.exists(args.log_dir):
        os.mkdir(args.log_dir)

    if args.existing_model and not utils.validate_model_dir(args.existing_model):
        print(
            'Existing model {} does not exist'.format(args.existing_model),
            file=sys.stderr)
        return False

    return True


def main(args):
    """Main function to train the model.

    Args:
        args: Parsed arguments.

    Returns:
        Execution status defined by `constants.ExitCode`.
    """

    np.random.seed(0)

    # Validate paths.
    if not validate_paths(args):
        return constants.ExitCode.INVALID_PATH

    model_name = args.model_name
    diff_xy = not utils.model_is(model_name, "BERT") and not utils.model_is(model_name, "VAE")

    # Extract paths.
    input_dir = args.input_dir
    model_weight_dir = args.model_weight_dir
    log_dir = args.log_dir
    existing_model = args.existing_model

    # Extract train parameters.
    debug = args.debug
    validation = args.validation
    sliding_window = args.sliding_window

    # Extract model parameters.
    batch_size = args.batch_size
    hidden_state_size = args.hidden_state_size
    hidden_layer_number = args.hidden_layer_number
    learning_rate = args.learning_rate
    train_seqlen = args.train_seqlen


    # Split corpus for training and validation.
    # validation_text will be empty if validation is False
    code_text, validation_text, input_ranges = utils.read_data_files(
        input_dir, validation=validation)

    # Bail out if we don't have enough corpus for training.
    if len(code_text) < batch_size * train_seqlen + diff_xy:
        print(f"Corpus too small.", file=sys.stderr)
        return constants.ExitCode.CORPUS_TOO_SMALL

    # Get corpus files info. Will be used in debug mode to generate sample text.
    files_info_list = []
    if debug:
        files_info_list = utils.get_files_info(input_dir)
        assert files_info_list

    # Calculate validation batch size. It will be 0 if we choose not to validate.
    validation_batch_size = len(validation_text) // args.validation_seqlen

    # Display some stats on the data.
    epoch_size = len(code_text) // (batch_size * train_seqlen)
    utils.print_data_stats(len(code_text), len(validation_text), epoch_size)

    # Init Tensorboard stuff.
    # This will save Tensorboard information in folder specified in command line.
    # Two sets of data are saved so that you can compare training and
    # validation curves visually in Tensorboard.
    timestamp = str(math.trunc(time.time()))
    training_writer = tf.summary.create_file_writer(
        os.path.join(log_dir, timestamp + "-training"))
    validation_writer = tf.summary.create_file_writer(
        os.path.join(log_dir, timestamp + "-validation"))

    # For display: init the progress bar.
    step_size = batch_size * train_seqlen

    if utils.model_is(args.model_name, 'RNN'):
        model = RNNModel(
                    ALPHA_SIZE=constants.ALPHA_SIZE,
                    hidden_state_size=hidden_state_size,
                    hidden_layer_number=hidden_layer_number,
                    pkeep=args.dropout_pkeep,
                    batch_size=batch_size)
    elif utils.model_is(args.model_name, 'GPT'):
        model = GPTModel(
                    hidden_layer_number=hidden_layer_number,
                    d_model=constants.DEFAULT_GPT_D_MODEL,
                    num_heads=constants.DEFAULT_GPT_NUM_HEADS,
                    dff=hidden_state_size,
                    ALPHA_SIZE=constants.ALPHA_SIZE,
                    seq_len=train_seqlen,
                    pkeep=args.dropout_pkeep,
                    batch_size=batch_size)
    elif utils.model_is(args.model_name, 'BERT'):
        model = BERTModel(
                    hidden_layer_number=hidden_layer_number,
                    d_model=constants.DEFAULT_BERT_D_MODEL,
                    num_heads=constants.DEFAULT_BERT_NUM_HEADS,
                    dff=hidden_state_size,
                    seq_len=train_seqlen,
                    pkeep=args.dropout_pkeep,
                    batch_size=batch_size)
    elif utils.model_is(args.model_name, 'VAE'):
        model = VAEModel(
                    batch_size=batch_size,
                    seq_len=train_seqlen)
    else:
        print(f"No applicable model {args.model_name}.", file=sys.stderr)
        return constants.ExitCode.TENSORFLOW_ERROR

    model.build(input_shape=(batch_size, train_seqlen))

    # We continue training on exsiting model, or start with a new model.
    if existing_model:
        print(f"Continue training on existing model: {existing_model}")
        model.load_weights(existing_model)
    else:
        # Create a model with alphabet size, hidden state size,
        # hidden layer size, keep rate and batch size
        print("No existing model provided. Start training with a new model.")

    # Use Adam as default optimizer.
    optimizer = keras.optimizers.Adam(learning_rate=args.learning_rate)

    # Use SparseCategoricalCrossentropy as default loss function
    # compute the average loss for all outputs equally.
    loss = keras.losses.SparseCategoricalCrossentropy()

    # Num of bytes we have trained so far.
    num_of_bytes = 0

    # Compile the model.
    model.compile(optimizer=optimizer, loss=loss)

    # Record the sum of each epoch.
    # If the mean of epoch_loss_sum is going up, we stop training early.
    epoch_loss_sum = [0] * args.n_epochs

    # Training loop.
    for input_batch, expected_batch, epoch in utils.minibatch_sequencer(
            code_text,
            batch_size,
            args.train_seqlen,
            nb_epochs=args.n_epochs,
            rtn_diff_xy=diff_xy):
        model.reset_states()

        if utils.model_is(args.model_name, 'BERT'):
            input_batch, mask_pos = model.mask(input_batch)

        # Eager execution.
        with tf.GradientTape() as tape:
            prediction = model(input_batch, training=True)
            if utils.model_is(args.model_name, 'BERT_MASK'):
                y_true = np.array([expected_batch[pos[0], pos[1]] for pos in mask_pos])
                y_pred = tf.gather_nd(prediction, mask_pos)
                loss_value = loss(y_true, y_pred)
            elif utils.model_is(args.model_name, 'BERT_BATCH'):
                loss_value = loss(expected_batch, prediction)
            elif utils.model_is(args.model_name, 'BERT_FIRST'):
                y_true = np.array([expected_batch[pos[0], pos[1]] for pos in mask_pos])
                y_pred = tf.gather_nd(prediction, [(i, 0) for i in range(batch_size)])
                loss_value = loss(y_true, y_pred)
            elif utils.model_is(args.model_name, 'VAE'):
                loss_value = vae_loss(expected_batch, prediction[0], prediction[1], prediction[2])
            else:
                loss_value = loss(expected_batch, prediction)

        grads = tape.gradient(loss_value, model.trainable_variables)
        optimizer.apply_gradients(zip(grads, model.trainable_variables))

        # Update current epoch loss in epoch_loss_sum.
        epoch_loss_sum[epoch] += loss_value.numpy()

        # Update number of bytes that have been trained in total.
        num_of_bytes += step_size

        # Save a checkpoint every epoch.
        # Each checkpoint is a version of model.
        # If the loss value is going bad, we stop early
        # and don't store the weights in the last epoch.
        if num_of_bytes % (epoch_size * step_size) == 0:
            utils.save_weights(model, model_weight_dir, f"{args.model_name}_{timestamp}_epoch_{epoch + 1}")
            print(f"epoch {epoch + 1} loss sum = {epoch_loss_sum[epoch]}")
            # Compare the current sliding_window mean and the last sliding_window mean.
            # If the model is getting worse, we stop early.
            if epoch + 1 >= sliding_window * 2 and \
                np.mean(epoch_loss_sum[epoch + 1 - sliding_window:epoch + 1]) >= np.mean(epoch_loss_sum[epoch + 1 - 2 * sliding_window:epoch + 1 - sliding_window]):
                break
    argmin_epoch = np.argmin(epoch_loss_sum[:min(args.n_epochs, epoch + 1)])
    print(f"epoch {argmin_epoch + 1} has minimum loss_sum = {epoch_loss_sum[argmin_epoch]}")

    return constants.ExitCode.SUCCESS


if __name__ == '__main__':
    parsed_args = config.train_parse_args()
    sys.exit(main(parsed_args))
