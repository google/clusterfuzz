# Training suggestions
#
# Training only:
#     Leave all the parameters as they are in constants.py.
#     Disable validation to run a bit faster (set validation=False).
#     You can follow progress in Tensorboard: tensorboard --logdir=log
#
# Training and experimenting (default):
#     Keep validation enabled.
#     You can now play with the parameters and follow the effects in
#     Tensorboard.
#     A good choice of parameters ensures that the testing and validation
#     curves stay close. To see the curves drift apart ("overfitting") try
#     to use an insufficient amount of training data.

import argparse
import yaml
from os import path

from bot.fuzzers.ml import utils

# Default model name.
DEFAULT_MODEL_NAME = 'rnn'

# Batch size for train.
DEFAULT_TRAIN_BATCH_SIZE = 100

# Dropout probability (keep rate).
DEFAULT_TRAIN_DROPOUT_PKEEP = 0.8

# Num of chars to be trained in one batch.
DEFAULT_RNN_TRAIN_SEQLEN = 30
DEFAULT_GPT_TRAIN_SEQLEN = 30
DEFAULT_BERT_TRAIN_SEQLEN = 30
DEFAULT_VAE_TRAIN_SEQLEN = 30

# Size of internal states in a neural cell.
DEFAULT_RNN_HIDDEN_STATE_SIZE = 512
DEFAULT_GPT_HIDDEN_STATE_SIZE = 512
DEFAULT_BERT_HIDDEN_STATE_SIZE = 512

# Number of hidden layers.
DEFAULT_RNN_HIDDEN_LAYER_NUMBER = 3
DEFAULT_GPT_HIDDEN_LAYER_NUMBER = 6
DEFAULT_BERT_HIDDEN_LAYER_NUMBER = 6

# Learning rate.
DEFAULT_LEARNING_RATE = 0.001

# Num of chars to be validated in one batch.
DEFAULT_VALIDATION_SEQLEN = 1024

# Num of train epochs.
DEFAULT_TRAIN_EPOCHS = 100

# Num of epoch loss to decide early stop.
DEFAULT_SLIDING_WINDOW = 5


def get_model_parameters(args, model):
  """Get model parameters for both train.py and generate.py

  Returns:
      Args with model parameters.
  """
  if args.model_name is None:
    args.model_name = model.get("model_name")
  if args.model_name is None:
    args.model_name = DEFAULT_MODEL_NAME

  if args.hidden_state_size is None:
    args.hidden_state_size = model.get("hidden_state_size")
  # It could still be empty
  if args.hidden_state_size is None:
    if utils.model_is(args.model_name, "RNN"):
      args.hidden_state_size = DEFAULT_RNN_HIDDEN_STATE_SIZE
    elif utils.model_is(args.model_name, "GPT"):
      args.hidden_state_size = DEFAULT_GPT_HIDDEN_STATE_SIZE
    elif utils.model_is(args.model_name, "BERT"):
      args.hidden_state_size = DEFAULT_BERT_HIDDEN_STATE_SIZE

  if args.hidden_layer_number is None:
    args.hidden_layer_number = model.get("hidden_layer_number")
  if args.hidden_layer_number is None:
    if utils.model_is(args.model_name, "RNN"):
      args.hidden_layer_number = DEFAULT_RNN_HIDDEN_LAYER_NUMBER
    elif utils.model_is(args.model_name, "GPT"):
      args.hidden_layer_number = DEFAULT_GPT_HIDDEN_LAYER_NUMBER
    elif utils.model_is(args.model_name, "BERT"):
      args.hidden_layer_number = DEFAULT_BERT_HIDDEN_LAYER_NUMBER

  if args.dropout_pkeep is None:
    args.dropout_pkeep = model.get("pkeep")
  if args.dropout_pkeep is None:
    args.dropout_pkeep = DEFAULT_TRAIN_DROPOUT_PKEEP

  return args


def yaml_train_parse(args):
  """Parse yaml arguments for train.py.

  Args:
      args: Parsed command line arguments

  Returns:
      All arguments from command line and yaml configuration file.
      If arguments are included in both, command line one will be adopted.
  """
  if args.config is None or not path.exists(args.config):
    return args

  f = open(args.config)
  yml_dict = yaml.load(f.read(), Loader=yaml.FullLoader)
  args = get_model_parameters(args, yml_dict.get("model"))
  general = yml_dict.get("general")
  hyperparameters = yml_dict.get("hyperparameters")
  assert isinstance(general, dict), "general in conf.yaml is required"
  assert isinstance(hyperparameters,
                    dict), "hyperparameters in conf.yaml is required"
  f.close()

  if args.input_dir is None:
    args.input_dir = general.get("input_dir")
  if args.model_weight_dir is None:
    args.model_weight_dir = general.get("model_weight_dir")
  if args.log_dir is None:
    args.log_dir = general.get("log_dir")

  assert args.input_dir, "Input directory is required"
  assert args.model_weight_dir, "Model weight directory is required"
  assert args.log_dir, "Log directory is requied"

  if args.debug is None:
    args.debug = general.get("debug", False)

  if args.existing_model is None:
    args.existing_model = general.get("existing_model")

  if args.validation is None:
    args.validation = general.get("validation")
  if args.validation is None:
    args.validation = False

  if args.sliding_window is None:
    args.sliding_window = general.get("sliding_window")
  if args.sliding_window is None:
    args.sliding_window = DEFAULT_SLIDING_WINDOW

  # Set values for hyperparameters.
  by_default = hyperparameters.get("all_default")
  if by_default is None:
    by_default = True

  if args.batch_size is None:
    args.batch_size = DEFAULT_TRAIN_BATCH_SIZE if by_default \
     else hyperparameters.get("batch_size")
  # Case for no --batch-size argument, by_default is False and argument is empty
  if args.batch_size is None:
    args.batch_size = DEFAULT_TRAIN_BATCH_SIZE

  if args.learning_rate is None:
    args.learning_rate = DEFAULT_LEARNING_RATE if by_default \
      else hyperparameters.get("learning_rate")
  if args.learning_rate is None:
    args.learning_rate = DEFAULT_LEARNING_RATE

  if args.train_seqlen is None:
    args.train_seqlen = None if by_default \
      else hyperparameters.get("train_seqlen")
  if args.train_seqlen is None:
    if utils.model_is(args.model_name, 'RNN'):
      args.train_seqlen = DEFAULT_RNN_TRAIN_SEQLEN
    elif utils.model_is(args.model_name, 'GPT'):
      args.train_seqlen = DEFAULT_GPT_TRAIN_SEQLEN
    elif utils.model_is(args.model_name, 'BERT'):
      args.train_seqlen = DEFAULT_BERT_TRAIN_SEQLEN
    elif utils.model_is(args.model_name, 'VAE'):
      args.train_seqlen = DEFAULT_VAE_TRAIN_SEQLEN

  args.validation_seqlen = DEFAULT_VALIDATION_SEQLEN if by_default \
    else hyperparameters.get("validation_seqlen")
  if args.validation_seqlen is None:
    args.validation_seqlen = DEFAULT_VALIDATION_SEQLEN

  if args.n_epochs is None:
    args.n_epochs = DEFAULT_TRAIN_EPOCHS if by_default \
      else hyperparameters.get("n_epochs")
  if args.n_epochs is None:
    args.n_epochs = DEFAULT_TRAIN_EPOCHS

  return args


def train_parse_args():
  """Parse command line arguments.

  Returns:
    Parsed arguement object.
  """
  parser = argparse.ArgumentParser("Training model on existing testcases")

  parser.add_argument(
      '-c',
      '--config',
      help='Configuration file path',
      dest='config',
      default='conf.yml')

  parser.add_argument('--input-dir', help='Input folder path')
  parser.add_argument('--log-dir', help='Log folder path')
  parser.add_argument('--model-weight-dir', help='Path to save model weights')

  parser.add_argument('--model-name', help='Model name', default=None)

  # Optional arguments: model parameters and additional flags.
  parser.add_argument('--batch-size', help='Batch size', type=int)
  parser.add_argument(
      '--debug',
      help='Print training progress',
      action='store_true',
      default=None)
  parser.add_argument(
      '--sliding-window',
      help='The window size to check if train loss is still decreasing',
      type=int)
  parser.add_argument('--n-epochs', help='Number of train epochs', type=int)
  parser.add_argument(
      '--dropout-pkeep', help='Dropout probability (keep rate)', type=float)
  parser.add_argument(
      '--existing-model', help='Continue training on existing model')
  parser.add_argument(
      '--train-seqlen', help='Length of train sequence', type=int)
  parser.add_argument(
      '--hidden-state-size', help='Hidden state size of LSTM cell', type=int)
  parser.add_argument(
      '--hidden-layer-number',
      help='Hidden layer number of LSTM model',
      type=int)
  parser.add_argument('--learning-rate', help='Learning rate', type=float)
  parser.add_argument(
      '--validation',
      help='Print validation stats during training',
      action='store_true',
      default=None)

  return yaml_train_parse(parser.parse_args())


# Generate the seed input from scratch by default.
DEFAULT_POS_CHANGE = 20

# Reset batch_size for generation: generate multiple inputs in each run.
DEFAULT_GENERATE_BATCH_SIZE = 50

# The parameter to decide
# whether the prediction distribution close to uniform or argmax.
DEFAULT_TEMPERATURE = 1.0

# If 0, we feed the whole sequence to the model to generate inference.
# If non 0, we feed the number of prefix bytes to the model
# to generate inference.
DEFAULT_PREDICT_WINDOW_SIZE = 30

# The number of insertions in insert strategy.
DEFAULT_INSERT_NUMS = 5


def yaml_generate_parse(args):
  """Parse yaml  arguments for generate.py.

  Args:
    args: Parsed command line arguments

  Returns:
    All arguments from command line and yaml configuration file.
    Command line is prioritized.
  """
  if args.config is None or not path.exists(args.config):
    return args

  f = open(args.config)
  yml_dict = yaml.load(f.read(), Loader=yaml.FullLoader)
  args = get_model_parameters(args, yml_dict.get("model"))
  generate = yml_dict.get("generate")
  assert isinstance(generate, dict), "genearte in conf.yaml is required"
  f.close()

  if args.input_dir is None:
    args.input_dir = generate.get("input_dir")
  if args.output_dir is None:
    args.output_dir = generate.get("output_dir")
  if args.model_weights_path is None:
    args.model_weights_path = generate.get("model_weights_path")
  if args.count is None:
    args.count = generate.get("count")

  assert args.input_dir, "Input directory is required"
  assert args.output_dir, "Output directory is required"
  assert args.model_weights_path, "Model weights path is required"
  assert args.count, "count is required"

  if args.pos_change is None:
    args.pos_change = generate.get("pos_change")
  if args.pos_change is None:
    args.pos_change = DEFAULT_POS_CHANGE

  if args.predict_window_size is None:
    args.predict_window_size = generate.get("predict_window_size")
  if args.predict_window_size is None:
    args.predict_window_size = DEFAULT_PREDICT_WINDOW_SIZE

  args.generate_batch_size = generate.get("generate_batch_size")
  if args.generate_batch_size is None:
    args.generate_batch_size = DEFAULT_GENERATE_BATCH_SIZE

  if args.temperature is None:
    args.temperature = generate.get("temperature")
  if args.temperature is None:
    args.temperature = DEFAULT_TEMPERATURE

  if args.insert_nums is None:
    args.insert_nums = generate.get("insert_nums")
  if args.insert_nums is None:
    args.insert_nums = DEFAULT_INSERT_NUMS

  return args


def generate_parse_args(batch_generation=False):
  """Parse command line arguments.

  Returns:
    Parsed arguement object.
  """
  parser = argparse.ArgumentParser(
      'Generating testcases using the model trained with train.py script.')

  parser.add_argument(
      '-c',
      '--config',
      help='Configuration file path',
      dest='config',
      default='conf.yml')

  parser.add_argument('--input-dir', help='Input folder path')
  parser.add_argument('--output-dir', help='Output folder path')
  parser.add_argument('--model-weights-path', help='Model weights path')
  parser.add_argument('--model-name', help='Model name', default=None)
  parser.add_argument(
      '--pos-change',
      help='Number of positions to change. Set to 0 if starting from scratch',
      type=int)
  parser.add_argument(
      '--count', help='Number of similar inputs to generate', type=int)
  parser.add_argument(
      "--predict-window-size", help="Size of perdict window", type=int)
  parser.add_argument(
      '--dropout-pkeep', help='Dropout probability (keep rate)', type=float)
  parser.add_argument(
      '--hidden-state-size', help='Hidden state size of LSTM cell', type=int)
  parser.add_argument(
      '--hidden-layer-number',
      help='Hidden layer number of LSTM model',
      type=int)
  parser.add_argument(
      '--temperature',
      help='Parameter to decide" \
        "whether the model is close to uniform or argmax',
      type=float)
  parser.add_argument(
      '--insert-nums', help='Number of insertions in insert strategy', type=int)

  return yaml_generate_parse(parser.parse_args())
