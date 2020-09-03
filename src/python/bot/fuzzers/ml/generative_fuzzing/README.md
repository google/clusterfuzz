# ML models for inputs generation

## Overview

In this project, there are four generative models for inputs generation.

Four models are RNN, GPT, BERT and VAE model. They are all well-tested models in
natural language processing and other Machine Learning fields. We are trying to
use them to build generative models to generate fuzzing inputs.

Specifically, the models will be trained on minimized corpus, and then generate
similar inputs which, as we hope, can trigger new coverage, find new path, and
ultimately find unforeseen bugs for targets.

These model were inspired by and implemented based on [tensorflow-rnn-shakespeare]
project.

*If you work at Google, you can read more about this model in [go/ml-fuzzing]
design doc.*

## Usage

1. Make sure that [TensorFlow] has been installed on your machine.

2. Prepare corpus directory. Corpus can be downloaded from GCS buckets.

3. Run the following command to train the model.
```
python train.py \
  --input-dir=<corpus directory> \
  --model-dir=<saved model directory> \
  --log-dir=<log directory>
```
Note that if the model or log directory doesn't exist, the script will create it
with the path specified. However, input directory is mandatory since the models are
learning from files provided in this directory.

The default model is RNN model. If you want to run other models, GPT for example,
please use flag `--model-name=GPT`. For BERT model, there are three different methods
to compute loss:
(1) loss over the whole batch.
(2) loss at the masked position.
(3) loss at the first position.
You can run with flag `--model-name=BERT_BATCH`, `--model-name=BERT_MASK` and
`--model-name=BERT_FIRST` respectively for each of the above strategies.

All valid model names are listed below:
```
(1) RNN
(2) GPT
(3) BERT_MASK
(4) BERT_FIRST
(5) BERT_BATCH
(6) VAE
```

If you want to continue training with an existing model weights, use the following flag.
Make sure that the model parameters must match. If not, please reset parameters.
```
  --existing-model=<model path, e.g. checkpoint/rnn_1592944901_150000.h5>
```

If you want to change the chunk size of each input batch, you can use flag
`--train-seqlen=<chunk size you want>` to train different lengths of input.

Use optional arguments to reset model parameters and training parameters.
You can find default settings in `config.py`.
```
  --n-epochs=<maximum number of epochs you want to train on training data> \
  --sliding-window=<the window size of epochs to check for early stop during training> \
  --batch-size=<reset batch size in training> \
  --hidden-state-size=<reset hidden state size for LSTM cell> \
  --hidden-layer-size=<reset hidden layer size for LSTM model> \
  --learning-rate=<reset learning rate> \
  --dropout-pkeep=<reset keep rate for dropout>
```

4. Use script `generate.py` to generate a number of inputs:
```
python generate.py \
  --input-dir=<input directory> \
  --output-dir=<directory to save generated inputs> \
  --model-path=<the model to use, e.g. saved/rnn_1592944901_150000.h5> \
  --count=<number of inputs to generate>
```
Note that if output directory doesn't exist, the script will create it with
the path specified.

Similar to `train.py`, the code is using RNN model by default. If you want to
use other models, please use `--model-name=<model name>` to specify the model.

All valid model names for generation are listed below:
```
(1) RNN
(2) RNN_INSERT
(3) RNN_SCORE
(4) RNN_SCORE_INSERT
(5) RNN_MK
(6) GPT
(7) GPT_INSERT
(8) BERT_MASK
(9) BERT_FIRST
(10) BERT_BATCH
(11) BERT_BATCH_INSERT
(12) VAE
(13) RANDOM
(14) RANDOM_DELETE
```

IMPORTANT: `--predict-window-size` is critical for inference. For most situations,
it should be the same as the `--train-seqlen` parameter. Only for RNN model, if you
want to generate from scratch, it can be ignored or set to 0. It's set to 30 by default.

For insert strategy, please use flags `--pos-change=<number of positions you want to insert>`
and `--insert-nums=<number of bytes inserted at each insert position>` with the corresponding
model name. `pos_change` is set to 20 by default.

Use optional arguments to reset model parameters for generation. You can find
default value in `config.py`. Note that the parameter set here must match
the model specified above, otherwise generation cannot work.
```
  --hidden-state-size=<reset hidden state size for GRU cell> \
  --hidden-layer-size=<reset hidden layer size for GRU model> \
```

5. For future models modification, you can use conf.yml to set all above parameters.
If the same parameter is provided both in command line and conf.yml, the commond line one will
have higher priority and the one in conf.yml will be ignored.

6. For future model implementation, you can add new model in `models` directory,  import he model name in `train.py` and maybe specify the way to compute the loss. For future generator implementation, you can add new generator in `generators` directory and import the generator in `generate.py`.

## A sample setting 

For example, if we want to train `GPT` model on libpng target with sequence length equal to 64 and train for 500 epochs, we can run the  command below.

```
python train.py \
  --model-name=GPT \
  --input-dir=/home/libpng/default_seeds \
  --model-dir=/home/libpng/model_weights \
  --log-dir=/home/libpng/log \
  --train-seqlen=64 \
  --n-epochs=500
```

Assume that the best model weights is `gpt_300.h5` and we want to generate 1000 inferences, mutate 20 bytes for each file and save all files in the directory `gpt_1000_m20`, we can run the command below.

```
python generate.py \
  --model-name=GPT \
  --input-dir=/home/libpng/default_seeds \
  --output-dir=/home/libpng/gpt_1000_m20 \
  --model-path=/home/libpng/model_weights/gpt_300.h5 \
  --count=1000 \
  --predict-window-size=64
```

The `--predict-window-size` during inference should be equal to `--train-seqlen` during training.

[RNN-generated Shakespeare play]: https://github.com/martin-gorner/tensorflow-rnn-shakespeare
[TensorFlow]: https://www.tensorflow.org/install
[go/ml-fuzzing]: https://goto.google.com/ml-fuzzing
