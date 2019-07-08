# Recurrent Neural Network model for inputs generation

## About RNN model

RNN is a well-tested model for natural language processing, such as speech
recognition, machine translation, etc. Now we are trying to build a similar
model to generate fuzzing inputs.

Specifically, the model will be trained on minimized corpus, and then generate
similar inputs which, as we hope, can trigger new coverage, find new path, and
ultimately find unforeseen bugs for targets.

This model was inspired by and implemented based on [tensorflow-rnn-shakespeare]
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
Note that if model or log directory doesn't exist, the script will create it
with the path specified.

If you want to continue training on an existing model, use the following flag.
Make sure that model parameters must match. If not, please reset parameters.
```
  --existing-model=<model path, e.g. saved/rnn_checkpoint_1529539983-600>
```

Use optional arguments to reset model parameters. You can find default settings
in `constants.py`.
```
  --batch-size=<reset batch size in training> \
  --hidden-state-size=<reset hidden state size for LSTM cell> \
  --hidden-layer-size=<reset hidden layer size for LSTM model> \
  --learning-rate=<reset learning rate> \
  --dropout-pkeep=<reset keep rate for dropout>
```
Use optional arguments below to control training modes. `debug` mode will
detailedly print training process, including text and files being trained
in each step. `validation` mode will periodically do valication and print
the loss and accuracy of the latest model.
```
  --debug \
  --validation
```

4. The training script `train.py` is set up to save training and validation
data as `Tensorboard summaries` in the `log` directory. They can be visualised
with Tensorboard. After training, you can see the dashboard with following
command.
```
tensorboard --logdir=<log directory>
```

5. Use script `generate.py` to generate a number of inputs:
```
python generate.py \
  --input-dir=<input directory> \
  --output-dir=<directory to save generated inputs> \
  --model-path=<the model to use, e.g. saved/rnn_checkpoint_1529539983-600> \
  --count=<number of inputs to generate>
```
Note that if output directory doesn't exist, the script will create it with
the path specified.

Use optional arguments to reset model parameters for generation. You can find
default value in `constants.py`. Note that the parameter set here must match
the model specified above, otherwise generation cannot work.
```
  --hidden-state-size=<reset hidden state size for LSTM cell> \
  --hidden-layer-size=<reset hidden layer size for LSTM model> \
```

[RNN-generated Shakespeare play]: https://github.com/martin-gorner/tensorflow-rnn-shakespeare
[TensorFlow]: https://www.tensorflow.org/install
[go/ml-fuzzing]: https://goto.google.com/ml-fuzzing
[tensorflow-rnn-shakespeare]: https://github.com/martin-gorner/tensorflow-rnn-shakespeare
