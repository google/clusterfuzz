# GradientFuzz

- [Introduction](#introduction)
- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting_started)
- [Summary of Files](#file_summary)
- [Sample File Tree](#file_tree)

<a name="introduction"/>

## Introduction
GradientFuzz is a libFuzzer accessory with the following features: 

- Training deep neural nets to predict fuzz target branch coverage.
- Using network gradients to propose critical locations for mutation.

Generated critical locations can be used directly by libFuzzer and other fuzzing engines to enhance coverage and fuzzing efficiency. 

<a name="installation"/>

## Installation

#### libFuzzer

- libFuzzer can be installed from the [LLVM official site](https://llvm.org/docs/LibFuzzer.html).

#### Python 3

- Python 3.6+ can be downloaded from the [Python official site](https://www.python.org/downloads/). 

#### Repository + Dependencies

- The source code can be downloaded via:

```
git clone https://github.com/googleinterns/clusterfuzz-fuzzers.git
cd clusterfuzz_fuzzers/ryancao_clusterfuzz_ml_fuzzer
```

- To install dependencies within a [Python virtual environment](https://docs.python.org/3/tutorial/venv.html):

```
python3 -m venv gradient_fuzzer_env
source gradient_fuzzer_env/bin/activate
pip3 install -r requirements.txt
```

<a name="prerequisites"/>

## Prerequisites

#### Fuzz Target
- You will first have to compile a fuzz target with the latest version of libFuzzer (in particular, one which allows the use of the `-print_full_coverage=1` flag). 
- An easy example of this would be to clone the [oss-fuzz](https://github.com/google/oss-fuzz) repository and build one of the sample fuzz targets (recommended for ease of build: [zlib](https://github.com/google/oss-fuzz/tree/master/projects/zlib)) with libFuzzer.

#### Sample Corpus
- You will also need a reasonably-sized sample corpus for that fuzz target. This can either be generated from scratch (simply by running the compiled fuzz target binary for a couple hours) or via the [oss-fuzz corpora page](https://google.github.io/oss-fuzz/advanced-topics/corpora/).

---

We assume from here on out that you have a working `[/path/to/compiled/fuzz-target]` which accepts a `-print_full_coverage=1` flag and a `[/path/to/seed/corpus/directory]` with a reasonable (at least several hundred; the more the better) number of inputs.

<a name="getting_started"/>

## Getting Started

#### Preprocessing

- To generate inputs and labels for training, use the following command (use `python3 libfuzzer_to_numpy.py -h` for all options):

```
python3 libfuzzer_to_numpy.py --input-dir [/path/to/seed/corpus/directory] \
			      --fuzz-target-binary [/path/to/compiled/fuzz-target] \
			      --dataset-name [dataset-name] \
			      --cutoff-percentile [95]
```

- This runs the compiled fuzz target binary on all files under `/path/to/input/dir`, generates coverage information for each input, and creates the following subtree (see [Sample File Tree](#file_tree) below):

```
data/
└── [dataset-name]/
    ├── inputs/
    └── labels/
```

- The `inputs/` and `labels/` directories store `.npy` files ready to be loaded by the training script.
- It also generates a couple of basic plots (saved under `data/[dataset-name]`) detailing your dataset's input length and branch coverage proportion distributions.

---

- **NOTE**: Some corpora have wild distributions of input lengths. Check the plots to see whether you need to truncate some longer inputs -- not doing so could make your model exponentially larger!
- **NOTE**: Padding is ALWAYS necessary for feedforward models. Do not switch padding off for any currently implemented model!

#### Training

- To train your model, use the following command (again, invoke with `-h` flag for all options):

```
python3 train.py --run-name [run-name] \
		 --dataset [dataset-name] \
		 --num-hidden [256] \
		 --neuzz-config
```

- This creates a new run with the specified run name (with a small addendum to signal the use of `--neuzz-config`) as follows:

```
models/
└── neuzz_one_hidden/
    └── [run-name]/
        └── tensorboard/
            ├── train/
            └── validation/
```

- To see the training history on tensorboard, use:

 ```tensorboard --logdir=models/neuzz_one_hidden/[run-name]```.
 
- You should get a final `bitmap_acc` of at least 95% or so, and a final `neuzz_jaccard_acc` of at least 70%. If not, try retraining over more epochs, lowering your batch size, or generating more inputs.
 
---
 
- **NOTE**: To manually specify architecture, epochs, optimizer, learning rate, and other hyperparameters, omit the `--neuzz-config` flag and specify manually (e.g. `--lr 1e-3`).
- **NOTE**: Models are saved every epoch the metric `neuzz_jaccard_acc` increases. If training is interrupted for any reason, resume using `python3 train.py --run-name [run-name]` (no need to specify other parameters; the training script will find and load the last saved model from that run).

#### Critical Location Generation

- To use a trained model to generate critical locations for a corpus (doesn't have to be the same as your training set! The corpus inputs **must** be in `.npy` form, however, and must be inputs to the **same** fuzz target trained on), invoke the following command:

```
python3 gradient_gen_critical_locs.py --run-name [run-name] \
				      --path-to-seeds [data/[dataset-name]/inputs] \
				      --path-to-lengths [data/[dataset-name]/input_lengths.json] \
				      --generation-name [gen-name] \
				      --gradient-gen-method [neuzz_random_branches] \
				      --num-output-locs [5] \
				      --top-k [100]
```

- Invoke `python3 gradient_gen_critical_locs.py -h` for a full explanation of the arguments.
- This runs your trained model `run-name` on the seed files and produces a critical locations file for each seed file, generating the following subtree:

```
generated/
└── [gen-name]/
    └── gradients/
```

- Critical locations are indices into the input file, ordered from largest to smallest in terms of gradient component with the largest absolute value.
  - The gradient of a single output branch *b_i* with respect to all *n* input bytes is an *n*-dimensional vector *v*.
  - The components of *v* correspond to how much *b_i*'s predicted value under the current model changes with respect to increasing/decreasing each input byte.
  - The largest (absolute value) components of *v* thus correspond to input bytes with the highest chance of influencing a coverage change to *b_i* in the actual binary, making those locations "critical" mutation spots.

---

**Note**: The directory name `gradients/` is actually a misnomer. Indeed, no gradients are ever saved; rather, critical locations as determined by gradients (as described above) are saved in decreasing order of potency.

#### Mutation Generation

- To use the critical location files to generate mutations, invoke the following (`-h` for all flags):

```
python3 gen_mutations.py --generation-name [gen-name] \
			 --path-to-lengths [data/[dataset-name]/input_lengths.json] \
			 --mutation-gen-method [simple_random] \
			 --mutation-name [mutation-name]
```

- This picks the simplest mutation strategy of taking a random subset of critical locations, sampling a uniform byte from [0, 255] to write to each critical location, and writes each mutated input to file.
- Mutations are saved under the `mutations/[mutation-name]` directory, as follows:

```
generated/
└── [gen-name]/
    ├── gradients/
    └── mutations/
	└── [mutation-name]/
```

- Mutated inputs are saved in raw binary format, ready to be fed into libFuzzer!

---

- **NOTE**: Invoking the script with `--mutation-gen-method neuzz_mutation` uses a truncated version of the mutation strategy performed in [NEUZZ](https://github.com/Dongdongshe/neuzz/blob/2c7179557a491266ca1478e5f8c431d0b69d3e3a/neuzz.c#L1155). Truncation is necessary as writing to C arrays, processing via native AFL, and only writing to file if new coverage is generated is orders of magnitude faster than writing every new mutated input to a file in Python. The recommended method for generating mutations is `--mutation-gen-method limited_neighborhood`.

<a name="file_summary"/>

## Summary of Files
#### Preprocessing
| Filename        					 | Description |
| ------------- | ------------- |
| `libfuzzer_to_numpy.py` | Converts raw inputs into an `np.ndarray` of bytes. Runs libFuzzer-compiled fuzz target binary on inputs and processes output coverage into indicator `np.ndarray`. |
| `plot_dataset_lengths.py`     | Plots dataset input lengths distribution. |
| `count_covered_branches.py`  | Plots proportion of branch coverage distribution.|
| `plot_utils.py` | Helper function for producing/saving plots. |

#### Training
| Filename | Description |
| -------- | ----------- |
| `data_utils.py` | Defines the dataset object used for training/validation. Uses outputs from `libfuzzer_to_numpy.py`. |
| `models.py` | Defines model architectures. |
| `model_utils.py` | Defines training settings (optimizer, metrics, callbacks). |
| `train.py` | Loads new/saved models and calls `model.fit()` on them. |
| `utils.py` | Various loading/saving utility functions. |
| `constants.py` | Defines globals for names, extensions, magic numbers, and configuration settings. |

#### Mutation
| Filename | Description |
| -------- | ----------- |
| `gradient_gen_critical_locs.py` | Generates input gradients with respect to output branches, then saves critical input indices in order of gradient component magnitude. 
| `gen_mutations.py` | Uses critical locations generated by `gradient_gen_critical_locs.py` to produce mutated input files for libFuzzer. |

<a name="file_tree"/>

## Sample File Tree
After running all the scripts, your file tree (directories only) should resemble the following:

```
ryancao_clusterfuzz_ml_fuzzer/
├── data/
│   ├── dataset_1/
│   │   ├── inputs/
│   │   └── labels/
│   ├── dataset_2/
│   │   ├── inputs/
│   │   └── labels/
│   └── dataset_3/
│       ├── inputs/
│       └── labels/
├── generated/
│   ├── generated_name_1/
│   │   ├── gradients/
│   │   └── mutations/
│   │       ├── mutation_name_1a/
│   │       └── mutation_name_1b/
│   ├── generated_name_2/
│   │   ├── gradients/
│   │   └── mutations/
│   │       ├── mutation_name_2a/
│   │       └── mutation_name_2b/
│   └── generated_name_3/
│   │   ├── gradients/
│   │   └── mutations/
│   │       ├── mutation_name_3a/
│   │       └── mutation_name_3b/
└── models/
    ├── architecture_1/
    │   ├── model_1/
    │   │   └── tensorboard/
    │   │       ├── train/
    │   │       └── validation/
    │   └── model_2/
    │       └── tensorboard/
    │           ├── train/
    │           └── validation/
    └── architecture_2/
        ├── model_1/
        │   └── tensorboard/
        │       ├── train/
        │       └── validation/
        └── model_2/
            └── tensorboard/
                ├── train/
                └── validation/
```
