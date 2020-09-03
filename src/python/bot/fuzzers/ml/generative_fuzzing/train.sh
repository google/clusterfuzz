#!/bin/bash

export CUDA_VISIBLE_DEVICES=0

model_name="rnn"
prefix="/home/danielduan_google_com/targets/libpng/"

python train.py \
        --model-name $model_name \
        --input-dir $prefix"input" \
        --log-dir $prefix"log" \
        --model-weight-dir $prefix"model_weights"
