#!/bin/bash

export CUDA_VISIBLE_DEVICES=0

model_name="gpt"
prefix="/home/danielduan/targets/libpng/"
seed_prefix=$prefix"cpu_test/seed_"
model_weights_path=$prefix"model_weights/"
predict_window_size=30
count_list=(1000)
pos_change_list=(20 50 100)

for count in ${count_list[@]}; do
  for pos_change in ${pos_change_list[@]}; do
    if [ $pos_change -lt 0 ]
      then
        output_dir=$seed_prefix"${count}_k$((-pos_change))"
    elif [ $pos_change -eq 0 ]
      then
        output_dir=$seed_prefix"${count}"
    else
      if [ $model_name = "rnn_mk" ]
      then
        output_dir=$seed_prefix"${count}_mk${pos_change}"
      else
        output_dir=$seed_prefix"${count}_m${pos_change}"
      fi
    fi

    python generate.py \
      --model-name $model_name \
      --input-dir $prefix"input" \
      --output-dir $output_dir \
      --model-weights-path $model_weights_path \
      --count $count \
      --pos-change $pos_change \
      --predict-window-size $predict_window_size
  done
done
