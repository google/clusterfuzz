export PATH_TO_LOCAL_DATA="/home/vtcosta_google_com/grouper_data_latest"
export DEBUG_TASK=True

echo "Using python: $(which python)"

echo -e "\nLoading testcases snapshot, if needed"
if ls "$PATH_TO_LOCAL_DATA"/testcases_snapshot* >/dev/null 2>&1; then
  echo "Using existing snapshot in $PATH_TO_LOCAL_DATA."
else
  echo "Loading testcase snapshot."
  python butler.py run grouper_experiment --script_args step=load --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
fi


echo -e "\nStarted grouper experiments!"

# echo -e "\nDefault"
# python butler.py run grouper_experiment --script_args step=group exp_name=default use_variant --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo

# echo -e "\nDisable Variant"
# python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo

# echo -e "\nDisable variant + crash comparer thr = 0.85"
# python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_crash_thr_85 crash_threshold=0.85 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo

# echo -e "\nDisable variant + crash comparer thr = 0.9"
# python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_crash_thr_90 crash_threshold=0.9 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo

# echo -e "\nDisable variant + same frames = 3"
# python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_same_frames_3 same_frames=3 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo

# echo -e "\nDisable variant + crash comparer thr = 0.85 + same frames = 3"
# python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_crash_thr_85_and_same_frames_3 crash_threshold=0.85 same_frames=3 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo

# echo -e "\nDisable variant + crash comparer thr = 0.90 + same frames = 3"
# python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_crash_thr_90_and_same_frames_3 crash_threshold=0.90 same_frames=3 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo

# echo -e "\nEnable variant + crash comparer thr = 0.9 + same frames = 3"
# python butler.py run grouper_experiment --script_args step=group exp_name=enable_variant_and_crash_thr_90_and_same_frames_3 crash_threshold=0.9 same_frames=3 use_variant --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
# echo


python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_group_size_35 group_max_size=35 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_group_size_40 group_max_size=40 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_increase_thrs_and_group_size_35 crash_threshold=0.90 same_frames=3 group_max_size=35 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant_and_increase_thrs_and_group_size_40 crash_threshold=0.90 same_frames=3 group_max_size=40 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
