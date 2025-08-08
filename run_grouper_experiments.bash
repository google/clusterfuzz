# if ! which "$PYTHON" > /dev/null; then
#   echo "python $PYTHON not found"
#   exit 1
# fi

echo "Using python: $(which python)"
echo
echo "Started grouper experiments!"
echo

echo "Default"
DEBUG_TASK=True PATH_TO_LOCAL_DATA="/home/vtcosta_google_com/grouper_data_without_reset" python butler.py run grouper_experiment --script_args step=group exp_name=default use_variant sample_to_group=0 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
echo

echo "Disable Variant"
DEBUG_TASK=True PATH_TO_LOCAL_DATA="/home/vtcosta_google_com/grouper_data_without_reset" python butler.py run grouper_experiment --script_args step=group exp_name=disable_variant sample_to_group=0 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
echo

echo "Disable variant + crash comparer thr = 0.9"
DEBUG_TASK=True PATH_TO_LOCAL_DATA="/home/vtcosta_google_com/grouper_data_without_reset" python butler.py run grouper_experiment --script_args step=group exp_name=crash_thr_90 crash_threshold=0.9 sample_to_group=0 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
echo

echo "Disable variant + crash comparer thr = 0.9 + same frames = 3"
DEBUG_TASK=True PATH_TO_LOCAL_DATA="/home/vtcosta_google_com/grouper_data_without_reset" python butler.py run grouper_experiment --script_args step=group exp_name=crash_thr_90_and_same_frames_3 crash_threshold=0.9 same_frames=3 sample_to_group=0 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
echo

echo "Disable variant + crash comparer thr = 0.85 + same frames = 3"
DEBUG_TASK=True PATH_TO_LOCAL_DATA="/home/vtcosta_google_com/grouper_data_without_reset" python butler.py run grouper_experiment --script_args step=group exp_name==crash_thr_85_and_same_frames_3 crash_threshold=0.85 same_frames=3 sample_to_group=0 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
echo

echo "Enable variant + crash comparer thr = 0.9 + same frames = 3"
DEBUG_TASK=True PATH_TO_LOCAL_DATA="/home/vtcosta_google_com/grouper_data_without_reset" python butler.py run grouper_experiment --script_args step=group exp_name=crash_thr_90_and_same_frames_3_with_variant crash_threshold=0.9 same_frames=3 use_variant sample_to_group=0 --config-dir=$HOME/Projects/clusterfuzz-config/configs/internal --non-dry-run
echo
