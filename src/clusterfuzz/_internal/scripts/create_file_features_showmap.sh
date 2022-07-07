# Copyright 2022 Google LLC
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

while [[ $# -gt 0 ]]
do
	case $1 in
		--showmap_path)
			SHOWMAP_PATH=$2
			shift
			shift
			;;

	  --fuzzer_path)
	    FUZZER_PATH=$2
	    shift
	    shift
	    ;;

	  --corpus_path)
	    CORPUS_PATH=$2
	    shift
	    shift
	    ;;

	  --output_path)
	    OUTPUT_PATH=$2
	    shift
	    shift
	    ;;

	  --seed_path)
	    SEED_PATH=$2
	    shift
	    shift
      ;;

		*)
			shift
			;;
	esac
done

if [ -z "$SHOWMAP_PATH" ] || [ -z "$FUZZER_PATH" ] || [ -z "$CORPUS_PATH" ] || [ -z "$OUTPUT_PATH" ] || [ -z "$SEED_PATH"]
then
  echo "Must set following parameters: --showmap_path --fuzzer_path --corpus_path --output_path --seed_path"
  exit 1
fi

echo "showmap_path $SHOWMAP_PATH"
echo "fuzzer_path $FUZZER_PATH"
echo "corpus_path $CORPUS_PATH"
echo "output_path $OUTPUT_PATH"

mkdir -p $OUTPUT_PATH

for full_path in $CORPUS_PATH/*
do
  file_name="${full_path##*/}"
  touch $OUTPUT_PATH/file_name
  $SHOWMAP_PATH -o$OUTPUT_PATH/$file_name -mnone $FUZZER_PATH $full_path
done

for full_path in $SEED_PATH/*
do
  file_name="${full_path##*/}"
  touch $OUTPUT_PATH/file_name
  $SHOWMAP_PATH -o$OUTPUT_PATH/$file_name -mnone $FUZZER_PATH $full_path
done
