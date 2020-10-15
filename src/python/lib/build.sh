#!/bin/bash

find clusterfuzz/ -type l | xargs rm

ln -s $(pwd)/../base clusterfuzz/
ln -s $(pwd)/../bot clusterfuzz/
ln -s $(pwd)/../build_managerment clusterfuzz/
ln -s $(pwd)/../config clusterfuzz/
ln -s $(pwd)/../crash_analysis clusterfuzz/
ln -s $(pwd)/../datastore clusterfuzz/
ln -s $(pwd)/../fuzzer_utils clusterfuzz/
ln -s $(pwd)/../fuzzing clusterfuzz/
ln -s $(pwd)/../google_cloud_utils clusterfuzz/
ln -s $(pwd)/../lib clusterfuzz/
ln -s $(pwd)/../metrics clusterfuzz/
ln -s $(pwd)/../platforms clusterfuzz/
ln -s $(pwd)/../system clusterfuzz/
ln -s $(pwd)/../../protos clusterfuzz/

python setup.py sdist bdist_wheel
