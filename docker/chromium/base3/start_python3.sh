#!/bin/bash -ex

cd $ROOT_DIR
pipenv sync
pipenv run python src/python/bot/startup/run.py

