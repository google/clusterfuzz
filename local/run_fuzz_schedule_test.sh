#!/bin/bash

# This script automates the process of testing local changes to the fuzz scheduling mechanism.
# It ensures the Pub/Sub emulator is set up correctly, runs the scheduler to publish tasks,
# and then runs the evidence collector to verify that the tasks were published successfully.

set -e
set -x

# --- Configuration ---
export PUBSUB_EMULATOR_HOST="localhost:8085"
export CLOUDSDK_API_ENDPOINT_OVERRIDES_PUBSUB="http://localhost:8085/"
PROJECT_ID="testes-locais"
TOPIC_ID="topic-testes"
SUBSCRIPTION_ID="topic-testes-sub"
# ---

echo "Checking for Pub/Sub topic: $TOPIC_ID"

# Check if the topic already exists.
# The output of the list command is piped to grep, which will have a non-zero exit code if no match is found.
# We suppress grep's output and check its exit code.
if ! gcloud pubsub --project=$PROJECT_ID topics list --filter="name:$TOPIC_ID" | grep -q $TOPIC_ID; then
  echo "Topic not found. Creating topic: $TOPIC_ID"
  gcloud pubsub --project=$PROJECT_ID topics create $TOPIC_ID
else
  echo "Topic $TOPIC_ID already exists."
fi

# --- Check/Create Subscription ---
echo "Checking for Pub/Sub subscription: $SUBSCRIPTION_ID"
if ! gcloud pubsub --project=$PROJECT_ID subscriptions list --filter="name:$SUBSCRIPTION_ID" | grep -q $SUBSCRIPTION_ID; then
    echo "Subscription not found. Creating subscription: $SUBSCRIPTION_ID"
    gcloud pubsub --project=$PROJECT_ID subscriptions create $SUBSCRIPTION_ID --topic=$TOPIC_ID
else
    echo "Subscription $SUBSCRIPTION_ID already exists."
fi

echo "Running the fuzz scheduler..."
python run_schedule_fuzz_directly.py

echo "Collecting evidence..."
python local/collect_evidence.py

echo "Done. Check test_evidence.txt for results."
