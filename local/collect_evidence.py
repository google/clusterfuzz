import os
import time
from google.cloud import pubsub_v1
from google.api_core import exceptions

# --- Configuration ---
PROJECT_ID = 'testes-locais'
TOPIC_NAME = 'topic-testes'
SUBSCRIPTION_NAME = 'topic-testes-sub'
EMULATOR_HOST = 'localhost:8085'
OUTPUT_FILE = 'test_evidence.txt'
# ---

def main():
    os.environ['PUBSUB_EMULATOR_HOST'] = EMULATOR_HOST
    
    subscriber = pubsub_v1.SubscriberClient()
    topic_path = f'projects/{PROJECT_ID}/topics/{TOPIC_NAME}'
    subscription_path = subscriber.subscription_path(PROJECT_ID, SUBSCRIPTION_NAME)

    print(f"Pulling messages from {subscription_path}...")
    
    all_messages = []
    # The pull request has a timeout. We need to pull multiple times.
    while True:
        try:
            response = subscriber.pull(
                request={"subscription": subscription_path, "max_messages": 1000},
                timeout=10.0,
            )
        except exceptions.DeadlineExceeded:
            print("Pull request timed out, assuming no more messages.")
            break
        
        if not response.received_messages:
            print("No more messages to pull.")
            break

        all_messages.extend(response.received_messages)
        
        # Acknowledge the messages so we don't pull them again.
        ack_ids = [msg.ack_id for msg in response.received_messages]
        subscriber.acknowledge(
            request={"subscription": subscription_path, "ack_ids": ack_ids}
        )
        print(f"Pulled and acknowledged {len(ack_ids)} messages. Total so far: {len(all_messages)}")

    print(f"\nFinished pulling. Total messages received: {len(all_messages)}")

    with open(OUTPUT_FILE, 'w') as f:
        f.write(f"""--- Pub/Sub Emulator Test Evidence ---

""")
        f.write(f"""Total tasks scheduled: {len(all_messages)}

""")
        f.write("""--- Sample of 5 Tasks ---

""")
        
        for i, received_message in enumerate(all_messages[:5]):
            f.write(f"""--- Message {i+1} ---
""")
            f.write(f"""Data: {received_message.message.data.decode('utf-8')}
""")
            f.write("""Attributes:
""")
            for key, value in received_message.message.attributes.items():
                f.write(f"""  {key}: {value}
""")
            f.write("""
""")

    print(f"\nEvidence written to {OUTPUT_FILE}")
    
    # Clean up subscription
    subscriber.delete_subscription(request={"subscription": subscription_path})
    print(f"Deleted subscription {subscription_path}")


if __name__ == '__main__':
    main()
