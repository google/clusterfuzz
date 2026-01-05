
import os
from google.cloud import datastore

def fetch_testcases():
    client = datastore.Client(project='clusterfuzz-external')
    query = client.query(kind='Testcase')
    query.order = ['-timestamp']
    query.add_filter('status', '=', 'Processed')
    testcases = list(query.fetch(limit=1))

    if not testcases:
        print("No testcases found.")
        return

    tc = testcases[0]
    print(f"Testcase ID: {tc.id}")
    for key, value in tc.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    fetch_testcases()
