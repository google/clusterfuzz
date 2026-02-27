
import base64
from google.protobuf import json_format
from clusterfuzz._internal.protos import swarming_pb2

def test():
    url = "https://example.com"
    encoded_url = base64.b64encode(url.encode('utf-8'))

    # Current behavior
    prop1 = swarming_pb2.TaskProperties(secret_bytes=encoded_url)
    json1 = json_format.MessageToJson(prop1)
    print("With manual base64 encoding:")
    print(json1)

    # Proposed behavior
    prop2 = swarming_pb2.TaskProperties(secret_bytes=url.encode('utf-8'))
    json2 = json_format.MessageToJson(prop2)
    print("Without manual base64 encoding:")
    print(json2)

if __name__ == "__main__":
    test()
