#!/usr/bin/env python3
import sys
import os
import signal

print(f"Top level sys.argv: {sys.argv}")

def main():
    with open('/tmp/fuzzer.log', 'a') as log:
        log.write(f"Running dummy fuzzer with args: {sys.argv}\n")
        log.write(f"Executable: {sys.executable}\n")
    print(f"Running dummy fuzzer with args: {sys.argv}")
    print(f"Executable: {sys.executable}")
    # print(f"Environment: {os.environ}")
    input_file = None
    for arg in sys.argv[1:]:
        if not arg.startswith('-'):
            input_file = arg

    if input_file:
        print(f"Reading input file: {input_file}")
        try:
            with open(input_file, 'r') as f:
                content = f.read()
            
            if "CRASH" in content:
                print("Crashing as requested!")
                sys.stdout.flush()
                sys.exit(77)
            else:
                print(f"Input file {input_file} did not contain CRASH. Content: {content!r}")
        except Exception as e:
            print(f"Error reading file {input_file}: {e}")
            sys.exit(1)
    else:
        print("No input file provided.")
        print("Usage: dummy_fuzzer.py <input_file>")
        sys.exit(1)

if __name__ == "__main__":
    main()
