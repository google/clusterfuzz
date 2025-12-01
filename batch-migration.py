#!/usr/bin/env python3
import json
import os
import subprocess
import sys

def main():
    # 1. Use existing top 100 projects list
    output_file = '/usr/local/google/home/matheushunsche/projects/top_100_projects.json'
    if not os.path.exists(output_file):
        print(f"Error: {output_file} not found. Please run count_testcases_async.py first or provide the file.")
        sys.exit(1)
    
    with open(output_file, 'r') as f:
        projects_data = json.load(f)
    
    projects = [p['project'] for p in projects_data]
    # projects.reverse() # Run projects with fewer test cases first
    total = len(projects)
    print(f"Found {total} projects to process (running in descending order of test cases).")
    
    # 2. Run oss-migration.py for each project
    for i, project in enumerate(projects, 1):
        print(f"\n[{i}/{total}] Processing project: {project}")
        print("=" * 40)
        
        # Check if project already has a successful result
        summary_log = f'/usr/local/google/home/matheushunsche/projects/oss-migration/{project}/results/summary.log'
        if os.path.exists(summary_log):
            with open(summary_log, 'r') as f:
                content = f.read()
                if "✅ Success: Results meet criteria for PR." in content:
                    print(f"Skipping {project} as it already has a successful result.")
                    print("=" * 40)
                    continue
        
        cmd = [sys.executable, 'oss-migration.py', project, '--use-batch', '--gcs-bucket', 'clusterfuzz-external-casp-temp', '--rebuild']
        # Add other flags if needed, e.g., --use-batch, --gcs-bucket
        # For now, keep it simple as requested (just build and test)
        
        try:
            subprocess.run(cmd, check=False) # Don't check=True to allow continuing on failure
        except Exception as e:
            print(f"Error running migration for {project}: {e}")
        
        print(f"Finished processing {project}")
        print("=" * 40)

if __name__ == '__main__':
    main()
