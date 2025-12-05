#!/usr/bin/env python3
import argparse
import json
import asyncio
import sys
import os

async def run_project(project, args, semaphore, project_index, total_projects):
    async with semaphore:
        print(f"\n[{project_index}/{total_projects}] Processing project: {project}")
        print("=" * 40)

        # Check if project already has a successful result
        summary_log = f'/usr/local/google/home/matheushunsche/projects/oss-migration/{project}/results/summary.log'
        if os.path.exists(summary_log):
            try:
                with open(summary_log, 'r') as f:
                    content = f.read()
                    if "✅ Success: Results meet criteria for PR." in content:
                        print(f"Skipping {project} as it already has a successful result.")
                        print("=" * 40)
                        return
            except Exception as e:
                print(f"Error reading summary log for {project}: {e}")

        # Pass --only-ubuntu-24-04 to ensure correct limits and filtering
        cmd = [sys.executable, 'oss-migration.py', project, '--use-batch', '--gcs-bucket', 'clusterfuzz-external-casp-temp', '--only-ubuntu-24-04']
        
        if args.rebuild:
            cmd.append('--rebuild')
        
        if args.no_gcb_verify:
            cmd.append('--no-gcb-verify')
            
        if args.limit:
            cmd.extend(['--limit', str(args.limit)])
        
        if args.build:
            cmd.append('--build')
        
        if args.reproduce:
            cmd.append('--reproduce')

        # If we are only reproducing, we might NOT want --rebuild, unless we want to rebuild if missing?
        # Actually, oss-migration.py logic: if rebuild is True, it removes dir.
        # If we run --reproduce, we probably DON'T want --rebuild.
        # So if --reproduce is set and --build is NOT set, we should remove --rebuild from cmd?
        if args.reproduce and not args.build:
            if '--rebuild' in cmd:
                cmd.remove('--rebuild')
        
        try:
            process = await asyncio.create_subprocess_exec(*cmd)
            await process.wait()
            print(f"Finished processing {project} (Exit code: {process.returncode})")
        except Exception as e:
            print(f"Error running migration for {project}: {e}")
        
        print("=" * 40)

async def main():
    parser = argparse.ArgumentParser(description='Batch migration of OSS-Fuzz projects.')
    parser.add_argument('projects_json', help='JSON file containing list of projects to migrate')
    parser.add_argument('--no-gcb-verify', action='store_true', help='Skip GCB build verification.')
    parser.add_argument('--limit', type=int, default=None, help='Limit the number of testcases to reproduce per project.')
    parser.add_argument('--build', action='store_true', help='Run only the build phase.')
    parser.add_argument('--reproduce', action='store_true', help='Run only the reproduction phase.')
    parser.add_argument('--rebuild', action='store_true', help='Force rebuild even if build directory exists.')
    args = parser.parse_args()

    output_file = args.projects_json
    if not os.path.exists(output_file):
        print(f"Error: {output_file} not found.")
        sys.exit(1)

    with open(output_file, 'r') as f:
        projects_data = json.load(f)
    
    # Handle both list of strings and list of dicts (legacy compatibility)
    if projects_data and isinstance(projects_data[0], dict):
        projects = [p['project'] for p in projects_data]
    else:
        projects = projects_data

    total = len(projects)
    print(f"Found {total} projects to process. Running with parallelism of 3.")
    
    semaphore = asyncio.Semaphore(3) # Limit to 3 concurrent projects
    tasks = [run_project(project, args, semaphore, i, total) for i, project in enumerate(projects, 1)]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
