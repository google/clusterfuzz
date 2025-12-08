import os
import sys
import subprocess
import json
import time
import tarfile
import tempfile
import random
import threading
import click
from typing import Dict, Optional, List, Tuple

import fcntl

gcloud_lock_file = '/tmp/gcloud_lock'

def run_command_with_retry(cmd, max_retries=5, backoff_factor=2, check=True):
    for i in range(max_retries):
        # Use file-based lock for inter-process synchronization
        with open(gcloud_lock_file, 'w') as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX)
                result = subprocess.run(cmd, capture_output=True, text=True, check=check)
                return result
            except subprocess.CalledProcessError as e:
                # Check for quota exceeded error (429) in stderr
                is_quota_error = "429" in e.stderr or "RESOURCE_EXHAUSTED" in e.stderr or "RATE_LIMIT_EXCEEDED" in e.stderr
                
                if i == max_retries - 1:
                    click.secho(f"Command failed after {max_retries} retries: {' '.join(cmd)}", fg="red")
                    click.secho(f"Stderr: {e.stderr}", fg="red")
                    raise e
                
                wait_time = backoff_factor ** i
                if is_quota_error:
                    # Longer wait for quota errors, with jitter
                    wait_time = (backoff_factor ** i) * 10 + random.uniform(1, 5)
                    click.secho(f"Quota exceeded, retrying in {wait_time:.2f}s...", fg="yellow")
                
                time.sleep(wait_time)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    return None # Should not reach here if check=True

def upload_to_gcs(local_path: str, bucket_name: str, gcs_path: str) -> str:
    """Uploads a file or directory to GCS using gsutil."""
    destination = f"gs://{bucket_name}/{gcs_path}"
    if os.path.isdir(local_path):
        # Create a tarball for directories to preserve structure and speed up upload
        # Optimized: use tar command directly and exclude .git
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp:
            tar_path = tmp.name
        
        click.echo(f"Creating tarball of {local_path} (excluding .git)...")
        # Use tar command for better performance and exclude support
        cmd = ["tar", "-czf", tar_path, "-C", os.path.dirname(local_path), "--exclude=.git", os.path.basename(local_path)]
        subprocess.run(cmd, check=True)
        
        click.echo(f"Uploading tarball to {destination}.tar.gz...")
        run_command_with_retry(["gsutil", "cp", tar_path, f"{destination}.tar.gz"], check=True)
        os.remove(tar_path)
        return f"{destination}.tar.gz"
    else:
        click.echo(f"Uploading {local_path} to {destination}...")
        run_command_with_retry(["gsutil", "cp", local_path, destination], check=True)
        return destination

def create_batch_job_spec(
    job_id: str,
    image: str,
    command: List[str],
    gcs_volumes: Dict[str, str], # Mount point -> GCS URI
    env_vars: Dict[str, str],
    privileged: bool = False
) -> Dict:
    """Creates a Cloud Batch job specification."""
    
    # Prepare runnables. 
    runnables = []
    
    # 1. Setup script runnable
    setup_commands = ["mkdir -p /mnt/shared/credentials"] # Base shared dir
    
    for mount_point, gcs_uri in gcs_volumes.items():
        # mount_point is like /mnt/shared/build or /mnt/shared/config
        setup_commands.append(f"mkdir -p {mount_point}")
        if gcs_uri.endswith('.tar.gz'):
            setup_commands.append(f"gsutil cp {gcs_uri} /tmp/vol.tar.gz")
            # Extract to mount_point. Since we tarred with -C and basename, 
            # we might need --strip-components=1 if we want to avoid the extra directory layer,
            # or keep it if we want it. For CASP, we usually want the contents directly in the mount point.
            setup_commands.append(f"tar -xzf /tmp/vol.tar.gz -C {mount_point} --strip-components=1")
            setup_commands.append("rm /tmp/vol.tar.gz")
        else:
            # For single files or directories (if gsutil supports it, but usually it's files here)
            # Better to use gsutil cp -r for directories
            setup_commands.append(f"gsutil cp -r {gcs_uri} {mount_point}/")

    # Add CASP specific setup if needed (like symlinks for builds)
    # This might need to be passed in or kept generic. For now, keep it generic
    # and handle specific setup in the command if possible, or add a setup_script arg.
    
    runnables.append({
        "script": {
            "text": "\n".join(setup_commands)
        }
    })
    
    # 2. Main container runnable
    container_volumes = ["/mnt/shared:/mnt/shared"]
    
    container_options = "--privileged" # Always privileged for ClusterFuzz Docker-in-Docker
    for vol in container_volumes:
        container_options += f" -v {vol}"
    
    # Add GCS mount if needed, though we use gsutil usually
    container_volumes_spec = [{"mountPath": "/mnt/shared", "remotePath": "mnt-shared"}] # Not used correctly, Batch is weird with GCS volumes
    
    runnable_container = {
        "container": {
            "imageUri": image,
            "commands": command,
            "options": container_options,
            "volumes": ["/mnt/shared:/mnt/shared"]
        },
        "environment": {
            "variables": env_vars
        }
    }
    runnables.append(runnable_container)

    # Get bucket name from first GCS volume for the GCS volume mount (even if not used by container directly, Batch needs it)
    job_spec = {
        "taskGroups": [{
            "taskSpec": {
                "runnables": runnables,
                "computeResource": {
                    "cpuMilli": "1000", # 1 vCPU
                    "memoryMib": "2000" # ~1.95 GB (2000 MiB)
                },
                "maxRunDuration": "3600s",
                "volumes": []
            }
        }],
        "logsPolicy": {
            "destination": "CLOUD_LOGGING"
        }
    }
    
    if gcs_volumes:
        bucket_name = gcs_volumes[list(gcs_volumes.keys())[0]].split('/')[2]
        job_spec["taskGroups"][0]["taskSpec"]["volumes"].append({
            "gcs": {
                "remotePath": bucket_name
            },
            "mountPath": "/mnt/gcs"
        })
    
    return job_spec

def submit_and_monitor_job(job_id: str, job_spec: Dict, project_id: str, location: str = "us-central1", success_strings: Optional[List[str]] = None, log_file_path: Optional[str] = None) -> Tuple[bool, str]:
    """Submits a Batch job and monitors its progress. Returns (success, logs)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(job_spec, tmp)
        tmp_path = tmp.name
    
    try:
        console_url = f"https://pantheon.corp.google.com/batch/jobsDetail/regions/{location}/jobs/{job_id}/details?project={project_id}"
        click.echo(f"Submitting Batch job {job_id}...", err=True)
        click.echo(f"Console URL: {console_url}", err=True)
        cmd = [
            "gcloud", "batch", "jobs", "submit", job_id,
            f"--location={location}",
            f"--config={tmp_path}",
            f"--project={project_id}",
            "--format=json"
        ]
        # Capture output to get the real job UID if needed, but job_id is usually enough for logs now
        try:
            run_command_with_retry(cmd, check=True)
        except subprocess.CalledProcessError as e:
            if "ALREADY_EXISTS" in e.stderr:
                click.echo(f"Job {job_id} already exists, proceeding to monitor existing job.")
            else:
                raise e
        
        click.echo(f"Job {job_id} submitted. Monitoring...")
        
        job_uid = None
        last_log_timestamp = None
        all_output = []
        
        log_file = None
        if log_file_path:
            log_file = open(log_file_path, 'a', encoding='utf-8', errors='ignore')
        
        # Initial jitter to avoid synchronized polling
        time.sleep(random.uniform(1, 10))
        
        while True:
            cmd = [
                "gcloud", "batch", "jobs", "describe", job_id,
                f"--location={location}",
                f"--project={project_id}",
                "--format=json"
            ]
            result = run_command_with_retry(cmd, check=True)
            job_info = json.loads(result.stdout)
            status = job_info.get("status", {}).get("state", "").strip()
            if not job_uid:
                job_uid = job_info.get("uid")
            
            # Removed real-time log polling to reduce GCS Logging quota usage.
            # Logs will be collected once at the end of the job.
            
            status_msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Job status: {status}"
            if log_file:
                log_file.write(status_msg + "\n")
                log_file.flush()
            all_output.append(status_msg)
            
            if status in ["SUCCEEDED", "FAILED"]:
                break
            
            # Polling interval for job status (less frequent than log polling)
            time.sleep(random.uniform(30, 60))
        
        # Final log collection to ensure we have everything, especially if container failed
        if job_uid:
            click.echo("Fetching final logs from Cloud Logging...")
            final_log_filter = (
                f'logName=("projects/{project_id}/logs/batch_task_logs" OR '
                f'"projects/{project_id}/logs/batch_agent_logs") AND '
                f'labels.job_uid="{job_uid}"'
            )
            
            cmd = [
                "gcloud", "logging", "read", 
                final_log_filter, 
                f"--project={project_id}",
                "--order=asc", 
                "--format=value(textPayload, jsonPayload.message)"
            ]
            
            try:
                # Use run_command_with_retry to handle transient network issues
                # Retry multiple times for logs as they might be delayed in Cloud Logging
                # Use exponential backoff with jitter to avoid hitting quota
                result = None
                max_log_retries = 5
                for i in range(max_log_retries):
                    result = run_command_with_retry(cmd, check=False)
                    if result and result.stdout and result.stdout.strip():
                        break
                    
                    # If we are here, either result is None, or stdout is empty
                    # Wait before retrying, with exponential backoff and jitter
                    wait_time = (2 ** i) * 5 + random.uniform(1, 5)
                    click.echo(f"No logs found yet (attempt {i+1}/{max_log_retries}), retrying in {wait_time:.2f}s...")
                    time.sleep(wait_time)

                if result and result.stdout and result.stdout.strip():
                    logs_text = result.stdout
                    if 'log_file' in locals() and log_file:
                        log_file.write("\n--- Final Logs (from Cloud Logging) ---\n")
                        log_file.write(logs_text)
                        log_file.write("\n")
                        log_file.flush()
                    all_output.append("\n--- Final Logs ---\n")
                    all_output.append(logs_text)
                else:
                    msg = "\n--- No logs found in Cloud Logging for this job ---\n"
                    if 'log_file' in locals() and log_file:
                        log_file.write(msg)
                        log_file.flush()
                    all_output.append(msg)
            except Exception as e:
                click.secho(f"Failed to fetch final logs: {e}", fg="yellow")
        
        full_log_text = "\n".join(all_output)
        
        if status == "FAILED":
            click.secho(f"Job failed with status: {status}", fg="red")
            return False, full_log_text
        
        if status == "SUCCEEDED":
            if success_strings:
                found_success = False
                for s in success_strings:
                    if s in full_log_text:
                        found_success = True
                        break
                
                if found_success:
                    click.secho("Job succeeded and verified via logs!", fg="green")
                    return True, full_log_text
                else:
                    click.secho("Job succeeded but success strings not found in logs.", fg="yellow")
                    return False, full_log_text
            else:
                click.secho("Job succeeded!", fg="green")
                return True, full_log_text
        
        return False, full_log_text
            
        return False, full_log_text
            
    finally:
        if log_file:
            log_file.close()
        os.remove(tmp_path)

def submit_and_monitor_build(project_id: str, cloudbuild_yaml: Dict, tags: List[str], log_file_path: Optional[str] = None, impersonate_service_account: Optional[str] = None, gcs_log_dir: Optional[str] = None, async_mode: bool = False) -> Tuple[bool, str]:
    # Add tags to cloudbuild_yaml if provided
    if tags:
        if 'tags' not in cloudbuild_yaml:
            cloudbuild_yaml['tags'] = []
        cloudbuild_yaml['tags'].extend(tags)
        
    # If gcs_log_dir is provided, we must NOT set logging: CLOUD_LOGGING_ONLY in options
    if gcs_log_dir and 'options' in cloudbuild_yaml and cloudbuild_yaml['options'].get('logging') == 'CLOUD_LOGGING_ONLY':
        del cloudbuild_yaml['options']['logging']

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
        import yaml
        yaml.dump(cloudbuild_yaml, tmp)
        tmp_path = tmp.name

    try:
        click.echo(f"Submitting Cloud Build to project {project_id}...", err=True)
        
        # Construct gcloud command
        # Use gcloud beta to support streaming logs from Cloud Logging
        cmd = [
            "gcloud", "beta", "builds", "submit",
            f"--project={project_id}",
            "--region=us-central1",
            f"--config={tmp_path}",
            "--no-source",
            "--format=json"
        ]
        
        if async_mode:
            cmd.append("--async")
        
        if gcs_log_dir:
            cmd.append(f"--gcs-log-dir={gcs_log_dir}")
            # CLOUD_LOGGING_ONLY cannot be used with gcs-log-dir/logs_bucket
        else:
            # Default to CLOUD_LOGGING_ONLY if no bucket provided, but user prefers explicit bucket.
            # We will use the bucket if provided.
            cmd.append("--logging=CLOUD_LOGGING_ONLY")
        
        if impersonate_service_account:
            cmd.append(f"--impersonate-service-account={impersonate_service_account}")

        if async_mode:
            click.echo("Submitting build asynchronously...", err=True)
            # Use run_command_with_retry to handle quotas/transient errors
            result = run_command_with_retry(cmd, check=True)
            return True, result.stdout
        else:
            click.echo("Build submitted. Streaming logs...", err=True)
            
            # Use Popen to stream logs
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            import threading
            
            stdout_lines = []
            stderr_lines = []
            
            def read_stream(stream, collector, is_stderr):
                for line in stream:
                    collector.append(line)
                    # Stream stderr (logs) to console
                    if is_stderr:
                        click.echo(line, nl=False, err=True)
                    # Write to log file if provided
                    if log_file_path:
                         try:
                             with open(log_file_path, 'a', encoding='utf-8', errors='ignore') as f:
                                 f.write(line)
                         except Exception:
                             pass

            t_stderr = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines, True))
            t_stderr.start()
            
            t_stdout = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines, False))
            t_stdout.start()
            
            process.wait()
            t_stderr.join()
            t_stdout.join()
            
            full_logs = "".join(stderr_lines) + "\n" + "".join(stdout_lines)
            
            # Check status
            json_output = "".join(stdout_lines)
            status = "UNKNOWN"
            try:
                # Attempt to find JSON object in stdout
                # It might be the whole stdout or mixed
                # gcloud --format=json usually outputs just the JSON to stdout
                build_info = json.loads(json_output)
                status = build_info.get("status")
            except json.JSONDecodeError:
                # Fallback: check exit code
                if process.returncode == 0:
                    status = "SUCCESS"
                else:
                    status = "FAILURE"
            
            click.echo(f"Build finished with status: {status}", err=True)
            
            if status == "SUCCESS":
                return True, full_logs
            else:
                return False, full_logs

    except subprocess.CalledProcessError as e:
        click.secho(f"Command failed: {e}", fg="red")
        if e.stderr:
            click.secho(f"Stderr: {e.stderr}", fg="red")
        return False, f"Command failed: {e}\nStderr: {e.stderr}"
    except Exception as e:
        click.secho(f"Exception during Cloud Build: {e}", fg="red")
        return False, str(e)
    finally:
        os.remove(tmp_path)
