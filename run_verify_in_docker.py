
import os
import sys
import click
from casp.utils import config
from casp.utils import docker_utils
from casp.utils import container

@click.command()
@click.option('--environment', default='external', help='ClusterFuzz environment')
@click.option('--target_binary', required=True, help='Path to target binary')
@click.option('--testcase_path', required=True, help='Path to testcase')
def main(environment, target_binary, testcase_path):
    cfg = config.load_and_validate_config()
    
    # Prepare volumes
    volumes, container_config_dir = docker_utils.prepare_docker_volumes(cfg, str(container.CONTAINER_CONFIG_PATH / 'config'))
    
    # Mount current directory to /workspace
    cwd = os.getcwd()
    volumes[cwd] = {'bind': '/workspace', 'mode': 'rw'}
    
    # Mount /tmp for testcase if needed (assuming testcase is in /tmp)
    testcase_dir = os.path.dirname(os.path.abspath(testcase_path))
    if testcase_dir not in volumes:
         volumes[testcase_dir] = {'bind': testcase_dir, 'mode': 'rw'}

    # Construct command to run inside container
    # We assume verify_reproduction.py is in cli/casp/src/casp/scripts/verify_reproduction.py relative to cwd
    verify_script = "/workspace/cli/casp/src/casp/scripts/verify_reproduction.py"
    
    # Adjust paths for container
    # Since we mount cwd to /workspace, paths relative to cwd should be prefixed with /workspace
    # But wait, target_binary and testcase_path might be absolute paths on host.
    # If they are in cwd, we can map them.
    
    container_target_binary = target_binary
    if target_binary.startswith(cwd):
        container_target_binary = target_binary.replace(cwd, '/workspace')
        
    container_testcase_path = testcase_path
    # If testcase is in /tmp, it is mounted as /tmp (if we added it to volumes)
    
    cmd = [
        "python3.11", verify_script,
        "--target_binary", container_target_binary,
        "--testcase_path", container_testcase_path,
        "--clusterfuzz_src", "/data/clusterfuzz/src", # Found via find
        "--bot_tmpdir", "/tmp/bot"
    ]
    
    print(f"Running command in container: {cmd}")
    
    image = docker_utils.PROJECT_TO_IMAGE[environment]
    docker_utils.run_command(cmd, volumes, privileged=True, image=image)

if __name__ == "__main__":
    main()
