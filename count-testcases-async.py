import os
import sys
import json
import collections
from datetime import datetime

# Add ClusterFuzz src to path
sys.path.insert(0, os.path.abspath('src'))
sys.path.insert(0, os.path.abspath('cli/casp/src'))

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils

def main():
    # Setup environment for Datastore access
    os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath('../clusterfuzz-config/configs/external')
    local_config.ProjectConfig().set_environment()
    
    print("Fetching all open testcases from Datastore...")
    with ndb_init.context():
        query = data_types.Testcase.query(
            ndb_utils.is_true(data_types.Testcase.open))
        testcases = list(ndb_utils.get_all_from_query(query))
        
        print(f"Found {len(testcases)} open testcases. Processing...")
        
        project_counts = collections.defaultdict(int)
        for t in testcases:
            # Apply same filtering logic as reproduce_project.py
            is_unreproducible = t.status and t.status.startswith('Unreproducible')
            is_one_time = t.one_time_crasher_flag
            is_timeout = t.crash_type == 'Timeout'
            is_flaky_stack = t.flaky_stack
            is_pending_status = t.status == 'Pending'
            
            if not (is_unreproducible or is_one_time or is_timeout or is_flaky_stack or is_pending_status):
                project_counts[t.project_name] += 1
        
        # Sort by count descending
        sorted_projects = sorted(project_counts.items(), key=lambda x: x[1], reverse=True)
        top_100 = sorted_projects[:100]
        
        result = []
        for project, count in top_100:
            result.append({
                'project': project,
                'open_testcases': count
            })
        
        output_dir = '/usr/local/google/home/matheushunsche/projects/oss-fuzz-temp'
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, 'top_100_projects.json')
        
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"Saved top 100 projects to {output_file}")
        print(f"Top 5 projects:")
        for p in result[:5]:
            print(f"  - {p['project']}: {p['open_testcases']}")

if __name__ == '__main__':
    main()
