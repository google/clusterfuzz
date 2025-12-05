import os
import sys
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.config import local_config

def main():
    # Setup paths
    base_dir = '/usr/local/google/home/matheushunsche/projects/clusterfuzz'
    config_dir = '/usr/local/google/home/matheushunsche/projects/clusterfuzz-config'
    project_name = 'google'
    
    # Use the google config directory directly
    config_path = os.path.join(config_dir, 'configs', 'google')
    if not os.path.isdir(config_path):
        print(f"Error: Config path not found: {config_path}")
        return

    os.environ['CONFIG_DIR_OVERRIDE'] = config_path
    
    try:
        local_config.ProjectConfig().set_environment()
    except Exception as e:
        print(f"Warning setting environment: {e}")

    print(f"Connecting to Datastore to check bots for project: {project_name}...")
    with ndb_init.context():
        # In ClusterFuzz, bots are often tracked via Bot entities or by checking TaskStatus
        # Let's check TaskStatus to see active bots
        query = data_types.TaskStatus.query()
        all_bot_statuses = list(ndb_utils.get_all_from_query(query))
        
        print(f"Found {len(all_bot_statuses)} bot statuses.")
        
        platforms = {}
        for status in all_bot_statuses:
            # TaskStatus doesn't directly have platform, but we can infer from bot name or other fields if available
            # However, Bot entity is better if it exists. Let's try to find Bot entity definition.
            # Since I don't see a Bot entity in data_types.py easily, I will check the bot names.
            bot_name = status.bot_name
            if bot_name:
                if 'linux' in bot_name.lower():
                    platforms[bot_name] = 'LINUX (inferred)'
                elif 'android' in bot_name.lower():
                    platforms[bot_name] = 'ANDROID (inferred)'
                elif 'windows' in bot_name.lower():
                    platforms[bot_name] = 'WINDOWS (inferred)'
                elif 'mac' in bot_name.lower():
                    platforms[bot_name] = 'MAC (inferred)'
                else:
                    platforms[bot_name] = 'Unknown'

        linux_bots = [b for b, p in platforms.items() if 'LINUX' in p]
        android_bots = [b for b, p in platforms.items() if 'ANDROID' in p]
        other_bots = [b for b, p in platforms.items() if 'LINUX' not in p and 'ANDROID' not in p]
        
        print(f"\nLinux Bots: {len(linux_bots)}")
        print(f"Android Bots: {len(android_bots)}")
        print(f"Other Bots: {len(other_bots)}")
        
        if android_bots:
            print("\nAndroid Bots:")
            for b in android_bots:
                print(f"- {b}")
        
        if other_bots:
            print("\nOther Bots:")
            for b in other_bots:
                print(f"- {b} ({platforms[b]})")

if __name__ == '__main__':
    main()
