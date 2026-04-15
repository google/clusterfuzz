from clusterfuzz._internal.datastore import data_types

def execute(args):
  fuzzer_name = 'my_builtin_fuzzer'
  
  if data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get():
    print(f'Fuzzer {fuzzer_name} already exists!')
    return

  fuzzer = data_types.Fuzzer(
      name=fuzzer_name,
      builtin=True, # Important: tells ClusterFuzz not to look for a zip archive
      file_size='builtin',
      source='builtin',
      jobs=['my_local_job'] # Link it to your job
  )

  if args.non_dry_run:
    fuzzer.put()
    print(f'Successfully created fuzzer: {fuzzer_name}')
  else:
    print(f'Dry-run: Would have created fuzzer: {fuzzer_name}')
