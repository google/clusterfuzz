from datastore import data_types
from datastore import ndb
from datastore import ndb_utils

def get_fuzz_target_tag(fuzz_target_name):
  query = data_types.CorpusTag().query()

  query = query.filter(data_types.CorpusTag.fuzz_target == fuzz_target_name)

  return ndb_utils.get_all_from_query(query)


def get_targets_with_tag(tag):
  query = data_types.CorpusTag().query()

  query = query.filter(data_types.CorpusTag.tag == tag)

  return ndb_utils.get_all_from_query(query)