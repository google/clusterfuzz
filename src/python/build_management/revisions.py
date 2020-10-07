# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Revisions related helper functions."""

import ast
import base64
import bisect
import os
import re
import requests
import six
import time
import urllib.parse

from base import memoize
from base import utils
from build_management import source_mapper
from config import local_config
from datastore import data_handler
from google_cloud_utils import storage
from metrics import logs
from system import environment

CHROMIUM_GIT_ROOT_URL = 'https://chromium.googlesource.com'
CRREV_NUMBERING_URL = (
    'https://cr-rev.appspot.com/_ah/api/crrev/v1/get_numbering')
CLANK_URL = 'https://chrome-internal.googlesource.com/clank/internal/apps.git'
CLANK_REVISION_FILE_COMPONENT_REGEX = re.compile(
    r'.*["]([^"]+)["]\s*:\s*["]([^"]+)["]')
COMPONENT_NAMES_BLACKLIST = [
    'api', 'bin', 'data', 'dist', 'lib', 'pylib', 'source', 'src'
]
DISK_CACHE_SIZE = 1000
SOURCE_MAP_EXTENSION = '.srcmap.json'
FIND_BRANCHED_FROM = re.compile(r'Cr-Branched-From:.*master@\{#(\d+)\}')


def _add_components_from_dict(deps_dict, vars_dict, revisions_dict):
  """Add components from a dict representing a DEPS file."""
  if not deps_dict:
    # If the dictionary is None, bail out early.
    return

  for key, value in six.iteritems(deps_dict):
    url = rev = None
    if isinstance(value, str):
      url, _, rev = value.partition('@')
    elif isinstance(value, dict):
      if 'revision' in value:
        url = value['url']
        rev = value['revision']
      elif 'url' in value and value['url'] is not None:
        url, _, rev = value['url'].partition('@')

    if url and rev:
      url = url.format(**vars_dict)
      rev = rev.format(**vars_dict)
      revisions_dict[key] = {
          'name': _get_component_display_name(key),
          'rev': rev,
          'url': url
      }


def _clank_revision_file_to_revisions_dict(content):
  """Parse Clank revision file and return revisions dict."""
  component_revision_mappings = {}
  for line in content.splitlines():
    match = CLANK_REVISION_FILE_COMPONENT_REGEX.match(line)
    if not match:
      continue

    component = match.group(1)
    revision = match.group(2)
    component_revision_mappings[component] = revision

  if not component_revision_mappings:
    logs.log_error('Failed to get component revision mappings for clank.')
    return None

  chromium_revision = component_revision_mappings['chromium_revision']
  clank_revision = component_revision_mappings['clank_revision']

  # Initialize revisions dictionary with chromium repo.
  revisions_dict = get_component_revisions_dict(chromium_revision, None)
  if revisions_dict is None:
    logs.log_error(
        'Failed to get chromium component revisions.',
        chromium_revision=chromium_revision,
        clank_revision=clank_revision)
    return None

  # Add info on clank repo.
  revisions_dict['/src/clank'] = {
      'name': 'Clank',
      'url': CLANK_URL,
      'rev': clank_revision
  }
  return revisions_dict


def _get_component_display_name(name, default=None):
  """Display name for a component."""
  if default and name in ['', 'default', '/src']:
    return default.capitalize()

  names = name.split('/')
  name_index = -1
  if len(names) > 1 and names[-1] in COMPONENT_NAMES_BLACKLIST:
    # Skip the blacklisted names from right.
    name_index -= 1

  return names[name_index].capitalize()


def _get_display_revision(component_revision_dict):
  """Return display revision for a component revision dict."""
  if 'commit_pos' in component_revision_dict:
    return component_revision_dict['commit_pos']

  return component_revision_dict['rev'] or '<empty>'


def _get_link_text(start_component_revision_dict, end_component_revision_dict):
  """Return link text given a start and end revision. This is used in cases
  when revision url is not available."""
  start_revision = _get_display_revision(start_component_revision_dict)
  end_revision = _get_display_revision(end_component_revision_dict)

  if start_revision == end_revision:
    return str(start_revision)

  return '%s:%s' % (start_revision, end_revision)


def _get_link_url(start_component_revision_dict, end_component_revision_dict):
  """Return link text given a start and end revision. This is used in cases
  when revision url is not available."""
  url = start_component_revision_dict['url']
  if not url:
    return None

  vcs_viewer = source_mapper.get_vcs_viewer_for_url(url)
  if not vcs_viewer:
    # If we don't support the vcs yet, bail out.
    return None

  start_revision = _get_revision(start_component_revision_dict)
  end_revision = _get_revision(end_component_revision_dict)

  if start_revision == end_revision:
    return vcs_viewer.get_source_url_for_revision(start_revision)

  return vcs_viewer.get_source_url_for_revision_diff(start_revision,
                                                     end_revision)


def _get_revision(component_revision_dict):
  """Return revision for a component revision dict."""
  return component_revision_dict['rev']


def _get_url_content(url):
  """Read a potentially base64-encoded resource from the given URL."""
  if url.startswith(storage.GS_PREFIX):
    # Fetch a GCS path with authentication.
    url_data = storage.read_data(url)
    if url_data is None:
      return None

    url_content = url_data.decode('utf-8')
  else:
    # Fetch a regular url without authentication.
    url_content = utils.fetch_url(url)

    # Urls on googlesource.com return file data as base64 encoded to avoid
    # cross-site scripting attacks. If the requested url contains |format=text|,
    # then the output is base64 encoded. So, decode it first.
    if url_content and url.endswith('format=text'):
      url_content = base64.b64decode(url_content)

  return url_content


def _git_url_for_chromium_repository(repository):
  """Return git url for a chromium repository."""
  return '%s/%s.git' % (CHROMIUM_GIT_ROOT_URL, repository)


def _is_clank(url):
  """Return bool on whether this is a clank url or not."""
  # FIXME: Need a better way to check for this.
  return '/chrome-test-builds/android' in url


def _is_deps(url):
  """Return bool on whether this is a DEPS url or not."""
  return urllib.parse.urlparse(url).path.endswith('/DEPS')


def _src_map_to_revisions_dict(src_map, project_name):
  """Convert src map contents to revisions dict."""
  revisions_dict = {}

  for key in src_map:
    # Only add keys that have both url and rev attributes.
    if 'url' in src_map[key] and 'rev' in src_map[key]:
      revisions_dict[key] = {
          'name': _get_component_display_name(key, project_name),
          'rev': src_map[key]['rev'],
          'url': src_map[key]['url']
      }

  return revisions_dict


@memoize.wrap(memoize.FifoOnDisk(DISK_CACHE_SIZE))
@memoize.wrap(memoize.Memcache(60 * 60 * 24 * 30))  # 30 day TTL
def _git_commit_position_to_git_hash_for_chromium(revision, repository):
  """Return git hash for a git commit position using cr-rev.appspot.com."""
  request_variables = {
      'number': revision,
      'numbering_identifier': 'refs/heads/master',
      'numbering_type': 'COMMIT_POSITION',
      'project': 'chromium',
      'repo': repository,
      'fields': 'git_sha',
  }
  query_string = urllib.parse.urlencode(request_variables)
  query_url = '%s?%s' % (CRREV_NUMBERING_URL, query_string)
  url_content = _get_url_content(query_url)
  if url_content is None:
    logs.log_error('Failed to fetch git hash from url: ' + query_url)
    return None

  result_dict = _to_dict(url_content)
  if result_dict is None:
    logs.log_error('Failed to parse git hash from url: ' + query_url)
    return None

  return result_dict['git_sha']


def _to_dict(contents):
  """Parse |contents| as a dict, returning None on failure or if it's not a
  dict."""
  try:
    result = ast.literal_eval(contents)
    if isinstance(result, dict):
      return result

  except (ValueError, TypeError):
    pass

  return None


def deps_to_revisions_dict(content):
  """Parses DEPS content and returns a dictionary of revision variables."""
  local_context = {}
  global_context = {
      'Var': lambda x: local_context.get('vars', {}).get(x),
      'Str': str,
  }
  # pylint: disable=exec-used
  exec(content, global_context, local_context)

  revisions_dict = {}

  vars_dict = local_context.get('vars', {})
  deps_dict = local_context.get('deps')
  if not deps_dict:
    # |deps| variable is required. If it does not exist, we should raise an
    # exception.
    logs.log_error('Deps format has changed, code needs fixing.')
    return None
  _add_components_from_dict(deps_dict, vars_dict, revisions_dict)

  deps_os_dict = local_context.get('deps_os')
  if deps_os_dict:
    # |deps_os| variable is optional.
    for deps_os in list(deps_os_dict.values()):
      _add_components_from_dict(deps_os, vars_dict, revisions_dict)

  return revisions_dict


def get_components_list(component_revisions_dict, job_type):
  """Return a prioritized order of components based on job type."""
  components = sorted(component_revisions_dict.keys())

  if utils.is_chromium():
    # Components prioritization only applies to non-chromium projects.
    return components

  project_name = data_handler.get_project_name(job_type)
  if not project_name:
    # No project name found in job environment, return list as-is.
    return components

  main_repo = data_handler.get_main_repo(job_type)
  project_src = '/src/' + project_name
  for component in components.copy():
    if component_revisions_dict[component]['url'] == main_repo:
      # Matches recorded main repo.
      components.remove(component)
      components.insert(0, component)
      break

    if component == project_src:
      components.remove(component)
      components.insert(0, component)
      break

    if project_name.lower() in os.path.basename(component).lower():
      components.remove(component)
      components.insert(0, component)
      # Keep trying in case an exact match is found later.

  return components


def _get_revision_vars_url_format(job_type):
  """Return REVISION_VARS_URL from job environment if available. Otherwise,
  default to one set in project.yaml. For custom binary jobs, this is not
  applicable."""
  if job_type is None:
    # Force it to use env attribute in project.yaml.
    return local_config.ProjectConfig().get('env.REVISION_VARS_URL')

  custom_binary = data_handler.get_value_from_job_definition(
      job_type, 'CUSTOM_BINARY')
  if utils.string_is_true(custom_binary):
    return None

  return data_handler.get_value_from_job_definition_or_environment(
      job_type, 'REVISION_VARS_URL')


@memoize.wrap(memoize.FifoOnDisk(DISK_CACHE_SIZE))
@memoize.wrap(memoize.Memcache(60 * 60 * 24 * 30))  # 30 day TTL
def get_component_revisions_dict(revision, job_type):
  """Retrieve revision vars dict."""
  if revision == 0 or revision == '0' or revision is None:
    # Return empty dict for zero start revision.
    return {}

  revision_vars_url_format = _get_revision_vars_url_format(job_type)
  if not revision_vars_url_format:
    return None

  project_name = data_handler.get_project_name(job_type)
  revisions_dict = {}

  if utils.is_chromium():
    component = data_handler.get_component_name(job_type)
    repository = data_handler.get_repository_for_component(component)
    if repository and not _is_clank(revision_vars_url_format):
      revision_hash = _git_commit_position_to_git_hash_for_chromium(
          revision, repository)
      if revision_hash is None:
        return None

      # FIXME: While we check for this explicitly appended component in all
      # applicable cases that we know of within this codebase, if the dict
      # is shared with an external service (e.g. Predator) we may need to clean
      # this up beforehand.
      revisions_dict['/src'] = {
          'name': _get_component_display_name(component, project_name),
          'url': _git_url_for_chromium_repository(repository),
          'rev': revision_hash,
          'commit_pos': revision
      }

      # Use revision hash for info url later.
      revision = revision_hash

  revision_vars_url = revision_vars_url_format % revision
  url_content = _get_url_content(revision_vars_url)
  if not url_content:
    logs.log_error(
        'Failed to get component revisions from %s.' % revision_vars_url)
    return None

  # Parse as per DEPS format.
  if _is_deps(revision_vars_url):
    deps_revisions_dict = deps_to_revisions_dict(url_content)
    if not deps_revisions_dict:
      return None

    revisions_dict.update(deps_revisions_dict)
    return revisions_dict

  # Parse as per Clank DEPS format.
  if _is_clank(revision_vars_url):
    return _clank_revision_file_to_revisions_dict(url_content)

  # Default case: parse content as yaml.
  revisions_dict = _to_dict(url_content)
  if not revisions_dict:
    logs.log_error(
        'Failed to parse component revisions from %s.' % revision_vars_url)
    return None

  # Parse as per source map format.
  if revision_vars_url.endswith(SOURCE_MAP_EXTENSION):
    revisions_dict = _src_map_to_revisions_dict(revisions_dict, project_name)

  return revisions_dict


def get_component_list(revision, job_type):
  """Gets mapped revisions for a given revision."""
  return get_component_range_list(revision, revision, job_type)


def get_component_range_list(start_revision, end_revision, job_type):
  """Gets revision variable ranges for a changeset range."""
  start_component_revisions_dict = get_component_revisions_dict(
      start_revision, job_type)

  if start_revision == end_revision:
    end_component_revisions_dict = start_component_revisions_dict
  else:
    end_component_revisions_dict = get_component_revisions_dict(
        end_revision, job_type)

  if (start_component_revisions_dict is None or
      end_component_revisions_dict is None):
    return []

  component_revisions = []
  keys = get_components_list(end_component_revisions_dict, job_type)
  for key in keys:
    if not start_component_revisions_dict:
      # 0 start revision, can only show link text.
      end_component_display_revision = _get_display_revision(
          end_component_revisions_dict[key])
      component_name = end_component_revisions_dict[key]['name']
      component_revisions.append({
          'component': component_name,
          'link_text': '0:%s' % end_component_display_revision
      })
      continue

    if key not in start_component_revisions_dict:
      logs.log_warn('Key %s not found in start revision %s for job %s.' %
                    (key, start_revision, job_type))
      continue

    start_component_revision_dict = start_component_revisions_dict[key]
    end_component_revision_dict = end_component_revisions_dict[key]

    component_revisions.append({
        'component':
            start_component_revision_dict['name'],
        'link_text':
            _get_link_text(start_component_revision_dict,
                           end_component_revision_dict),
        'link_url':
            _get_link_url(start_component_revision_dict,
                          end_component_revision_dict)
    })

  return component_revisions


def get_build_to_revision_mappings(platform=None):
  """Gets the build information."""
  if not platform:
    platform = environment.platform()

  # Build information matching regex.
  # Platform, Build Type, Version, ..., ..., ..., ..., Base Trunk Position, etc.
  build_info_pattern = ('([a-z]+),([a-z]+),([0-9.]+),'
                        '[^,]*,[^,]*,[^,]*,[^,]*,([0-9_]+),.*')
  build_info_url = environment.get_value('BUILD_INFO_URL')
  if not build_info_url:
    return None

  operations_timeout = environment.get_value('URL_BLOCKING_OPERATIONS_TIMEOUT')
  result = {}

  response = requests.get(build_info_url, timeout=operations_timeout)
  if response.status_code != 200:
    logs.log_error('Failed to get build mappings from url: %s' % build_info_url)
    return None
  build_info = response.text

  for line in build_info.splitlines():
    m = re.match(build_info_pattern, line)
    if m:
      build_platform = m.group(1)
      if not platform.lower().startswith(build_platform):
        continue

      build_type = m.group(2)
      version = m.group(3)
      revision = m.group(4)

      result[build_type] = {'revision': revision, 'version': version}

  return result


def get_start_and_end_revision(revision_range):
  """Return start and end revision for a regression range."""
  try:
    revision_range_list = revision_range.split(':')
    start_revision = int(revision_range_list[0])
    end_revision = int(revision_range_list[1])
  except:
    return [0, 0]

  return [start_revision, end_revision]


def format_revision_list(revisions, use_html=True):
  """Converts component revision list to html."""
  result = ''
  for revision in revisions:
    if revision['component']:
      result += '%s: ' % revision['component']

    if 'link_url' in revision and revision['link_url'] and use_html:
      result += '<a target="_blank" href="{link_url}">{link_text}</a>'.format(
          link_url=revision['link_url'], link_text=revision['link_text'])
    else:
      result += revision['link_text']

    if use_html:
      result += '<br />'
    else:
      result += '\n'

  return result


def convert_revision_to_integer(revision):
  """Returns an integer that represents the given revision."""
  # If revision is only decimal digits, like '249055', then do a simple
  # conversion.
  match = re.match(r'^\d+$', revision)
  if match:
    return int(revision)

  # If the revision has 4 parts separated by dots, like '34.0.1824.2', then do
  # the following conversion:
  # Pad the heads with up to 5 "0"s to allow them to be sorted properly, eg.:
  #   '34.0.1824.2'   -> 00034000000182400002
  #   '32.0.1700.107' -> 00032000000170000107
  # If neither of the two patterns matches, raise an error.
  match = re.match(r'^(\d{1,5})\.(\d{1,5})\.(\d{1,5})\.(\d{1,5})$', revision)
  if match:
    revision = '%s%s%s%s' % (match.group(1).zfill(5), match.group(2).zfill(5),
                             match.group(3).zfill(5), match.group(4).zfill(5))
    return int(revision)

  error = 'Unknown revision pattern: %s' % revision
  logs.log_error(error)
  raise ValueError(error)


def find_build_url(bucket_path, build_url_list, revision):
  """Returns the build url associated with a revision."""
  if not build_url_list:
    return None

  revision_pattern = revision_pattern_from_build_bucket_path(bucket_path)
  for build_url in build_url_list:
    match = re.match(revision_pattern, build_url)
    if not match:
      continue

    current_revision = convert_revision_to_integer(match.group(1))
    if current_revision == revision:
      return build_url

  return None


def find_min_revision_index(revisions_list, revision):
  """Find the min index for bisection. Find largest revision <= the given
  revision."""
  # bisect_left partitions |revisions_list| into 2 such that:
  #   all(val < revision for val in a[:index])
  #   all(val >= revision for val in a[index:])
  index = bisect.bisect_left(revisions_list, revision)
  if index < len(revisions_list) and revisions_list[index] == revision:
    return index

  if index > 0:
    return index - 1

  # No revisions <= given revision.
  return None


def find_max_revision_index(revisions_list, revision):
  """Find the max index for bisection. Find smallest revision >= the given
  revision."""
  index = bisect.bisect_left(revisions_list, revision)
  if index < len(revisions_list):
    return index

  # No revisions >= given revision.
  return None


def get_first_revision_in_list(revision_list):
  """Gets the first revision in list greater than or equal to MIN_REVISION."""
  first_revision = revision_list[0]

  min_revision = environment.get_value('MIN_REVISION')
  if not min_revision:
    return first_revision

  for revision in revision_list:
    if revision >= min_revision:
      return revision

  # No revision >= |MIN_REVISION| was found, store the error and just return
  # first revision.
  logs.log_error('Unable to find a revision >= MIN_REVISION.')
  return first_revision


def get_last_revision_in_list(revision_list):
  """Gets the last revision in list."""
  return revision_list[-1]


def get_real_revision(revision, job_type, display=False):
  """Convert the revision number into a real revision hash (e.g. git hash)."""
  if revision is None:
    # Bail early when caller passes revision from a non-existent attribute.
    return None

  component_revisions_dict = get_component_revisions_dict(revision, job_type)
  if not component_revisions_dict:
    return str(revision)

  keys = list(component_revisions_dict.keys())
  key = ('/src' if '/src' in keys else get_components_list(
      component_revisions_dict, job_type)[0])
  helper = _get_display_revision if display else _get_revision
  return helper(component_revisions_dict[key])


def needs_update(revision_file, revision):
  """Check a revision file against the provided revision
  to see if an update is required."""
  failure_wait_interval = environment.get_value('FAIL_WAIT')
  file_exists = False
  retry_limit = environment.get_value('FAIL_RETRIES')

  for _ in range(retry_limit):
    # NFS can sometimes return a wrong result on file existence, so redo
    # this check a couple of times to be sure.
    if not os.path.exists(revision_file):
      file_exists = False
      time.sleep(15)
      continue

    # Found the file, now try to read its contents.
    file_exists = True

    try:
      file_handle = open(revision_file, 'r')
      current_revision = file_handle.read()
      file_handle.close()
    except:
      logs.log_error(
          'Error occurred while reading revision file %s.' % revision_file)
      time.sleep(utils.random_number(1, failure_wait_interval))
      continue

    if current_revision.isdigit():
      return int(revision) > int(current_revision)

    return str(revision) != str(current_revision)

  # If there is no revision file or if we have lost track of its revision,
  # then we do need to update the data bundle.
  if not file_exists:
    return True

  # An error has occurred and we have failed to read revision file
  # despite several retries. So, don't bother updating the data
  # bundle as it will probably fail as well.
  logs.log_error('Failed to read revision file, exiting.')
  return False


def write_revision_to_revision_file(revision_file, revision):
  """Writes a revision to the revision file."""
  try:
    with open(revision_file, 'wb') as file_handle:
      file_handle.write(str(revision).encode('utf-8'))
  except:
    logs.log_error(
        "Could not save revision to revision file '%s'" % revision_file)


def revision_pattern_from_build_bucket_path(bucket_path):
  """Get the revision pattern from a build bucket path."""
  return '.*?' + os.path.basename(bucket_path)


@memoize.wrap(memoize.FifoOnDisk(DISK_CACHE_SIZE))
@memoize.wrap(memoize.Memcache(60 * 60 * 24 * 30))  # 30 day TTL
def revision_to_branched_from(uri, revision):
  """Interrogates git code review server to find the branch-from
  revision of a component."""
  full_uri = "%s/+/%s?format=JSON" % (uri, revision)
  url_content = _get_url_content(full_uri)
  # gerrit intentionally returns nonsense in the first line.
  # See 'cross site script inclusion here:
  # https://gerrit-review.googlesource.com/Documentation/rest-api.html
  url_content = '\n'.join(url_content.splitlines()[1:])
  result = _to_dict(url_content)
  if not result:
    logs.log_error("Unable to retrieve and parse url: %s" % full_uri)
    return None
  msg = result.get('message', None)
  if not msg:
    logs.log_error("%s JSON had no 'message'" % full_uri)
    return None
  m = FIND_BRANCHED_FROM.search(msg)
  if not m:
    logs.log_error("%s JSON message lacked Cr-Branched-From" % full_uri)
    return None
  return m.group(1)
