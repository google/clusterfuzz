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
"""Home page handler."""

from clusterfuzz._internal.base import external_users
from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from handlers import base_handler
from libs import access
from libs import handler
from libs import helpers

MEMCACHE_TTL_IN_SECONDS = 30 * 60


def _sort_by_name(item):
  """Sort key function."""
  return item['name']


def _get_engine_names(job_name):
  """Return the (engine display name, engine name) for the job."""
  if job_name.startswith('afl_'):
    return 'AFL', 'afl'

  if job_name.startswith('libfuzzer_'):
    return 'libFuzzer', 'libFuzzer'

  return 'Unknown', 'Unknown'


@memoize.wrap(memoize.Memcache(MEMCACHE_TTL_IN_SECONDS))
def get_single_fuzz_target_or_none(project, engine_name):
  """Return the name of the single child fuzzer for the project, or None."""
  fuzz_targets = data_handler.get_fuzz_targets(
      engine=engine_name, project=project)
  fuzz_target_name = None

  for fuzz_target in fuzz_targets:
    if fuzz_target_name:
      # More than 1 child fuzzer.
      return None

    fuzz_target_name = fuzz_target.fully_qualified_name()

  return fuzz_target_name


def _get_project_results_for_jobs(jobs):
  """Return projects for jobs."""
  projects = {}
  for job in sorted(jobs, key=lambda j: j.name):
    project_name = job.get_environment().get('PROJECT_NAME', job.name)
    if project_name not in projects:
      projects[project_name] = {'name': project_name, 'jobs': []}

    if utils.string_is_true(job.get_environment().get('CORPUS_PRUNE')):
      projects[project_name]['coverage_job'] = job.name

    engine_display_name, engine_name = _get_engine_names(job.name)
    projects[project_name]['jobs'].append({
        'engine_display_name':
            engine_display_name,
        'engine_name':
            engine_name,
        'sanitizer_string':
            environment.get_memory_tool_display_string(job.name),
        'name':
            job.name,
        'single_target':
            get_single_fuzz_target_or_none(project_name, engine_name),
        'has_stats':
            True
    })

  projects = list(projects.values())
  projects.sort(key=_sort_by_name)
  for project in projects:
    project['jobs'].sort(key=_sort_by_name)

  return projects


@memoize.wrap(memoize.Memcache(MEMCACHE_TTL_IN_SECONDS))
def _get_all_project_results():
  """Return all results."""
  jobs = list(data_types.Job.query())
  return _get_project_results_for_jobs(jobs)


def _get_project_results_for_external_user(external_jobs):
  """Return results for external user."""
  jobs = list(data_types.Job.query())
  jobs = [job for job in jobs if job.name in external_jobs]
  return _get_project_results_for_jobs(jobs)


def get_results():
  """Return results."""
  is_user = access.has_access()
  user_email = helpers.get_user_email()
  external_jobs = external_users.allowed_jobs_for_user(user_email)

  is_external_user = not is_user and external_jobs
  if not is_user and not is_external_user:
    raise helpers.AccessDeniedException()

  if is_user:
    projects = _get_all_project_results()
  else:
    projects = _get_project_results_for_external_user(external_jobs)

  results = {
      'info': {
          'projects': projects,
          'is_internal_user': is_user,
      },
  }
  return results


class Handler(base_handler.Handler):
  """Home page handler."""

  @handler.get(handler.HTML)
  def get(self):
    """GET handler."""
    return self.render('oss-fuzz-home.html', get_results())


class RefreshCacheHandler(base_handler.Handler):
  """Home page handler."""

  @handler.cron()
  def get(self):
    """GET handler."""
    # pylint: disable=unexpected-keyword-arg
    _get_all_project_results(__memoize_force__=True)
