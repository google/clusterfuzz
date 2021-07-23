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
"""Helper functions for fetch source links."""

import re

from clusterfuzz._internal.base import utils

DRIVE_LETTER_REGEX = re.compile(r'^[a-zA-Z]:\\')
RANGE_LIMIT = 10000
SOURCE_START_ID = 'src/'
SOURCE_STRIP_REGEX = re.compile(r'^[/]?src[/]?')
STACK_FRAME_PATH_LINE_REGEX = re.compile(
    r'(?<=\[|\(|\s)([a-zA-Z/.][^\s]*?)\s*(:|@)\s*(\d+)(?=\]$|\)$|:\d+$|$)')


class ComponentPath(object):

  def __init__(self, source=None, relative_path=None, display_path=None):
    self.source = source
    self.relative_path = relative_path
    self.display_path = display_path

  def __eq__(self, other):
    return (self.source == other.source and
            self.relative_path == other.relative_path and
            self.display_path == other.display_path)


class VCSViewer(object):
  """Base viewer class."""
  VCS_URL_REGEX = None
  VCS_REVISION_SUB = None
  VCS_REVISION_DIFF_SUB = None
  VCS_REVISION_PATH_LINE_SUB = None

  def __init__(self, url):
    self.url = url

  def get_mapped_url(self, repl, **kwargs):
    """Return mapped url given a url map and arguments."""
    mapped_url = self.VCS_URL_REGEX.sub(repl, self.url)
    mapped_url = mapped_url.format(**kwargs)
    return mapped_url

  def get_source_url_for_revision(self, revision):
    """Return source revision url given a url and revision."""
    if not self.VCS_REVISION_SUB:
      return None

    return self.get_mapped_url(self.VCS_REVISION_SUB, revision=revision)

  def get_source_url_for_revision_diff(self, start_revision, end_revision):
    """Return source revision diff url given a url and revision."""
    if not self.VCS_REVISION_DIFF_SUB:
      return None

    return self.get_mapped_url(
        self.VCS_REVISION_DIFF_SUB,
        start_revision=start_revision,
        end_revision=end_revision,
        range_limit=RANGE_LIMIT)

  def get_source_url_for_revision_path_and_line(self, revision, path, line):
    """Return source revision url given a url, revision, path and line."""
    if not self.VCS_REVISION_PATH_LINE_SUB:
      return None

    return self.get_mapped_url(
        self.VCS_REVISION_PATH_LINE_SUB,
        revision=revision,
        path=path,
        line=line)


class FreeDesktopVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(
      r'https://anongit\.freedesktop\.org/git/(.*)\.git$')
  VCS_REVISION_SUB = r'https://cgit.freedesktop.org/\1/commit/?id={revision}'
  VCS_REVISION_DIFF_SUB = (r'https://cgit.freedesktop.org/\1/diff/'
                           r'?id={end_revision}&id2={start_revision}')
  VCS_REVISION_PATH_LINE_SUB = (
      r'https://cgit.freedesktop.org/\1/tree/{path}?id={revision}#n{line}')


class GitHubVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'(https://github\.com/(.*?))(\.git)?$')
  VCS_REVISION_SUB = r'\1/commit/{revision}'
  VCS_REVISION_DIFF_SUB = (r'\1/compare/{start_revision}...{end_revision}')
  VCS_REVISION_PATH_LINE_SUB = r'\1/blob/{revision}/{path}#L{line}'


class GitLabVCS(GitHubVCS):
  VCS_URL_REGEX = re.compile(
      r'(https://gitlab(\.[\w\.\-]+)?\.(com|org)/(.*?))(\.git)?$')


class GoogleSourceVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(
      r'(https://[^/]+\.googlesource\.com/(.*?))(\.git)?$')
  VCS_REVISION_SUB = r'\1/+/{revision}'
  VCS_REVISION_DIFF_SUB = (
      r'\1/+log/{start_revision}..{end_revision}?pretty=fuller&n={range_limit}')
  VCS_REVISION_PATH_LINE_SUB = r'\1/+/{revision}/{path}#{line}'


class GoogleVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'^//(.*)$')
  VCS_REVISION_SUB = r'https://cs.corp.google.com/\1/?rcl={revision}'
  VCS_REVISION_PATH_LINE_SUB = (
      r'https://cs.corp.google.com/\1/{path}?rcl={revision}&l={line}')


class MercurialVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'(https?://hg\.(.*))')
  VCS_REVISION_SUB = r'\1/rev/{revision}'
  VCS_REVISION_DIFF_SUB = (r'\1/log?rev={start_revision}%3A%3A{end_revision}'
                           r'&revcount={range_limit}')
  VCS_REVISION_PATH_LINE_SUB = r'\1/file/{revision}/{path}#l{line}'


VCS_LIST = [
    FreeDesktopVCS,
    GitHubVCS,
    GitLabVCS,
    GoogleSourceVCS,
    GoogleVCS,
    MercurialVCS,
]


def get_component_source_and_relative_path(path, revisions_dict):
  """Get component source and relative path given a revisions dictionary and
  path."""
  if not revisions_dict:
    return ComponentPath()

  normalized_path = normalize_source_path(path)
  if normalized_path is None:
    return ComponentPath()

  component_sources = sorted(list(revisions_dict.keys()), key=len, reverse=True)
  default_component_source = None
  for component_source in component_sources:
    # Trailing slash is important so that we match the exact component source.
    # E.g. without slash, we would match src/webrtc_overrides with src/webrtc
    # which is incorrect.
    stripped_component_source = (
        SOURCE_STRIP_REGEX.sub('', component_source) + '/')

    if normalized_path.startswith(stripped_component_source):
      relative_path = utils.strip_from_left(normalized_path,
                                            stripped_component_source)
      return ComponentPath(component_source, relative_path, normalized_path)

    if stripped_component_source == '/':
      default_component_source = component_source

  if default_component_source is None:
    return ComponentPath()

  return ComponentPath(default_component_source, normalized_path,
                       normalized_path)


def get_vcs_viewer_for_url(url):
  """Return a VCS instance given an input url."""
  for vcs in VCS_LIST:
    if vcs.VCS_URL_REGEX.match(url):
      return vcs(url)

  return None


def linkify_stack_frame(stack_frame, revisions_dict):
  """Linkify a stack frame with source links to its repo."""
  match = STACK_FRAME_PATH_LINE_REGEX.search(stack_frame)
  if not match:
    # If this stack frame does not contain a path and line, bail out.
    return stack_frame

  path = match.group(1)
  line = match.group(3)

  component_path = get_component_source_and_relative_path(path, revisions_dict)
  if not component_path.source:
    # Can't find any matching component source in revisions dict, bail out.
    return stack_frame

  source_dict = revisions_dict[component_path.source]
  repo_url = source_dict['url']
  revision = source_dict['rev']
  vcs_viewer = get_vcs_viewer_for_url(repo_url)
  if not vcs_viewer:
    # If we don't support the vcs, bail out.
    return stack_frame

  link_html = r'<a href="{url}">{path}:{line}</a>'.format(
      url=vcs_viewer.get_source_url_for_revision_path_and_line(
          revision, component_path.relative_path, line),
      path=component_path.display_path,
      line=line)

  linkified_stack_frame = STACK_FRAME_PATH_LINE_REGEX.sub(
      link_html, stack_frame)

  return linkified_stack_frame


def normalize_source_path(path):
  """Normalizes source path for comparison with component sources."""
  # Account for ../../ at start of path due to working directory
  # out/<build_dir>/ at time of build generation (chromium only).
  path = utils.remove_prefix(path, '../../')

  # Remove /proc/self/cwd prefix added by Bazel.
  path = utils.remove_prefix(path, '/proc/self/cwd/')

  # Cross-platform way to determine path absoluteness.
  is_path_absolute = path.startswith('/') or DRIVE_LETTER_REGEX.match(path)

  # Normalize backslashes into slashes.
  normalized_path = path.replace('\\', '/')

  if is_path_absolute:
    source_start_id_index = normalized_path.find(SOURCE_START_ID)
    if source_start_id_index == -1:
      # This absolute path does not have source start id, so we cannot
      # figure out a relative path. Bail out.
      return None

    return normalized_path[source_start_id_index + len(SOURCE_START_ID):]

  return normalized_path
