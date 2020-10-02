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
"""Helpers used to generate Content Security Policies for pages."""
import collections

from libs import auth


class CSPBuilder(object):
  """Helper to build a Content Security Policy string."""

  def __init__(self):
    self.directives = collections.defaultdict(list)

  def add(self, directive, source, quote=False):
    """Add a source for a given directive."""
    # Some values for sources are expected to be quoted. No escaping is done
    # since these are specific literal values that don't require it.
    if quote:
      source = '\'{}\''.format(source)

    assert source not in self.directives[directive], (
        'Duplicate source "{source}" for directive "{directive}"'.format(
            source=source, directive=directive))
    self.directives[directive].append(source)

  def add_sourceless(self, directive):
    assert directive not in self.directives, (
        'Sourceless directive "{directive}" already exists.'.format(
            directive=directive))

    self.directives[directive] = []

  def remove(self, directive, source, quote=False):
    """Remove a source for a given directive."""
    if quote:
      source = '\'{}\''.format(source)

    assert source in self.directives[directive], (
        'Removing nonexistent "{source}" for directive "{directive}"'.format(
            source=source, directive=directive))
    self.directives[directive].remove(source)

  def __str__(self):
    """Convert to a string to send with a Content-Security-Policy header."""
    parts = []

    # Sort directives for deterministic results.
    for directive, sources in sorted(self.directives.items()):
      # Each policy part has the form "directive source1 source2 ...;".
      parts.append(' '.join([directive] + sources) + ';')

    return ' '.join(parts)


def get_default_builder():
  """Get a CSPBuilder object for the default policy.

  Can be modified for specific pages if needed."""
  builder = CSPBuilder()

  # By default, disallow everything. Whitelist only features that are needed.
  builder.add('default-src', 'none', quote=True)

  # Allow various directives if sourced from self.
  builder.add('font-src', 'self', quote=True)
  builder.add('connect-src', 'self', quote=True)
  builder.add('img-src', 'self', quote=True)
  builder.add('manifest-src', 'self', quote=True)

  # External scripts. Google analytics, charting libraries.
  builder.add('script-src', 'www.google-analytics.com')
  builder.add('script-src', 'www.gstatic.com')
  builder.add('script-src', 'apis.google.com')

  # Google Analytics also uses connect-src and img-src.
  builder.add('connect-src', 'www.google-analytics.com')
  builder.add('img-src', 'www.google-analytics.com')

  # Firebase.
  builder.add('img-src', 'www.gstatic.com')
  builder.add('connect-src', 'securetoken.googleapis.com')
  builder.add('connect-src', 'www.googleapis.com')
  builder.add('frame-src', auth.auth_domain())

  # External style. Used for fonts, charting libraries.
  builder.add('style-src', 'fonts.googleapis.com')
  builder.add('style-src', 'www.gstatic.com')

  # External fonts.
  builder.add('font-src', 'fonts.gstatic.com')

  # Some upload forms require us to connect to the cloud storage API.
  builder.add('connect-src', 'storage.googleapis.com')

  # Mixed content is unexpected, but upgrade requests rather than block.
  builder.add_sourceless('upgrade-insecure-requests')

  # We don't expect object to be used, but it doesn't fall back to default-src.
  builder.add('object-src', 'none', quote=True)

  # We don't expect workers to be used, but they fall back to script-src.
  builder.add('worker-src', 'none', quote=True)

  # Add reporting so that violations don't break things silently.
  builder.add('report-uri', '/report-csp-failure')

  # TODO(mbarbella): Remove Google-specific cases by allowing configuration.

  # Internal authentication.
  builder.add('manifest-src', 'login.corp.google.com')

  # TODO(mbarbella): Improve the policy by limiting the additions below.

  # Because we use Polymer Bundler to create large files containing all of our
  # scripts inline, our policy requires this (which weakens CSP significantly).
  builder.add('script-src', 'unsafe-inline', quote=True)

  # Some of the pages that read responses from json handlers require this.
  builder.add('script-src', 'unsafe-eval', quote=True)

  # Our Polymer Bundler usage also requires inline style.
  builder.add('style-src', 'unsafe-inline', quote=True)

  # Some fonts are loaded from data URIs.
  builder.add('font-src', 'data:')

  return builder


def get_default():
  """Get the default Content Security Policy as a string."""
  return str(get_default_builder())
