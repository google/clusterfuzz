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
"""Minimizer that attempts to use specialized minimizers on different parts of
   an HTML test case."""

import functools

from clusterfuzz._internal.bot.tokenizer.antlr_tokenizer import AntlrTokenizer
from clusterfuzz._internal.bot.tokenizer.grammars.HTMLLexer import HTMLLexer
from clusterfuzz._internal.bot.tokenizer.grammars.JavaScriptLexer import \
    JavaScriptLexer

from . import chunk_minimizer
from . import delta_minimizer
from . import js_minimizer
from . import minimizer
from . import utils

SCRIPT_START_STRING = b'<script'
SCRIPT_END_STRING = b'</script>'


class HTMLMinimizer(minimizer.Minimizer):  # pylint:disable=abstract-method
  """Specialized HTML minimizer.

     Note that this will not work properly with normal tokenizers. It simply
     acts as a wrapper around other minimizers and passes pieces of the HTML
     file to those."""

  class Token(object):
    """Helper class to represent a single token."""
    TYPE_HTML = 0
    TYPE_SCRIPT = 1

    def __init__(self, data, token_type):
      self.data = data
      self.token_type = token_type

  class TokenizerState(object):
    """Enum for tokenizer states."""
    SEARCHING_FOR_SCRIPT = 0
    SEARCHING_FOR_TAG_END = 1
    SEARCHING_FOR_CLOSE_SCRIPT = 2

  HTMLTOKENIZER = AntlrTokenizer(HTMLLexer).tokenize
  JSTOKENIZER = AntlrTokenizer(JavaScriptLexer).tokenize

  TOKENIZER_MAP = {
      Token.TYPE_HTML: [HTMLTOKENIZER, HTMLTOKENIZER, HTMLTOKENIZER],
      Token.TYPE_SCRIPT: [JSTOKENIZER, JSTOKENIZER],
  }

  CHUNK_SIZES = [
      [400, 100, 20, 5],
      [400, 100, 20, 5, 2],
      [400, 100, 20, 5, 1],
  ]

  def __init__(self, test_function, *args, **kwargs):
    # The HTML minimizer will not be used directly. Instead, preserve its
    # arguments and pass them along when creating subminimizers.
    super(HTMLMinimizer, self).__init__(lambda: False)

    assert not args, 'Positional arguments not supported.'
    assert 'tokenizer' not in kwargs, 'Custom tokenizers not supported.'
    assert 'token_combiner' not in kwargs, 'Custom tokenizers not supported.'

    self.test_function = test_function
    self.kwargs = kwargs

  def minimize(self, data):
    """Wrapper to perform common tasks and call |_execute|."""
    # Do an initial line-by-line minimization to filter out noise.
    line_minimizer = delta_minimizer.DeltaMinimizer(self.test_function,
                                                    **self.kwargs)
    # Do two line minimizations to make up for the fact that minimzations on
    # bots don't always minimize as much as they can.
    for _ in range(2):
      data = line_minimizer.minimize(data)

    tokens = self.get_tokens_and_metadata(data)
    for index, token in enumerate(tokens):
      current_tokenizers = self.TOKENIZER_MAP[token.token_type]
      prefix = self.combine_tokens(tokens[:index])
      suffix = self.combine_tokens(tokens[index + 1:])
      token_combiner = functools.partial(
          self.combine_worker_tokens, prefix=prefix, suffix=suffix)

      for level, current_tokenizer in enumerate(current_tokenizers):
        # We need to preserve the parts of the test case that are not currently
        # being minimized. Create a special token combiner that adds these
        # portions of the test to the combined tokens.

        if token.token_type == HTMLMinimizer.Token.TYPE_HTML:
          current_minimizer = chunk_minimizer.ChunkMinimizer(
              self.test_function,
              chunk_sizes=HTMLMinimizer.CHUNK_SIZES[level],
              token_combiner=token_combiner,
              tokenizer=current_tokenizer,
              **self.kwargs)
        else:
          current_minimizer = js_minimizer.JSMinimizer(
              self.test_function,
              token_combiner=token_combiner,
              tokenizer=current_tokenizer,
              **self.kwargs)

        result_data = current_minimizer.minimize(token.data)
        start = len(prefix)
        end = len(result_data) - len(suffix)
        token.data = result_data[start:end]

    # TODO(mbarbella): Remove this once other minimizers are improved.
    # Do a final line-by-line minimization pass.
    data = self.combine_tokens(tokens)
    return line_minimizer.minimize(data)

  @staticmethod
  def get_tokens_and_metadata(data):
    """Get the token list with associated metadata."""
    tokens = []
    state = HTMLMinimizer.TokenizerState.SEARCHING_FOR_SCRIPT
    current_token_start = 0
    current_token_type = HTMLMinimizer.Token.TYPE_HTML
    index = 0

    while 0 <= index < len(data):
      if state == HTMLMinimizer.TokenizerState.SEARCHING_FOR_SCRIPT:
        # In this case, we are simply searching for the next script tag.
        index = data.find(SCRIPT_START_STRING, index)
        state = HTMLMinimizer.TokenizerState.SEARCHING_FOR_TAG_END

      elif state == HTMLMinimizer.TokenizerState.SEARCHING_FOR_TAG_END:
        # Make sure that this really looks like a script tag.
        next_newline = data.find(b'\n', index)
        tag_end = data.find(b'>', index)
        if 0 <= tag_end < next_newline or next_newline < 0 <= tag_end:
          # The end of the script tag is before the next newline, so it should
          # be safe to attempt to split this.
          index = tag_end + 1
          token = HTMLMinimizer.Token(data[current_token_start:index],
                                      current_token_type)
          tokens.append(token)

          # Update state.
          current_token_type = HTMLMinimizer.Token.TYPE_SCRIPT
          current_token_start = index
          state = HTMLMinimizer.TokenizerState.SEARCHING_FOR_CLOSE_SCRIPT
        else:
          # We found a newline before the end of tag or did not find the end
          # of the tag, so something seems wrong. Skip this one.
          index += len(SCRIPT_START_STRING)

      elif state == HTMLMinimizer.TokenizerState.SEARCHING_FOR_CLOSE_SCRIPT:
        # Simply look for the end of this script.
        index = data.find(SCRIPT_END_STRING, index)
        if index < 0:
          break

        # TODO(mbarbella): Optimize for empty script case (e.g. for "src=").
        token = HTMLMinimizer.Token(data[current_token_start:index],
                                    current_token_type)
        tokens.append(token)

        current_token_start = index
        current_token_type = HTMLMinimizer.Token.TYPE_HTML
        state = HTMLMinimizer.TokenizerState.SEARCHING_FOR_SCRIPT

    token = HTMLMinimizer.Token(data[current_token_start:], current_token_type)
    tokens.append(token)
    return tokens

  @staticmethod
  def combine_worker_tokens(tokens, prefix=b'', suffix=b''):
    """Combine tokens for a worker minimizer."""
    # The Antlr tokenizer decodes the bytes objects we originally pass to it.
    encoded_tokens = [
        t if isinstance(t, bytes) else t.encode('utf-8') for t in tokens
    ]
    return prefix + b''.join(encoded_tokens) + suffix

  @staticmethod
  def combine_tokens(tokens):
    """Combine tokens into a usable format, stripping metadata."""
    return b''.join([t.data for t in tokens])

  @staticmethod
  def run(data,
          thread_count=minimizer.DEFAULT_THREAD_COUNT,
          file_extension='.html'):
    """Attempt to minimize an html test case."""
    html_minimizer = HTMLMinimizer(
        utils.test, max_threads=thread_count, file_extension=file_extension)
    return html_minimizer.minimize(data)
