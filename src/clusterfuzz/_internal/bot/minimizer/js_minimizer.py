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
"""Minimizer used for additional reduction on javascript test cases."""

from clusterfuzz._internal.bot.tokenizer.antlr_tokenizer import AntlrTokenizer
from clusterfuzz._internal.bot.tokenizer.grammars.JavaScriptLexer import \
    JavaScriptLexer

from . import delta_minimizer
from . import errors
from . import minimizer
from . import utils


def step_back_while(cur_index, condition):
  """Helper function. Decreases index from cur while condition is satisfied."""
  while cur_index >= 0 and condition(cur_index):
    cur_index -= 1
  return cur_index


class JSMinimizer(minimizer.Minimizer):
  """Intended as a second-pass minimizer to remove unneeded tokens from JS."""

  def _execute(self, data):
    testcase = minimizer.Testcase(data, self)
    if not self.validate_tokenizer(data, testcase):
      raise errors.TokenizationFailureError('JS Minimizer')

    brace_stack = []
    paren_stack = []

    for index, token in enumerate(testcase.tokens):
      if token == '{':
        brace_stack.append(index)

      elif token == '}' and brace_stack:

        # Two hypotheses for tokens grouped by curly braces:
        # 1) Remove from start of line to open brace and the closing brace.
        #    e.g.: if (statement_that_evaluates_to_true) { crash() } -> crash()
        open_brace_index = brace_stack.pop()

        # Find the first non-empty token prior to the starting brackets.
        token_before_bracket = step_back_while(
            open_brace_index - 1, (lambda x: not testcase.tokens[x].strip()))

        # If that token is a close paren, we need to grab everything else too.
        # Do this to grab the whole paren so we don't create a syntax error by
        # removing only part of a paren.
        if testcase.tokens[token_before_bracket] == ')':
          # Find everything in the paren.
          token_before_bracket = step_back_while(
              token_before_bracket, (lambda x: testcase.tokens[x] != '('))

          # Get the token before the paren.
          token_before_bracket -= 1
          token_before_bracket = step_back_while(
              token_before_bracket, (lambda x: not testcase.tokens[x].strip()))

        # Walk back to the start of that line as well to get if/else and funcs.
        # Do this after paren to manage situations where there are newlines in
        # the parens.
        token_before_bracket = step_back_while(
            token_before_bracket, (lambda x: testcase.tokens[x] != '\n'))

        token_before_bracket += 1

        hypothesis = list(range(token_before_bracket,
                                open_brace_index + 1)) + [index]

        testcase.prepare_test(hypothesis)

        # 2) Remove previous tokens and from the closing brace to the next one.
        #    e.g.: try { crash() } catch(e) {} -> crash().
        future_index = len(testcase.tokens)
        open_count = 0
        for future_index in range(index + 1, len(testcase.tokens)):
          if testcase.tokens[future_index] == '{':
            open_count += 1
          if testcase.tokens[future_index] == '}':
            open_count -= 1
            # Make sure to grab entire outer brace if there are inner braces.
            if not open_count:
              break
        if future_index != len(testcase.tokens):
          lookahead_hypothesis = hypothesis + list(
              range(index + 1, future_index + 1))

          testcase.prepare_test(lookahead_hypothesis)

      elif token == '(':
        paren_stack.append(index)

      elif token == ')' and paren_stack:
        # Three hypotheses for tokens grouped by parentheses:
        # 1) Remove the parentheses and the previous token.
        #    e.g.: assertTrue(crash()); -> crash()
        previous_end = paren_stack.pop()
        if previous_end > 0:
          hypothesis = [previous_end - 1, previous_end, index]
          testcase.prepare_test(hypothesis)

        # 2) Remove everything between the parentheses.
        #    e.g. crash(junk, more_junk) -> crash()
        if index - previous_end > 1:
          hypothesis = list(range(previous_end + 1, index))
          testcase.prepare_test(hypothesis)

        # 3) Like 1, but to start of line instead of previous token.
        #    e.g.: leftover_junk = (function() {
        #          });

        # Find the beginning of the line
        token_before_paren = previous_end
        token_before_paren = step_back_while(
            previous_end, (lambda x: testcase.tokens[x] != '\n'))
        token_before_paren += 1

        hypothesis = list(range(token_before_paren, previous_end + 1)) + [index]
        testcase.prepare_test(hypothesis)

        # 4) Like 3, but also from the closing brace to the next one.
        #    e.g.: (function(global) { })(this);
        future_index = len(testcase.tokens)
        for future_index in range(index + 1, len(testcase.tokens)):
          if testcase.tokens[future_index] == ')':
            break
        if future_index != len(testcase.tokens):
          lookahead_hypothesis = list(
              range(token_before_paren, future_index + 1))
          testcase.prepare_test(lookahead_hypothesis)

      elif token == ',':
        # Two hypotheses for commas:
        # 1) Remove comma and left-hand-side.
        #    e.g.: f(whatever, crash()) -> f(crash())
        if index > 0:
          hypothesis = [index - 1, index]
          testcase.prepare_test(hypothesis)

        # 2) Remove comma and right-hand-side.
        #    e.g.: f(crash(), whatever) -> f(crash())

        # Find the next non whitespace token after the comma.
        hypothesis = [index]
        for right_token_index in range(index + 1, len(testcase.tokens)):
          hypothesis.append(right_token_index)
          if testcase.tokens[right_token_index].strip():
            testcase.prepare_test(hypothesis)
            break

    testcase.process()
    return testcase

  @staticmethod
  def run(data,
          thread_count=minimizer.DEFAULT_THREAD_COUNT,
          file_extension='.js'):
    """Attempt to minimize a javascript test case."""
    line_minimizer = delta_minimizer.DeltaMinimizer(
        utils.test, max_threads=thread_count, file_extension=file_extension)

    js_tokenizer = AntlrTokenizer(JavaScriptLexer)

    js_minimizer = JSMinimizer(
        utils.test,
        max_threads=thread_count,
        tokenizer=js_tokenizer.tokenize,
        token_combiner=js_tokenizer.combine,
        file_extension=file_extension)

    result = line_minimizer.minimize(data)
    result = js_minimizer.minimize(result)
    result = js_minimizer.minimize(result)
    result = line_minimizer.minimize(result)

    return result
