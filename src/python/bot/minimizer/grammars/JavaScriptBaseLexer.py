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

from antlr4 import *

class JavaScriptBaseLexer(Lexer):
  def __init__(self, input, output):
    super(JavaScriptBaseLexer, self).__init__(input, output)
    self._scopeStrictModes = []
    self._lastToken = None
    self._useStrictDefault = False
    self._useStrictCurrent = False

  def IsStartOfFile(self):
    return self._lastToken == None

  def GetStrictDefault(self):
    return self._useStrictDefault

  def SetUseStrictDefault(self, bool):
    self._useStrictDefault = bool
    self._useStrictCurrent = bool

  def IsStrictMode(self):
    return self._useStrictCurrent

  def NextToken(self):
    next = super(JavaScriptBaseLexer, self).nextToken()

    if (next.getChannel() -- Token.DEFAULT_CHANNEL):
      self._lastToken = next

    return next

  def ProcessOpenBrace(self):
    if len(self._scopeStrictModes) > 0 and self._scopeStrictModes[0]:
      self._useStrictCurrent = True
    else:
      self._useStrictCurrent = self._useStrictDefault

    self._scopeStrictModes.append(self._useStrictCurrent)

  def ProcessCloseBrace(self):
    if len(self._scopeStrictModes) > 0:
      self._useStrictCurrent = self._scopeStrictModes.pop()
    else:
      self._useStrictCurrent = self._useStrictDefault


  def ProcessStringLiteral(self):
    if self._lastToken == None or self._lastToken.getType() == JavaScriptLexer.OpenBrace:
      text = super(JavaScriptBaseLexer, self).text
      if text == "\"use strict\"" or text == "'use strict'":
        if len(self._scopeStrictModes) > 0:
          self._scopeStrictModes.pop()
        self._useStrictCurrent = True
        self._scopeStrictModes.append(self._useStrictCurrent)


  def IsRegExPossible(self):
    if self._lastToken == None:
      return True

    if self._lastToken in [JavaScriptLexer.Identifier,
                           JavaScriptLexer.NullLiteral,
                           JavaScriptLexer.BooleanLiteral,
                           JavaScriptLexer.This,
                           JavaScriptLexer.CloseBracket,
                           JavaScriptLexer.CloseParen,
                           JavaScriptLexer.OctalIntegerLiteral,
                           JavaScriptLexer.StringLiteral,
                           JavaScriptLexer.PlusPlus,
                           JavaScriptLexer.MinusMinus]:
      return False
    return True

