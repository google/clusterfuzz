# Copyright 2020 Google LLC
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

from io import StringIO
import sys

# Generated from HTMLLexer.g4 by ANTLR 4.7.1
# encoding: utf-8
from antlr4 import *


def serializedATN():
  with StringIO() as buf:
    buf.write(u"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2")
    buf.write(u"\31\u017b\b\1\b\1\b\1\b\1\b\1\4\2\t\2\4\3\t\3\4\4\t\4")
    buf.write(u"\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13")
    buf.write(u"\t\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4")
    buf.write(u"\21\t\21\4\22\t\22\4\23\t\23\4\24\t\24\4\25\t\25\4\26")
    buf.write(u"\t\26\4\27\t\27\4\30\t\30\4\31\t\31\4\32\t\32\4\33\t")
    buf.write(u"\33\4\34\t\34\4\35\t\35\4\36\t\36\4\37\t\37\4 \t \4!")
    buf.write(u"\t!\4\"\t\"\3\2\3\2\3\2\3\2\3\2\3\2\7\2P\n\2\f\2\16\2")
    buf.write(u"S\13\2\3\2\3\2\3\2\3\2\3\3\3\3\3\3\3\3\3\3\7\3^\n\3\f")
    buf.write(u"\3\16\3a\13\3\3\3\3\3\3\3\3\4\3\4\3\4\3\4\3\4\3\4\3\4")
    buf.write(u"\7\4m\n\4\f\4\16\4p\13\4\3\4\3\4\3\5\3\5\3\5\3\5\3\5")
    buf.write(u"\3\5\3\5\3\5\3\5\3\5\3\5\7\5\177\n\5\f\5\16\5\u0082\13")
    buf.write(u"\5\3\5\3\5\3\5\3\5\3\6\3\6\3\6\3\6\7\6\u008c\n\6\f\6")
    buf.write(u"\16\6\u008f\13\6\3\6\3\6\3\7\3\7\3\7\3\7\7\7\u0097\n")
    buf.write(u"\7\f\7\16\7\u009a\13\7\3\7\3\7\3\7\3\7\3\7\3\7\7\7\u00a2")
    buf.write(u"\n\7\f\7\16\7\u00a5\13\7\3\7\3\7\5\7\u00a9\n\7\3\b\3")
    buf.write(u"\b\5\b\u00ad\n\b\3\b\6\b\u00b0\n\b\r\b\16\b\u00b1\3\t")
    buf.write(u"\3\t\3\t\3\t\3\t\3\t\3\t\3\t\3\t\7\t\u00bd\n\t\f\t\16")
    buf.write(u"\t\u00c0\13\t\3\t\3\t\3\t\3\t\3\n\3\n\3\n\3\n\3\n\3\n")
    buf.write(u"\3\n\3\n\7\n\u00ce\n\n\f\n\16\n\u00d1\13\n\3\n\3\n\3")
    buf.write(u"\n\3\n\3\13\3\13\3\13\3\13\3\f\6\f\u00dc\n\f\r\f\16\f")
    buf.write(u"\u00dd\3\r\3\r\3\r\3\r\3\16\3\16\3\16\3\16\3\16\3\17")
    buf.write(u"\3\17\3\20\3\20\3\20\3\20\3\21\3\21\7\21\u00f1\n\21\f")
    buf.write(u"\21\16\21\u00f4\13\21\3\22\3\22\3\23\3\23\3\24\3\24\3")
    buf.write(u"\25\3\25\3\25\3\25\5\25\u0100\n\25\3\26\5\26\u0103\n")
    buf.write(u"\26\3\27\7\27\u0106\n\27\f\27\16\27\u0109\13\27\3\27")
    buf.write(u"\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3\27\3")
    buf.write(u"\27\3\30\7\30\u0118\n\30\f\30\16\30\u011b\13\30\3\30")
    buf.write(u"\3\30\3\30\3\30\3\30\3\30\3\31\7\31\u0124\n\31\f\31\16")
    buf.write(u"\31\u0127\13\31\3\31\3\31\3\31\3\31\3\31\3\31\3\31\3")
    buf.write(u"\31\3\31\3\31\3\31\3\32\7\32\u0135\n\32\f\32\16\32\u0138")
    buf.write(u"\13\32\3\32\3\32\3\32\3\32\3\32\3\32\3\33\7\33\u0141")
    buf.write(u"\n\33\f\33\16\33\u0144\13\33\3\33\3\33\3\33\3\33\3\34")
    buf.write(u"\3\34\3\34\3\34\3\34\5\34\u014f\n\34\3\35\5\35\u0152")
    buf.write(u"\n\35\3\36\6\36\u0155\n\36\r\36\16\36\u0156\3\36\5\36")
    buf.write(u"\u015a\n\36\3\37\3\37\6\37\u015e\n\37\r\37\16\37\u015f")
    buf.write(u"\3 \6 \u0163\n \r \16 \u0164\3 \5 \u0168\n \3!\3!\7!")
    buf.write(u"\u016c\n!\f!\16!\u016f\13!\3!\3!\3\"\3\"\7\"\u0175\n")
    buf.write(u"\"\f\"\16\"\u0178\13\"\3\"\3\"\17Q_n\u0080\u008d\u0098")
    buf.write(u"\u00a3\u00be\u00cf\u0107\u0119\u0125\u0136\2#\7\3\t\4")
    buf.write(u"\13\5\r\6\17\7\21\b\23\t\25\n\27\13\31\f\33\r\35\16\37")
    buf.write(u"\17!\20#\21%\22\'\23)\2+\2-\2/\2\61\24\63\25\65\26\67")
    buf.write(u"\279\30;\31=\2?\2A\2C\2E\2G\2\7\2\3\4\5\6\16\4\2\13\13")
    buf.write(u"\"\"\3\2>>\5\2\13\f\17\17\"\"\5\2\62;CHch\3\2\62;\4\2")
    buf.write(u"/\60aa\5\2\u00b9\u00b9\u0302\u0371\u2041\u2042\n\2<<")
    buf.write(u"C\\c|\u2072\u2191\u2c02\u2ff1\u3003\ud801\uf902\ufdd1")
    buf.write(u"\ufdf2\uffff\3\2\"\"\t\2%%-=??AAC\\aac|\4\2$$>>\4\2)")
    buf.write(u")>>\2\u018e\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2\r")
    buf.write(u"\3\2\2\2\2\17\3\2\2\2\2\21\3\2\2\2\2\23\3\2\2\2\2\25")
    buf.write(u"\3\2\2\2\2\27\3\2\2\2\2\31\3\2\2\2\2\33\3\2\2\2\3\35")
    buf.write(u"\3\2\2\2\3\37\3\2\2\2\3!\3\2\2\2\3#\3\2\2\2\3%\3\2\2")
    buf.write(u"\2\3\'\3\2\2\2\4\61\3\2\2\2\4\63\3\2\2\2\5\65\3\2\2\2")
    buf.write(u"\5\67\3\2\2\2\69\3\2\2\2\6;\3\2\2\2\7I\3\2\2\2\tX\3\2")
    buf.write(u"\2\2\13e\3\2\2\2\rs\3\2\2\2\17\u0087\3\2\2\2\21\u00a8")
    buf.write(u"\3\2\2\2\23\u00af\3\2\2\2\25\u00b3\3\2\2\2\27\u00c5\3")
    buf.write(u"\2\2\2\31\u00d6\3\2\2\2\33\u00db\3\2\2\2\35\u00df\3\2")
    buf.write(u"\2\2\37\u00e3\3\2\2\2!\u00e8\3\2\2\2#\u00ea\3\2\2\2%")
    buf.write(u"\u00ee\3\2\2\2\'\u00f5\3\2\2\2)\u00f7\3\2\2\2+\u00f9")
    buf.write(u"\3\2\2\2-\u00ff\3\2\2\2/\u0102\3\2\2\2\61\u0107\3\2\2")
    buf.write(u"\2\63\u0119\3\2\2\2\65\u0125\3\2\2\2\67\u0136\3\2\2\2")
    buf.write(u"9\u0142\3\2\2\2;\u014e\3\2\2\2=\u0151\3\2\2\2?\u0154")
    buf.write(u"\3\2\2\2A\u015b\3\2\2\2C\u0162\3\2\2\2E\u0169\3\2\2\2")
    buf.write(u"G\u0172\3\2\2\2IJ\7>\2\2JK\7#\2\2KL\7/\2\2LM\7/\2\2M")
    buf.write(u"Q\3\2\2\2NP\13\2\2\2ON\3\2\2\2PS\3\2\2\2QR\3\2\2\2QO")
    buf.write(u"\3\2\2\2RT\3\2\2\2SQ\3\2\2\2TU\7/\2\2UV\7/\2\2VW\7@\2")
    buf.write(u"\2W\b\3\2\2\2XY\7>\2\2YZ\7#\2\2Z[\7]\2\2[_\3\2\2\2\\")
    buf.write(u"^\13\2\2\2]\\\3\2\2\2^a\3\2\2\2_`\3\2\2\2_]\3\2\2\2`")
    buf.write(u"b\3\2\2\2a_\3\2\2\2bc\7_\2\2cd\7@\2\2d\n\3\2\2\2ef\7")
    buf.write(u">\2\2fg\7A\2\2gh\7z\2\2hi\7o\2\2ij\7n\2\2jn\3\2\2\2k")
    buf.write(u"m\13\2\2\2lk\3\2\2\2mp\3\2\2\2no\3\2\2\2nl\3\2\2\2oq")
    buf.write(u"\3\2\2\2pn\3\2\2\2qr\7@\2\2r\f\3\2\2\2st\7>\2\2tu\7#")
    buf.write(u"\2\2uv\7]\2\2vw\7E\2\2wx\7F\2\2xy\7C\2\2yz\7V\2\2z{\7")
    buf.write(u"C\2\2{|\7]\2\2|\u0080\3\2\2\2}\177\13\2\2\2~}\3\2\2\2")
    buf.write(u"\177\u0082\3\2\2\2\u0080\u0081\3\2\2\2\u0080~\3\2\2\2")
    buf.write(u"\u0081\u0083\3\2\2\2\u0082\u0080\3\2\2\2\u0083\u0084")
    buf.write(u"\7_\2\2\u0084\u0085\7_\2\2\u0085\u0086\7@\2\2\u0086\16")
    buf.write(u"\3\2\2\2\u0087\u0088\7>\2\2\u0088\u0089\7#\2\2\u0089")
    buf.write(u"\u008d\3\2\2\2\u008a\u008c\13\2\2\2\u008b\u008a\3\2\2")
    buf.write(u"\2\u008c\u008f\3\2\2\2\u008d\u008e\3\2\2\2\u008d\u008b")
    buf.write(u"\3\2\2\2\u008e\u0090\3\2\2\2\u008f\u008d\3\2\2\2\u0090")
    buf.write(u"\u0091\7@\2\2\u0091\20\3\2\2\2\u0092\u0093\7>\2\2\u0093")
    buf.write(u"\u0094\7A\2\2\u0094\u0098\3\2\2\2\u0095\u0097\13\2\2")
    buf.write(u"\2\u0096\u0095\3\2\2\2\u0097\u009a\3\2\2\2\u0098\u0099")
    buf.write(u"\3\2\2\2\u0098\u0096\3\2\2\2\u0099\u009b\3\2\2\2\u009a")
    buf.write(u"\u0098\3\2\2\2\u009b\u009c\7A\2\2\u009c\u00a9\7@\2\2")
    buf.write(u"\u009d\u009e\7>\2\2\u009e\u009f\7\'\2\2\u009f\u00a3\3")
    buf.write(u"\2\2\2\u00a0\u00a2\13\2\2\2\u00a1\u00a0\3\2\2\2\u00a2")
    buf.write(u"\u00a5\3\2\2\2\u00a3\u00a4\3\2\2\2\u00a3\u00a1\3\2\2")
    buf.write(u"\2\u00a4\u00a6\3\2\2\2\u00a5\u00a3\3\2\2\2\u00a6\u00a7")
    buf.write(u"\7\'\2\2\u00a7\u00a9\7@\2\2\u00a8\u0092\3\2\2\2\u00a8")
    buf.write(u"\u009d\3\2\2\2\u00a9\22\3\2\2\2\u00aa\u00b0\t\2\2\2\u00ab")
    buf.write(u"\u00ad\7\17\2\2\u00ac\u00ab\3\2\2\2\u00ac\u00ad\3\2\2")
    buf.write(u"\2\u00ad\u00ae\3\2\2\2\u00ae\u00b0\7\f\2\2\u00af\u00aa")
    buf.write(u"\3\2\2\2\u00af\u00ac\3\2\2\2\u00b0\u00b1\3\2\2\2\u00b1")
    buf.write(u"\u00af\3\2\2\2\u00b1\u00b2\3\2\2\2\u00b2\24\3\2\2\2\u00b3")
    buf.write(u"\u00b4\7>\2\2\u00b4\u00b5\7u\2\2\u00b5\u00b6\7e\2\2\u00b6")
    buf.write(u"\u00b7\7t\2\2\u00b7\u00b8\7k\2\2\u00b8\u00b9\7r\2\2\u00b9")
    buf.write(u"\u00ba\7v\2\2\u00ba\u00be\3\2\2\2\u00bb\u00bd\13\2\2")
    buf.write(u"\2\u00bc\u00bb\3\2\2\2\u00bd\u00c0\3\2\2\2\u00be\u00bf")
    buf.write(u"\3\2\2\2\u00be\u00bc\3\2\2\2\u00bf\u00c1\3\2\2\2\u00c0")
    buf.write(u"\u00be\3\2\2\2\u00c1\u00c2\7@\2\2\u00c2\u00c3\3\2\2\2")
    buf.write(u"\u00c3\u00c4\b\t\2\2\u00c4\26\3\2\2\2\u00c5\u00c6\7>")
    buf.write(u"\2\2\u00c6\u00c7\7u\2\2\u00c7\u00c8\7v\2\2\u00c8\u00c9")
    buf.write(u"\7{\2\2\u00c9\u00ca\7n\2\2\u00ca\u00cb\7g\2\2\u00cb\u00cf")
    buf.write(u"\3\2\2\2\u00cc\u00ce\13\2\2\2\u00cd\u00cc\3\2\2\2\u00ce")
    buf.write(u"\u00d1\3\2\2\2\u00cf\u00d0\3\2\2\2\u00cf\u00cd\3\2\2")
    buf.write(u"\2\u00d0\u00d2\3\2\2\2\u00d1\u00cf\3\2\2\2\u00d2\u00d3")
    buf.write(u"\7@\2\2\u00d3\u00d4\3\2\2\2\u00d4\u00d5\b\n\3\2\u00d5")
    buf.write(u"\30\3\2\2\2\u00d6\u00d7\7>\2\2\u00d7\u00d8\3\2\2\2\u00d8")
    buf.write(u"\u00d9\b\13\4\2\u00d9\32\3\2\2\2\u00da\u00dc\n\3\2\2")
    buf.write(u"\u00db\u00da\3\2\2\2\u00dc\u00dd\3\2\2\2\u00dd\u00db")
    buf.write(u"\3\2\2\2\u00dd\u00de\3\2\2\2\u00de\34\3\2\2\2\u00df\u00e0")
    buf.write(u"\7@\2\2\u00e0\u00e1\3\2\2\2\u00e1\u00e2\b\r\5\2\u00e2")
    buf.write(u"\36\3\2\2\2\u00e3\u00e4\7\61\2\2\u00e4\u00e5\7@\2\2\u00e5")
    buf.write(u"\u00e6\3\2\2\2\u00e6\u00e7\b\16\5\2\u00e7 \3\2\2\2\u00e8")
    buf.write(u"\u00e9\7\61\2\2\u00e9\"\3\2\2\2\u00ea\u00eb\7?\2\2\u00eb")
    buf.write(u"\u00ec\3\2\2\2\u00ec\u00ed\b\20\6\2\u00ed$\3\2\2\2\u00ee")
    buf.write(u"\u00f2\5/\26\2\u00ef\u00f1\5-\25\2\u00f0\u00ef\3\2\2")
    buf.write(u"\2\u00f1\u00f4\3\2\2\2\u00f2\u00f0\3\2\2\2\u00f2\u00f3")
    buf.write(u"\3\2\2\2\u00f3&\3\2\2\2\u00f4\u00f2\3\2\2\2\u00f5\u00f6")
    buf.write(u"\t\4\2\2\u00f6(\3\2\2\2\u00f7\u00f8\t\5\2\2\u00f8*\3")
    buf.write(u"\2\2\2\u00f9\u00fa\t\6\2\2\u00fa,\3\2\2\2\u00fb\u0100")
    buf.write(u"\5/\26\2\u00fc\u0100\t\7\2\2\u00fd\u0100\5+\24\2\u00fe")
    buf.write(u"\u0100\t\b\2\2\u00ff\u00fb\3\2\2\2\u00ff\u00fc\3\2\2")
    buf.write(u"\2\u00ff\u00fd\3\2\2\2\u00ff\u00fe\3\2\2\2\u0100.\3\2")
    buf.write(u"\2\2\u0101\u0103\t\t\2\2\u0102\u0101\3\2\2\2\u0103\60")
    buf.write(u"\3\2\2\2\u0104\u0106\13\2\2\2\u0105\u0104\3\2\2\2\u0106")
    buf.write(u"\u0109\3\2\2\2\u0107\u0108\3\2\2\2\u0107\u0105\3\2\2")
    buf.write(u"\2\u0108\u010a\3\2\2\2\u0109\u0107\3\2\2\2\u010a\u010b")
    buf.write(u"\7>\2\2\u010b\u010c\7\61\2\2\u010c\u010d\7u\2\2\u010d")
    buf.write(u"\u010e\7e\2\2\u010e\u010f\7t\2\2\u010f\u0110\7k\2\2\u0110")
    buf.write(u"\u0111\7r\2\2\u0111\u0112\7v\2\2\u0112\u0113\7@\2\2\u0113")
    buf.write(u"\u0114\3\2\2\2\u0114\u0115\b\27\5\2\u0115\62\3\2\2\2")
    buf.write(u"\u0116\u0118\13\2\2\2\u0117\u0116\3\2\2\2\u0118\u011b")
    buf.write(u"\3\2\2\2\u0119\u011a\3\2\2\2\u0119\u0117\3\2\2\2\u011a")
    buf.write(u"\u011c\3\2\2\2\u011b\u0119\3\2\2\2\u011c\u011d\7>\2\2")
    buf.write(u"\u011d\u011e\7\61\2\2\u011e\u011f\7@\2\2\u011f\u0120")
    buf.write(u"\3\2\2\2\u0120\u0121\b\30\5\2\u0121\64\3\2\2\2\u0122")
    buf.write(u"\u0124\13\2\2\2\u0123\u0122\3\2\2\2\u0124\u0127\3\2\2")
    buf.write(u"\2\u0125\u0126\3\2\2\2\u0125\u0123\3\2\2\2\u0126\u0128")
    buf.write(u"\3\2\2\2\u0127\u0125\3\2\2\2\u0128\u0129\7>\2\2\u0129")
    buf.write(u"\u012a\7\61\2\2\u012a\u012b\7u\2\2\u012b\u012c\7v\2\2")
    buf.write(u"\u012c\u012d\7{\2\2\u012d\u012e\7n\2\2\u012e\u012f\7")
    buf.write(u"g\2\2\u012f\u0130\7@\2\2\u0130\u0131\3\2\2\2\u0131\u0132")
    buf.write(u"\b\31\5\2\u0132\66\3\2\2\2\u0133\u0135\13\2\2\2\u0134")
    buf.write(u"\u0133\3\2\2\2\u0135\u0138\3\2\2\2\u0136\u0137\3\2\2")
    buf.write(u"\2\u0136\u0134\3\2\2\2\u0137\u0139\3\2\2\2\u0138\u0136")
    buf.write(u"\3\2\2\2\u0139\u013a\7>\2\2\u013a\u013b\7\61\2\2\u013b")
    buf.write(u"\u013c\7@\2\2\u013c\u013d\3\2\2\2\u013d\u013e\b\32\5")
    buf.write(u"\2\u013e8\3\2\2\2\u013f\u0141\t\n\2\2\u0140\u013f\3\2")
    buf.write(u"\2\2\u0141\u0144\3\2\2\2\u0142\u0140\3\2\2\2\u0142\u0143")
    buf.write(u"\3\2\2\2\u0143\u0145\3\2\2\2\u0144\u0142\3\2\2\2\u0145")
    buf.write(u"\u0146\5;\34\2\u0146\u0147\3\2\2\2\u0147\u0148\b\33\5")
    buf.write(u"\2\u0148:\3\2\2\2\u0149\u014f\5E!\2\u014a\u014f\5G\"")
    buf.write(u"\2\u014b\u014f\5?\36\2\u014c\u014f\5A\37\2\u014d\u014f")
    buf.write(u"\5C \2\u014e\u0149\3\2\2\2\u014e\u014a\3\2\2\2\u014e")
    buf.write(u"\u014b\3\2\2\2\u014e\u014c\3\2\2\2\u014e\u014d\3\2\2")
    buf.write(u"\2\u014f<\3\2\2\2\u0150\u0152\t\13\2\2\u0151\u0150\3")
    buf.write(u"\2\2\2\u0152>\3\2\2\2\u0153\u0155\5=\35\2\u0154\u0153")
    buf.write(u"\3\2\2\2\u0155\u0156\3\2\2\2\u0156\u0154\3\2\2\2\u0156")
    buf.write(u"\u0157\3\2\2\2\u0157\u0159\3\2\2\2\u0158\u015a\7\"\2")
    buf.write(u"\2\u0159\u0158\3\2\2\2\u0159\u015a\3\2\2\2\u015a@\3\2")
    buf.write(u"\2\2\u015b\u015d\7%\2\2\u015c\u015e\t\5\2\2\u015d\u015c")
    buf.write(u"\3\2\2\2\u015e\u015f\3\2\2\2\u015f\u015d\3\2\2\2\u015f")
    buf.write(u"\u0160\3\2\2\2\u0160B\3\2\2\2\u0161\u0163\t\6\2\2\u0162")
    buf.write(u"\u0161\3\2\2\2\u0163\u0164\3\2\2\2\u0164\u0162\3\2\2")
    buf.write(u"\2\u0164\u0165\3\2\2\2\u0165\u0167\3\2\2\2\u0166\u0168")
    buf.write(u"\7\'\2\2\u0167\u0166\3\2\2\2\u0167\u0168\3\2\2\2\u0168")
    buf.write(u"D\3\2\2\2\u0169\u016d\7$\2\2\u016a\u016c\n\f\2\2\u016b")
    buf.write(u"\u016a\3\2\2\2\u016c\u016f\3\2\2\2\u016d\u016b\3\2\2")
    buf.write(u"\2\u016d\u016e\3\2\2\2\u016e\u0170\3\2\2\2\u016f\u016d")
    buf.write(u"\3\2\2\2\u0170\u0171\7$\2\2\u0171F\3\2\2\2\u0172\u0176")
    buf.write(u"\7)\2\2\u0173\u0175\n\r\2\2\u0174\u0173\3\2\2\2\u0175")
    buf.write(u"\u0178\3\2\2\2\u0176\u0174\3\2\2\2\u0176\u0177\3\2\2")
    buf.write(u"\2\u0177\u0179\3\2\2\2\u0178\u0176\3\2\2\2\u0179\u017a")
    buf.write(u"\7)\2\2\u017aH\3\2\2\2&\2\3\4\5\6Q_n\u0080\u008d\u0098")
    buf.write(u"\u00a3\u00a8\u00ac\u00af\u00b1\u00be\u00cf\u00dd\u00f2")
    buf.write(u"\u00ff\u0102\u0107\u0119\u0125\u0136\u0142\u014e\u0151")
    buf.write(u"\u0156\u0159\u015f\u0164\u0167\u016d\u0176\7\7\4\2\7")
    buf.write(u"\5\2\7\3\2\6\2\2\7\6\2")
    return buf.getvalue()


class HTMLLexer(Lexer):

  atn = ATNDeserializer().deserialize(serializedATN())

  decisionsToDFA = [DFA(ds, i) for i, ds in enumerate(atn.decisionToState)]

  TAG = 1
  SCRIPT = 2
  STYLE = 3
  ATTVALUE = 4

  HTML_COMMENT = 1
  HTML_CONDITIONAL_COMMENT = 2
  XML_DECLARATION = 3
  CDATA = 4
  DTD = 5
  SCRIPTLET = 6
  SEA_WS = 7
  SCRIPT_OPEN = 8
  STYLE_OPEN = 9
  TAG_OPEN = 10
  HTML_TEXT = 11
  TAG_CLOSE = 12
  TAG_SLASH_CLOSE = 13
  TAG_SLASH = 14
  TAG_EQUALS = 15
  TAG_NAME = 16
  TAG_WHITESPACE = 17
  SCRIPT_BODY = 18
  SCRIPT_SHORT_BODY = 19
  STYLE_BODY = 20
  STYLE_SHORT_BODY = 21
  ATTVALUE_VALUE = 22
  ATTRIBUTE = 23

  channelNames = [u"DEFAULT_TOKEN_CHANNEL", u"HIDDEN"]

  modeNames = [u"DEFAULT_MODE", u"TAG", u"SCRIPT", u"STYLE", u"ATTVALUE"]

  literalNames = [u"<INVALID>", u"'<'", u"'>'", u"'/>'", u"'/'", u"'='"]

  symbolicNames = [
      u"<INVALID>", u"HTML_COMMENT", u"HTML_CONDITIONAL_COMMENT",
      u"XML_DECLARATION", u"CDATA", u"DTD", u"SCRIPTLET", u"SEA_WS",
      u"SCRIPT_OPEN", u"STYLE_OPEN", u"TAG_OPEN", u"HTML_TEXT", u"TAG_CLOSE",
      u"TAG_SLASH_CLOSE", u"TAG_SLASH", u"TAG_EQUALS", u"TAG_NAME",
      u"TAG_WHITESPACE", u"SCRIPT_BODY", u"SCRIPT_SHORT_BODY", u"STYLE_BODY",
      u"STYLE_SHORT_BODY", u"ATTVALUE_VALUE", u"ATTRIBUTE"
  ]

  ruleNames = [
      u"HTML_COMMENT", u"HTML_CONDITIONAL_COMMENT", u"XML_DECLARATION",
      u"CDATA", u"DTD", u"SCRIPTLET", u"SEA_WS", u"SCRIPT_OPEN", u"STYLE_OPEN",
      u"TAG_OPEN", u"HTML_TEXT", u"TAG_CLOSE", u"TAG_SLASH_CLOSE", u"TAG_SLASH",
      u"TAG_EQUALS", u"TAG_NAME", u"TAG_WHITESPACE", u"HEXDIGIT", u"DIGIT",
      u"TAG_NameChar", u"TAG_NameStartChar", u"SCRIPT_BODY",
      u"SCRIPT_SHORT_BODY", u"STYLE_BODY", u"STYLE_SHORT_BODY",
      u"ATTVALUE_VALUE", u"ATTRIBUTE", u"ATTCHAR", u"ATTCHARS", u"HEXCHARS",
      u"DECCHARS", u"DOUBLE_QUOTE_STRING", u"SINGLE_QUOTE_STRING"
  ]

  grammarFileName = u"HTMLLexer.g4"

  def __init__(self, input=None, output=sys.stdout):
    super(HTMLLexer, self).__init__(input, output=output)
    self.checkVersion("4.7.1")
    self._interp = LexerATNSimulator(self, self.atn, self.decisionsToDFA,
                                     PredictionContextCache())
    self._actions = None
    self._predicates = None
