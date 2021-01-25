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
"""Translation from Java code for JavaScriptBaseLexer made to work with
JavaScriptLexer"""

from antlr4 import *
from io import StringIO
import sys

from .JavaScriptBaseLexer import JavaScriptBaseLexer


def serializedATN():
  with StringIO() as buf:
    buf.write(u"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2")
    buf.write(u"}\u0484\b\1\4\2\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4")
    buf.write(u"\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13\t\13\4\f\t\f\4\r")
    buf.write(u"\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22\t\22")
    buf.write(u"\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4")
    buf.write(u"\30\t\30\4\31\t\31\4\32\t\32\4\33\t\33\4\34\t\34\4\35")
    buf.write(u"\t\35\4\36\t\36\4\37\t\37\4 \t \4!\t!\4\"\t\"\4#\t#\4")
    buf.write(u"$\t$\4%\t%\4&\t&\4\'\t\'\4(\t(\4)\t)\4*\t*\4+\t+\4,\t")
    buf.write(u",\4-\t-\4.\t.\4/\t/\4\60\t\60\4\61\t\61\4\62\t\62\4\63")
    buf.write(u"\t\63\4\64\t\64\4\65\t\65\4\66\t\66\4\67\t\67\48\t8\4")
    buf.write(u"9\t9\4:\t:\4;\t;\4<\t<\4=\t=\4>\t>\4?\t?\4@\t@\4A\tA")
    buf.write(u"\4B\tB\4C\tC\4D\tD\4E\tE\4F\tF\4G\tG\4H\tH\4I\tI\4J\t")
    buf.write(u"J\4K\tK\4L\tL\4M\tM\4N\tN\4O\tO\4P\tP\4Q\tQ\4R\tR\4S")
    buf.write(u"\tS\4T\tT\4U\tU\4V\tV\4W\tW\4X\tX\4Y\tY\4Z\tZ\4[\t[\4")
    buf.write(u"\\\t\\\4]\t]\4^\t^\4_\t_\4`\t`\4a\ta\4b\tb\4c\tc\4d\t")
    buf.write(u"d\4e\te\4f\tf\4g\tg\4h\th\4i\ti\4j\tj\4k\tk\4l\tl\4m")
    buf.write(u"\tm\4n\tn\4o\to\4p\tp\4q\tq\4r\tr\4s\ts\4t\tt\4u\tu\4")
    buf.write(u"v\tv\4w\tw\4x\tx\4y\ty\4z\tz\4{\t{\4|\t|\4}\t}\4~\t~")
    buf.write(u"\4\177\t\177\4\u0080\t\u0080\4\u0081\t\u0081\4\u0082")
    buf.write(u"\t\u0082\4\u0083\t\u0083\4\u0084\t\u0084\4\u0085\t\u0085")
    buf.write(u"\4\u0086\t\u0086\4\u0087\t\u0087\4\u0088\t\u0088\4\u0089")
    buf.write(u"\t\u0089\4\u008a\t\u008a\4\u008b\t\u008b\4\u008c\t\u008c")
    buf.write(u"\4\u008d\t\u008d\4\u008e\t\u008e\4\u008f\t\u008f\4\u0090")
    buf.write(u"\t\u0090\4\u0091\t\u0091\4\u0092\t\u0092\4\u0093\t\u0093")
    buf.write(u"\4\u0094\t\u0094\3\2\3\2\3\2\3\2\3\2\7\2\u012f\n\2\f")
    buf.write(u"\2\16\2\u0132\13\2\3\3\3\3\3\3\3\3\7\3\u0138\n\3\f\3")
    buf.write(u"\16\3\u013b\13\3\3\3\3\3\3\3\3\3\3\3\3\4\3\4\3\4\3\4")
    buf.write(u"\7\4\u0146\n\4\f\4\16\4\u0149\13\4\3\4\3\4\3\5\3\5\3")
    buf.write(u"\5\7\5\u0150\n\5\f\5\16\5\u0153\13\5\3\5\3\5\3\5\7\5")
    buf.write(u"\u0158\n\5\f\5\16\5\u015b\13\5\3\6\3\6\3\7\3\7\3\b\3")
    buf.write(u"\b\3\t\3\t\3\n\3\n\3\n\3\13\3\13\3\13\3\f\3\f\3\r\3\r")
    buf.write(u"\3\16\3\16\3\17\3\17\3\20\3\20\3\21\3\21\3\21\3\21\3")
    buf.write(u"\22\3\22\3\23\3\23\3\23\3\24\3\24\3\24\3\25\3\25\3\26")
    buf.write(u"\3\26\3\27\3\27\3\30\3\30\3\31\3\31\3\32\3\32\3\33\3")
    buf.write(u"\33\3\34\3\34\3\34\3\35\3\35\3\35\3\36\3\36\3\37\3\37")
    buf.write(u"\3\37\3 \3 \3 \3!\3!\3!\3!\3\"\3\"\3#\3#\3$\3$\3$\3%")
    buf.write(u"\3%\3%\3&\3&\3&\3\'\3\'\3\'\3(\3(\3(\3(\3)\3)\3)\3)\3")
    buf.write(u"*\3*\3+\3+\3,\3,\3-\3-\3-\3.\3.\3.\3/\3/\3/\3\60\3\60")
    buf.write(u"\3\60\3\61\3\61\3\61\3\62\3\62\3\62\3\63\3\63\3\63\3")
    buf.write(u"\64\3\64\3\64\3\64\3\65\3\65\3\65\3\65\3\66\3\66\3\66")
    buf.write(u"\3\66\3\66\3\67\3\67\3\67\38\38\38\39\39\39\3:\3:\3:")
    buf.write(u"\3:\3;\3;\3;\3<\3<\3<\3<\3<\3=\3=\3=\3=\3=\3=\3=\3=\3")
    buf.write(u"=\5=\u01ff\n=\3>\3>\3>\3>\7>\u0205\n>\f>\16>\u0208\13")
    buf.write(u">\3>\5>\u020b\n>\3>\3>\3>\7>\u0210\n>\f>\16>\u0213\13")
    buf.write(u">\3>\5>\u0216\n>\3>\3>\5>\u021a\n>\5>\u021c\n>\3?\3?")
    buf.write(u"\3?\3?\7?\u0222\n?\f?\16?\u0225\13?\3@\3@\6@\u0229\n")
    buf.write(u"@\r@\16@\u022a\3@\3@\3A\3A\3A\3A\7A\u0233\nA\fA\16A\u0236")
    buf.write(u"\13A\3B\3B\3B\3B\7B\u023c\nB\fB\16B\u023f\13B\3C\3C\3")
    buf.write(u"C\3C\7C\u0245\nC\fC\16C\u0248\13C\3C\3C\3D\3D\3D\3D\7")
    buf.write(u"D\u0250\nD\fD\16D\u0253\13D\3D\3D\3E\3E\3E\3E\7E\u025b")
    buf.write(u"\nE\fE\16E\u025e\13E\3E\3E\3F\3F\3F\3G\3G\3G\3G\3G\3")
    buf.write(u"G\3H\3H\3H\3I\3I\3I\3I\3I\3I\3I\3I\3I\3I\3I\3J\3J\3J")
    buf.write(u"\3J\3J\3J\3J\3K\3K\3K\3K\3K\3L\3L\3L\3L\3L\3M\3M\3M\3")
    buf.write(u"M\3N\3N\3N\3N\3O\3O\3O\3O\3O\3O\3P\3P\3P\3P\3P\3P\3P")
    buf.write(u"\3P\3Q\3Q\3Q\3Q\3Q\3Q\3Q\3R\3R\3R\3R\3R\3S\3S\3S\3S\3")
    buf.write(u"S\3S\3S\3S\3S\3T\3T\3T\3T\3U\3U\3U\3U\3U\3U\3U\3V\3V")
    buf.write(u"\3V\3V\3V\3V\3W\3W\3W\3W\3W\3W\3W\3W\3W\3X\3X\3X\3X\3")
    buf.write(u"X\3X\3X\3X\3X\3Y\3Y\3Y\3Y\3Y\3Z\3Z\3Z\3Z\3Z\3[\3[\3[")
    buf.write(u"\3[\3[\3[\3[\3[\3\\\3\\\3\\\3]\3]\3]\3]\3]\3]\3^\3^\3")
    buf.write(u"^\3^\3^\3^\3^\3_\3_\3_\3`\3`\3`\3`\3a\3a\3a\3b\3b\3b")
    buf.write(u"\3b\3b\3c\3c\3c\3c\3c\3c\3d\3d\3d\3d\3d\3e\3e\3e\3e\3")
    buf.write(u"e\3e\3e\3e\3f\3f\3f\3f\3f\3f\3g\3g\3g\3g\3g\3g\3h\3h")
    buf.write(u"\3h\3h\3h\3h\3h\3i\3i\3i\3i\3i\3i\3i\3j\3j\3j\3j\3j\3")
    buf.write(u"j\3k\3k\3k\3k\3k\3k\3l\3l\3l\3l\3l\3l\3l\3l\3l\3l\3l")
    buf.write(u"\3l\3l\3m\3m\3m\3m\3m\3m\3n\3n\3n\3n\3n\3n\3n\3n\3n\3")
    buf.write(u"n\3o\3o\3o\3o\3o\3o\3o\3o\3o\3p\3p\3p\3p\3p\3p\3p\3p")
    buf.write(u"\3p\3p\3p\3p\3q\3q\3q\3q\3q\3q\3q\3q\3q\3q\3r\3r\3r\3")
    buf.write(u"r\3r\3r\3r\3r\3r\3r\3r\3r\3s\3s\3s\3s\3s\3s\3s\3s\3s")
    buf.write(u"\3t\3t\3t\3t\3t\3t\3t\3t\3u\3u\7u\u039d\nu\fu\16u\u03a0")
    buf.write(u"\13u\3v\3v\7v\u03a4\nv\fv\16v\u03a7\13v\3v\3v\3v\7v\u03ac")
    buf.write(u"\nv\fv\16v\u03af\13v\3v\5v\u03b2\nv\3v\3v\3w\3w\3w\3")
    buf.write(u"w\7w\u03ba\nw\fw\16w\u03bd\13w\3w\3w\3x\6x\u03c2\nx\r")
    buf.write(u"x\16x\u03c3\3x\3x\3y\3y\3y\3y\3z\3z\3z\3z\3z\3z\7z\u03d2")
    buf.write(u"\nz\fz\16z\u03d5\13z\3z\3z\3z\3z\3z\3z\3{\3{\3{\3{\3")
    buf.write(u"{\3{\3{\3{\3{\3{\3{\7{\u03e8\n{\f{\16{\u03eb\13{\3{\3")
    buf.write(u"{\3{\3{\3{\3{\3|\3|\3|\3|\3}\3}\3}\3}\5}\u03fb\n}\3~")
    buf.write(u"\3~\3~\3~\5~\u0401\n~\3\177\3\177\3\177\3\177\3\177\5")
    buf.write(u"\177\u0408\n\177\3\u0080\3\u0080\5\u0080\u040c\n\u0080")
    buf.write(u"\3\u0081\3\u0081\3\u0081\3\u0081\3\u0082\3\u0082\3\u0082")
    buf.write(u"\3\u0082\3\u0082\3\u0082\3\u0082\3\u0082\3\u0082\3\u0082")
    buf.write(u"\6\u0082\u041c\n\u0082\r\u0082\16\u0082\u041d\3\u0082")
    buf.write(u"\3\u0082\5\u0082\u0422\n\u0082\3\u0083\3\u0083\3\u0083")
    buf.write(u"\6\u0083\u0427\n\u0083\r\u0083\16\u0083\u0428\3\u0083")
    buf.write(u"\3\u0083\3\u0084\3\u0084\3\u0085\3\u0085\3\u0086\3\u0086")
    buf.write(u"\5\u0086\u0433\n\u0086\3\u0087\3\u0087\3\u0087\3\u0088")
    buf.write(u"\3\u0088\3\u0089\3\u0089\3\u0089\7\u0089\u043d\n\u0089")
    buf.write(u"\f\u0089\16\u0089\u0440\13\u0089\5\u0089\u0442\n\u0089")
    buf.write(u"\3\u008a\3\u008a\5\u008a\u0446\n\u008a\3\u008a\6\u008a")
    buf.write(u"\u0449\n\u008a\r\u008a\16\u008a\u044a\3\u008b\3\u008b")
    buf.write(u"\3\u008b\3\u008b\3\u008b\5\u008b\u0452\n\u008b\3\u008c")
    buf.write(u"\3\u008c\3\u008c\3\u008c\5\u008c\u0458\n\u008c\3\u008d")
    buf.write(u"\5\u008d\u045b\n\u008d\3\u008e\5\u008e\u045e\n\u008e")
    buf.write(u"\3\u008f\5\u008f\u0461\n\u008f\3\u0090\5\u0090\u0464")
    buf.write(u"\n\u0090\3\u0091\3\u0091\3\u0091\3\u0091\7\u0091\u046a")
    buf.write(u"\n\u0091\f\u0091\16\u0091\u046d\13\u0091\3\u0091\5\u0091")
    buf.write(u"\u0470\n\u0091\3\u0092\3\u0092\3\u0092\3\u0092\7\u0092")
    buf.write(u"\u0476\n\u0092\f\u0092\16\u0092\u0479\13\u0092\3\u0092")
    buf.write(u"\5\u0092\u047c\n\u0092\3\u0093\3\u0093\5\u0093\u0480")
    buf.write(u"\n\u0093\3\u0094\3\u0094\3\u0094\5\u0139\u03d3\u03e9")
    buf.write(u"\2\u0095\3\3\5\4\7\5\t\6\13\7\r\b\17\t\21\n\23\13\25")
    buf.write(u"\f\27\r\31\16\33\17\35\20\37\21!\22#\23%\24\'\25)\26")
    buf.write(u"+\27-\30/\31\61\32\63\33\65\34\67\359\36;\37= ?!A\"C")
    buf.write(u"#E$G%I&K\'M(O)Q*S+U,W-Y.[/]\60_\61a\62c\63e\64g\65i\66")
    buf.write(u"k\67m8o9q:s;u<w=y>{?}@\177A\u0081B\u0083C\u0085D\u0087")
    buf.write(u"E\u0089F\u008bG\u008dH\u008fI\u0091J\u0093K\u0095L\u0097")
    buf.write(u"M\u0099N\u009bO\u009dP\u009fQ\u00a1R\u00a3S\u00a5T\u00a7")
    buf.write(u"U\u00a9V\u00abW\u00adX\u00afY\u00b1Z\u00b3[\u00b5\\\u00b7")
    buf.write(u"]\u00b9^\u00bb_\u00bd`\u00bfa\u00c1b\u00c3c\u00c5d\u00c7")
    buf.write(u"e\u00c9f\u00cbg\u00cdh\u00cfi\u00d1j\u00d3k\u00d5l\u00d7")
    buf.write(u"m\u00d9n\u00dbo\u00ddp\u00dfq\u00e1r\u00e3s\u00e5t\u00e7")
    buf.write(u"u\u00e9v\u00ebw\u00edx\u00efy\u00f1z\u00f3{\u00f5|\u00f7")
    buf.write(u"}\u00f9\2\u00fb\2\u00fd\2\u00ff\2\u0101\2\u0103\2\u0105")
    buf.write(u"\2\u0107\2\u0109\2\u010b\2\u010d\2\u010f\2\u0111\2\u0113")
    buf.write(u"\2\u0115\2\u0117\2\u0119\2\u011b\2\u011d\2\u011f\2\u0121")
    buf.write(u"\2\u0123\2\u0125\2\u0127\2\3\2 \5\2\f\f\17\17\u202a\u202b")
    buf.write(u"\3\2\62;\4\2\62;aa\4\2ZZzz\5\2\62;CHch\3\2\629\4\2QQ")
    buf.write(u"qq\4\2\629aa\4\2DDdd\3\2\62\63\4\2\62\63aa\3\2bb\6\2")
    buf.write(u"\13\13\r\16\"\"\u00a2\u00a2\6\2\f\f\17\17$$^^\6\2\f\f")
    buf.write(u"\17\17))^^\13\2$$))^^ddhhppttvvxx\16\2\f\f\17\17$$))")
    buf.write(u"\62;^^ddhhppttvxzz\5\2\62;wwzz\6\2\62;CHaach\3\2\63;")
    buf.write(u"\4\2GGgg\4\2--//\4\2&&aa\u0101\2C\\c|\u00ac\u00ac\u00b7")
    buf.write(u"\u00b7\u00bc\u00bc\u00c2\u00d8\u00da\u00f8\u00fa\u0221")
    buf.write(u"\u0224\u0235\u0252\u02af\u02b2\u02ba\u02bd\u02c3\u02d2")
    buf.write(u"\u02d3\u02e2\u02e6\u02f0\u02f0\u037c\u037c\u0388\u0388")
    buf.write(u"\u038a\u038c\u038e\u038e\u0390\u03a3\u03a5\u03d0\u03d2")
    buf.write(u"\u03d9\u03dc\u03f5\u0402\u0483\u048e\u04c6\u04c9\u04ca")
    buf.write(u"\u04cd\u04ce\u04d2\u04f7\u04fa\u04fb\u0533\u0558\u055b")
    buf.write(u"\u055b\u0563\u0589\u05d2\u05ec\u05f2\u05f4\u0623\u063c")
    buf.write(u"\u0642\u064c\u0673\u06d5\u06d7\u06d7\u06e7\u06e8\u06fc")
    buf.write(u"\u06fe\u0712\u0712\u0714\u072e\u0782\u07a7\u0907\u093b")
    buf.write(u"\u093f\u093f\u0952\u0952\u095a\u0963\u0987\u098e\u0991")
    buf.write(u"\u0992\u0995\u09aa\u09ac\u09b2\u09b4\u09b4\u09b8\u09bb")
    buf.write(u"\u09de\u09df\u09e1\u09e3\u09f2\u09f3\u0a07\u0a0c\u0a11")
    buf.write(u"\u0a12\u0a15\u0a2a\u0a2c\u0a32\u0a34\u0a35\u0a37\u0a38")
    buf.write(u"\u0a3a\u0a3b\u0a5b\u0a5e\u0a60\u0a60\u0a74\u0a76\u0a87")
    buf.write(u"\u0a8d\u0a8f\u0a8f\u0a91\u0a93\u0a95\u0aaa\u0aac\u0ab2")
    buf.write(u"\u0ab4\u0ab5\u0ab7\u0abb\u0abf\u0abf\u0ad2\u0ad2\u0ae2")
    buf.write(u"\u0ae2\u0b07\u0b0e\u0b11\u0b12\u0b15\u0b2a\u0b2c\u0b32")
    buf.write(u"\u0b34\u0b35\u0b38\u0b3b\u0b3f\u0b3f\u0b5e\u0b5f\u0b61")
    buf.write(u"\u0b63\u0b87\u0b8c\u0b90\u0b92\u0b94\u0b97\u0b9b\u0b9c")
    buf.write(u"\u0b9e\u0b9e\u0ba0\u0ba1\u0ba5\u0ba6\u0baa\u0bac\u0bb0")
    buf.write(u"\u0bb7\u0bb9\u0bbb\u0c07\u0c0e\u0c10\u0c12\u0c14\u0c2a")
    buf.write(u"\u0c2c\u0c35\u0c37\u0c3b\u0c62\u0c63\u0c87\u0c8e\u0c90")
    buf.write(u"\u0c92\u0c94\u0caa\u0cac\u0cb5\u0cb7\u0cbb\u0ce0\u0ce0")
    buf.write(u"\u0ce2\u0ce3\u0d07\u0d0e\u0d10\u0d12\u0d14\u0d2a\u0d2c")
    buf.write(u"\u0d3b\u0d62\u0d63\u0d87\u0d98\u0d9c\u0db3\u0db5\u0dbd")
    buf.write(u"\u0dbf\u0dbf\u0dc2\u0dc8\u0e03\u0e32\u0e34\u0e35\u0e42")
    buf.write(u"\u0e48\u0e83\u0e84\u0e86\u0e86\u0e89\u0e8a\u0e8c\u0e8c")
    buf.write(u"\u0e8f\u0e8f\u0e96\u0e99\u0e9b\u0ea1\u0ea3\u0ea5\u0ea7")
    buf.write(u"\u0ea7\u0ea9\u0ea9\u0eac\u0ead\u0eaf\u0eb2\u0eb4\u0eb5")
    buf.write(u"\u0ebf\u0ec6\u0ec8\u0ec8\u0ede\u0edf\u0f02\u0f02\u0f42")
    buf.write(u"\u0f6c\u0f8a\u0f8d\u1002\u1023\u1025\u1029\u102b\u102c")
    buf.write(u"\u1052\u1057\u10a2\u10c7\u10d2\u10f8\u1102\u115b\u1161")
    buf.write(u"\u11a4\u11aa\u11fb\u1202\u1208\u120a\u1248\u124a\u124a")
    buf.write(u"\u124c\u124f\u1252\u1258\u125a\u125a\u125c\u125f\u1262")
    buf.write(u"\u1288\u128a\u128a\u128c\u128f\u1292\u12b0\u12b2\u12b2")
    buf.write(u"\u12b4\u12b7\u12ba\u12c0\u12c2\u12c2\u12c4\u12c7\u12ca")
    buf.write(u"\u12d0\u12d2\u12d8\u12da\u12f0\u12f2\u1310\u1312\u1312")
    buf.write(u"\u1314\u1317\u131a\u1320\u1322\u1348\u134a\u135c\u13a2")
    buf.write(u"\u13f6\u1403\u1678\u1683\u169c\u16a2\u16ec\u1782\u17b5")
    buf.write(u"\u1822\u1879\u1882\u18aa\u1e02\u1e9d\u1ea2\u1efb\u1f02")
    buf.write(u"\u1f17\u1f1a\u1f1f\u1f22\u1f47\u1f4a\u1f4f\u1f52\u1f59")
    buf.write(u"\u1f5b\u1f5b\u1f5d\u1f5d\u1f5f\u1f5f\u1f61\u1f7f\u1f82")
    buf.write(u"\u1fb6\u1fb8\u1fbe\u1fc0\u1fc0\u1fc4\u1fc6\u1fc8\u1fce")
    buf.write(u"\u1fd2\u1fd5\u1fd8\u1fdd\u1fe2\u1fee\u1ff4\u1ff6\u1ff8")
    buf.write(u"\u1ffe\u2081\u2081\u2104\u2104\u2109\u2109\u210c\u2115")
    buf.write(u"\u2117\u2117\u211b\u211f\u2126\u2126\u2128\u2128\u212a")
    buf.write(u"\u212a\u212c\u212f\u2131\u2133\u2135\u213b\u2162\u2185")
    buf.write(u"\u3007\u3009\u3023\u302b\u3033\u3037\u303a\u303c\u3043")
    buf.write(u"\u3096\u309f\u30a0\u30a3\u30fc\u30fe\u3100\u3107\u312e")
    buf.write(u"\u3133\u3190\u31a2\u31b9\u3402\u4dc1\u4e02\ua48e\uac02")
    buf.write(u"\uac02\ud7a5\ud7a5\uf902\ufa2f\ufb02\ufb08\ufb15\ufb19")
    buf.write(u"\ufb1f\ufb1f\ufb21\ufb2a\ufb2c\ufb38\ufb3a\ufb3e\ufb40")
    buf.write(u"\ufb40\ufb42\ufb43\ufb45\ufb46\ufb48\ufbb3\ufbd5\ufd3f")
    buf.write(u"\ufd52\ufd91\ufd94\ufdc9\ufdf2\ufdfd\ufe72\ufe74\ufe76")
    buf.write(u"\ufe76\ufe78\ufefe\uff23\uff3c\uff43\uff5c\uff68\uffc0")
    buf.write(u"\uffc4\uffc9\uffcc\uffd1\uffd4\uffd9\uffdc\uffdef\2\u0302")
    buf.write(u"\u0350\u0362\u0364\u0485\u0488\u0593\u05a3\u05a5\u05bb")
    buf.write(u"\u05bd\u05bf\u05c1\u05c1\u05c3\u05c4\u05c6\u05c6\u064d")
    buf.write(u"\u0657\u0672\u0672\u06d8\u06de\u06e1\u06e6\u06e9\u06ea")
    buf.write(u"\u06ec\u06ef\u0713\u0713\u0732\u074c\u07a8\u07b2\u0903")
    buf.write(u"\u0905\u093e\u093e\u0940\u094f\u0953\u0956\u0964\u0965")
    buf.write(u"\u0983\u0985\u09be\u09c6\u09c9\u09ca\u09cd\u09cf\u09d9")
    buf.write(u"\u09d9\u09e4\u09e5\u0a04\u0a04\u0a3e\u0a3e\u0a40\u0a44")
    buf.write(u"\u0a49\u0a4a\u0a4d\u0a4f\u0a72\u0a73\u0a83\u0a85\u0abe")
    buf.write(u"\u0abe\u0ac0\u0ac7\u0ac9\u0acb\u0acd\u0acf\u0b03\u0b05")
    buf.write(u"\u0b3e\u0b3e\u0b40\u0b45\u0b49\u0b4a\u0b4d\u0b4f\u0b58")
    buf.write(u"\u0b59\u0b84\u0b85\u0bc0\u0bc4\u0bc8\u0bca\u0bcc\u0bcf")
    buf.write(u"\u0bd9\u0bd9\u0c03\u0c05\u0c40\u0c46\u0c48\u0c4a\u0c4c")
    buf.write(u"\u0c4f\u0c57\u0c58\u0c84\u0c85\u0cc0\u0cc6\u0cc8\u0cca")
    buf.write(u"\u0ccc\u0ccf\u0cd7\u0cd8\u0d04\u0d05\u0d40\u0d45\u0d48")
    buf.write(u"\u0d4a\u0d4c\u0d4f\u0d59\u0d59\u0d84\u0d85\u0dcc\u0dcc")
    buf.write(u"\u0dd1\u0dd6\u0dd8\u0dd8\u0dda\u0de1\u0df4\u0df5\u0e33")
    buf.write(u"\u0e33\u0e36\u0e3c\u0e49\u0e50\u0eb3\u0eb3\u0eb6\u0ebb")
    buf.write(u"\u0ebd\u0ebe\u0eca\u0ecf\u0f1a\u0f1b\u0f37\u0f37\u0f39")
    buf.write(u"\u0f39\u0f3b\u0f3b\u0f40\u0f41\u0f73\u0f86\u0f88\u0f89")
    buf.write(u"\u0f92\u0f99\u0f9b\u0fbe\u0fc8\u0fc8\u102e\u1034\u1038")
    buf.write(u"\u103b\u1058\u105b\u17b6\u17d5\u18ab\u18ab\u20d2\u20de")
    buf.write(u"\u20e3\u20e3\u302c\u3031\u309b\u309c\ufb20\ufb20\ufe22")
    buf.write(u"\ufe25\26\2\62;\u0662\u066b\u06f2\u06fb\u0968\u0971\u09e8")
    buf.write(u"\u09f1\u0a68\u0a71\u0ae8\u0af1\u0b68\u0b71\u0be9\u0bf1")
    buf.write(u"\u0c68\u0c71\u0ce8\u0cf1\u0d68\u0d71\u0e52\u0e5b\u0ed2")
    buf.write(u"\u0edb\u0f22\u0f2b\u1042\u104b\u136b\u1373\u17e2\u17eb")
    buf.write(u"\u1812\u181b\uff12\uff1b\t\2aa\u2041\u2042\u30fd\u30fd")
    buf.write(u"\ufe35\ufe36\ufe4f\ufe51\uff41\uff41\uff67\uff67\b\2")
    buf.write(u"\f\f\17\17,,\61\61]^\u202a\u202b\7\2\f\f\17\17\61\61")
    buf.write(u"]^\u202a\u202b\6\2\f\f\17\17^_\u202a\u202b\2\u04a6\2")
    buf.write(u"\3\3\2\2\2\2\5\3\2\2\2\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3")
    buf.write(u"\2\2\2\2\r\3\2\2\2\2\17\3\2\2\2\2\21\3\2\2\2\2\23\3\2")
    buf.write(u"\2\2\2\25\3\2\2\2\2\27\3\2\2\2\2\31\3\2\2\2\2\33\3\2")
    buf.write(u"\2\2\2\35\3\2\2\2\2\37\3\2\2\2\2!\3\2\2\2\2#\3\2\2\2")
    buf.write(u"\2%\3\2\2\2\2\'\3\2\2\2\2)\3\2\2\2\2+\3\2\2\2\2-\3\2")
    buf.write(u"\2\2\2/\3\2\2\2\2\61\3\2\2\2\2\63\3\2\2\2\2\65\3\2\2")
    buf.write(u"\2\2\67\3\2\2\2\29\3\2\2\2\2;\3\2\2\2\2=\3\2\2\2\2?\3")
    buf.write(u"\2\2\2\2A\3\2\2\2\2C\3\2\2\2\2E\3\2\2\2\2G\3\2\2\2\2")
    buf.write(u"I\3\2\2\2\2K\3\2\2\2\2M\3\2\2\2\2O\3\2\2\2\2Q\3\2\2\2")
    buf.write(u"\2S\3\2\2\2\2U\3\2\2\2\2W\3\2\2\2\2Y\3\2\2\2\2[\3\2\2")
    buf.write(u"\2\2]\3\2\2\2\2_\3\2\2\2\2a\3\2\2\2\2c\3\2\2\2\2e\3\2")
    buf.write(u"\2\2\2g\3\2\2\2\2i\3\2\2\2\2k\3\2\2\2\2m\3\2\2\2\2o\3")
    buf.write(u"\2\2\2\2q\3\2\2\2\2s\3\2\2\2\2u\3\2\2\2\2w\3\2\2\2\2")
    buf.write(u"y\3\2\2\2\2{\3\2\2\2\2}\3\2\2\2\2\177\3\2\2\2\2\u0081")
    buf.write(u"\3\2\2\2\2\u0083\3\2\2\2\2\u0085\3\2\2\2\2\u0087\3\2")
    buf.write(u"\2\2\2\u0089\3\2\2\2\2\u008b\3\2\2\2\2\u008d\3\2\2\2")
    buf.write(u"\2\u008f\3\2\2\2\2\u0091\3\2\2\2\2\u0093\3\2\2\2\2\u0095")
    buf.write(u"\3\2\2\2\2\u0097\3\2\2\2\2\u0099\3\2\2\2\2\u009b\3\2")
    buf.write(u"\2\2\2\u009d\3\2\2\2\2\u009f\3\2\2\2\2\u00a1\3\2\2\2")
    buf.write(u"\2\u00a3\3\2\2\2\2\u00a5\3\2\2\2\2\u00a7\3\2\2\2\2\u00a9")
    buf.write(u"\3\2\2\2\2\u00ab\3\2\2\2\2\u00ad\3\2\2\2\2\u00af\3\2")
    buf.write(u"\2\2\2\u00b1\3\2\2\2\2\u00b3\3\2\2\2\2\u00b5\3\2\2\2")
    buf.write(u"\2\u00b7\3\2\2\2\2\u00b9\3\2\2\2\2\u00bb\3\2\2\2\2\u00bd")
    buf.write(u"\3\2\2\2\2\u00bf\3\2\2\2\2\u00c1\3\2\2\2\2\u00c3\3\2")
    buf.write(u"\2\2\2\u00c5\3\2\2\2\2\u00c7\3\2\2\2\2\u00c9\3\2\2\2")
    buf.write(u"\2\u00cb\3\2\2\2\2\u00cd\3\2\2\2\2\u00cf\3\2\2\2\2\u00d1")
    buf.write(u"\3\2\2\2\2\u00d3\3\2\2\2\2\u00d5\3\2\2\2\2\u00d7\3\2")
    buf.write(u"\2\2\2\u00d9\3\2\2\2\2\u00db\3\2\2\2\2\u00dd\3\2\2\2")
    buf.write(u"\2\u00df\3\2\2\2\2\u00e1\3\2\2\2\2\u00e3\3\2\2\2\2\u00e5")
    buf.write(u"\3\2\2\2\2\u00e7\3\2\2\2\2\u00e9\3\2\2\2\2\u00eb\3\2")
    buf.write(u"\2\2\2\u00ed\3\2\2\2\2\u00ef\3\2\2\2\2\u00f1\3\2\2\2")
    buf.write(u"\2\u00f3\3\2\2\2\2\u00f5\3\2\2\2\2\u00f7\3\2\2\2\3\u0129")
    buf.write(u"\3\2\2\2\5\u0133\3\2\2\2\7\u0141\3\2\2\2\t\u014c\3\2")
    buf.write(u"\2\2\13\u015c\3\2\2\2\r\u015e\3\2\2\2\17\u0160\3\2\2")
    buf.write(u"\2\21\u0162\3\2\2\2\23\u0164\3\2\2\2\25\u0167\3\2\2\2")
    buf.write(u"\27\u016a\3\2\2\2\31\u016c\3\2\2\2\33\u016e\3\2\2\2\35")
    buf.write(u"\u0170\3\2\2\2\37\u0172\3\2\2\2!\u0174\3\2\2\2#\u0178")
    buf.write(u"\3\2\2\2%\u017a\3\2\2\2\'\u017d\3\2\2\2)\u0180\3\2\2")
    buf.write(u"\2+\u0182\3\2\2\2-\u0184\3\2\2\2/\u0186\3\2\2\2\61\u0188")
    buf.write(u"\3\2\2\2\63\u018a\3\2\2\2\65\u018c\3\2\2\2\67\u018e\3")
    buf.write(u"\2\2\29\u0191\3\2\2\2;\u0194\3\2\2\2=\u0196\3\2\2\2?")
    buf.write(u"\u0199\3\2\2\2A\u019c\3\2\2\2C\u01a0\3\2\2\2E\u01a2\3")
    buf.write(u"\2\2\2G\u01a4\3\2\2\2I\u01a7\3\2\2\2K\u01aa\3\2\2\2M")
    buf.write(u"\u01ad\3\2\2\2O\u01b0\3\2\2\2Q\u01b4\3\2\2\2S\u01b8\3")
    buf.write(u"\2\2\2U\u01ba\3\2\2\2W\u01bc\3\2\2\2Y\u01be\3\2\2\2[")
    buf.write(u"\u01c1\3\2\2\2]\u01c4\3\2\2\2_\u01c7\3\2\2\2a\u01ca\3")
    buf.write(u"\2\2\2c\u01cd\3\2\2\2e\u01d0\3\2\2\2g\u01d3\3\2\2\2i")
    buf.write(u"\u01d7\3\2\2\2k\u01db\3\2\2\2m\u01e0\3\2\2\2o\u01e3\3")
    buf.write(u"\2\2\2q\u01e6\3\2\2\2s\u01e9\3\2\2\2u\u01ed\3\2\2\2w")
    buf.write(u"\u01f0\3\2\2\2y\u01fe\3\2\2\2{\u021b\3\2\2\2}\u021d\3")
    buf.write(u"\2\2\2\177\u0226\3\2\2\2\u0081\u022e\3\2\2\2\u0083\u0237")
    buf.write(u"\3\2\2\2\u0085\u0240\3\2\2\2\u0087\u024b\3\2\2\2\u0089")
    buf.write(u"\u0256\3\2\2\2\u008b\u0261\3\2\2\2\u008d\u0264\3\2\2")
    buf.write(u"\2\u008f\u026a\3\2\2\2\u0091\u026d\3\2\2\2\u0093\u0278")
    buf.write(u"\3\2\2\2\u0095\u027f\3\2\2\2\u0097\u0284\3\2\2\2\u0099")
    buf.write(u"\u0289\3\2\2\2\u009b\u028d\3\2\2\2\u009d\u0291\3\2\2")
    buf.write(u"\2\u009f\u0297\3\2\2\2\u00a1\u029f\3\2\2\2\u00a3\u02a6")
    buf.write(u"\3\2\2\2\u00a5\u02ab\3\2\2\2\u00a7\u02b4\3\2\2\2\u00a9")
    buf.write(u"\u02b8\3\2\2\2\u00ab\u02bf\3\2\2\2\u00ad\u02c5\3\2\2")
    buf.write(u"\2\u00af\u02ce\3\2\2\2\u00b1\u02d7\3\2\2\2\u00b3\u02dc")
    buf.write(u"\3\2\2\2\u00b5\u02e1\3\2\2\2\u00b7\u02e9\3\2\2\2\u00b9")
    buf.write(u"\u02ec\3\2\2\2\u00bb\u02f2\3\2\2\2\u00bd\u02f9\3\2\2")
    buf.write(u"\2\u00bf\u02fc\3\2\2\2\u00c1\u0300\3\2\2\2\u00c3\u0303")
    buf.write(u"\3\2\2\2\u00c5\u0308\3\2\2\2\u00c7\u030e\3\2\2\2\u00c9")
    buf.write(u"\u0313\3\2\2\2\u00cb\u031b\3\2\2\2\u00cd\u0321\3\2\2")
    buf.write(u"\2\u00cf\u0327\3\2\2\2\u00d1\u032e\3\2\2\2\u00d3\u0335")
    buf.write(u"\3\2\2\2\u00d5\u033b\3\2\2\2\u00d7\u0341\3\2\2\2\u00d9")
    buf.write(u"\u034e\3\2\2\2\u00db\u0354\3\2\2\2\u00dd\u035e\3\2\2")
    buf.write(u"\2\u00df\u0367\3\2\2\2\u00e1\u0373\3\2\2\2\u00e3\u037d")
    buf.write(u"\3\2\2\2\u00e5\u0389\3\2\2\2\u00e7\u0392\3\2\2\2\u00e9")
    buf.write(u"\u039a\3\2\2\2\u00eb\u03b1\3\2\2\2\u00ed\u03b5\3\2\2")
    buf.write(u"\2\u00ef\u03c1\3\2\2\2\u00f1\u03c7\3\2\2\2\u00f3\u03cb")
    buf.write(u"\3\2\2\2\u00f5\u03dc\3\2\2\2\u00f7\u03f2\3\2\2\2\u00f9")
    buf.write(u"\u03fa\3\2\2\2\u00fb\u0400\3\2\2\2\u00fd\u0407\3\2\2")
    buf.write(u"\2\u00ff\u040b\3\2\2\2\u0101\u040d\3\2\2\2\u0103\u0421")
    buf.write(u"\3\2\2\2\u0105\u0423\3\2\2\2\u0107\u042c\3\2\2\2\u0109")
    buf.write(u"\u042e\3\2\2\2\u010b\u0432\3\2\2\2\u010d\u0434\3\2\2")
    buf.write(u"\2\u010f\u0437\3\2\2\2\u0111\u0441\3\2\2\2\u0113\u0443")
    buf.write(u"\3\2\2\2\u0115\u0451\3\2\2\2\u0117\u0457\3\2\2\2\u0119")
    buf.write(u"\u045a\3\2\2\2\u011b\u045d\3\2\2\2\u011d\u0460\3\2\2")
    buf.write(u"\2\u011f\u0463\3\2\2\2\u0121\u046f\3\2\2\2\u0123\u047b")
    buf.write(u"\3\2\2\2\u0125\u047f\3\2\2\2\u0127\u0481\3\2\2\2\u0129")
    buf.write(u"\u012a\6\2\2\2\u012a\u012b\7%\2\2\u012b\u012c\7#\2\2")
    buf.write(u"\u012c\u0130\3\2\2\2\u012d\u012f\n\2\2\2\u012e\u012d")
    buf.write(u"\3\2\2\2\u012f\u0132\3\2\2\2\u0130\u012e\3\2\2\2\u0130")
    buf.write(u"\u0131\3\2\2\2\u0131\4\3\2\2\2\u0132\u0130\3\2\2\2\u0133")
    buf.write(u"\u0134\7\61\2\2\u0134\u0135\7,\2\2\u0135\u0139\3\2\2")
    buf.write(u"\2\u0136\u0138\13\2\2\2\u0137\u0136\3\2\2\2\u0138\u013b")
    buf.write(u"\3\2\2\2\u0139\u013a\3\2\2\2\u0139\u0137\3\2\2\2\u013a")
    buf.write(u"\u013c\3\2\2\2\u013b\u0139\3\2\2\2\u013c\u013d\7,\2\2")
    buf.write(u"\u013d\u013e\7\61\2\2\u013e\u013f\3\2\2\2\u013f\u0140")
    buf.write(u"\b\3\2\2\u0140\6\3\2\2\2\u0141\u0142\7\61\2\2\u0142\u0143")
    buf.write(u"\7\61\2\2\u0143\u0147\3\2\2\2\u0144\u0146\n\2\2\2\u0145")
    buf.write(u"\u0144\3\2\2\2\u0146\u0149\3\2\2\2\u0147\u0145\3\2\2")
    buf.write(u"\2\u0147\u0148\3\2\2\2\u0148\u014a\3\2\2\2\u0149\u0147")
    buf.write(u"\3\2\2\2\u014a\u014b\b\4\2\2\u014b\b\3\2\2\2\u014c\u014d")
    buf.write(u"\7\61\2\2\u014d\u0151\5\u0121\u0091\2\u014e\u0150\5\u0123")
    buf.write(u"\u0092\2\u014f\u014e\3\2\2\2\u0150\u0153\3\2\2\2\u0151")
    buf.write(u"\u014f\3\2\2\2\u0151\u0152\3\2\2\2\u0152\u0154\3\2\2")
    buf.write(u"\2\u0153\u0151\3\2\2\2\u0154\u0155\6\5\3\2\u0155\u0159")
    buf.write(u"\7\61\2\2\u0156\u0158\5\u0115\u008b\2\u0157\u0156\3\2")
    buf.write(u"\2\2\u0158\u015b\3\2\2\2\u0159\u0157\3\2\2\2\u0159\u015a")
    buf.write(u"\3\2\2\2\u015a\n\3\2\2\2\u015b\u0159\3\2\2\2\u015c\u015d")
    buf.write(u"\7]\2\2\u015d\f\3\2\2\2\u015e\u015f\7_\2\2\u015f\16\3")
    buf.write(u"\2\2\2\u0160\u0161\7*\2\2\u0161\20\3\2\2\2\u0162\u0163")
    buf.write(u"\7+\2\2\u0163\22\3\2\2\2\u0164\u0165\7}\2\2\u0165\u0166")
    buf.write(u"\b\n\3\2\u0166\24\3\2\2\2\u0167\u0168\7\177\2\2\u0168")
    buf.write(u"\u0169\b\13\4\2\u0169\26\3\2\2\2\u016a\u016b\7=\2\2\u016b")
    buf.write(u"\30\3\2\2\2\u016c\u016d\7.\2\2\u016d\32\3\2\2\2\u016e")
    buf.write(u"\u016f\7?\2\2\u016f\34\3\2\2\2\u0170\u0171\7A\2\2\u0171")
    buf.write(u"\36\3\2\2\2\u0172\u0173\7<\2\2\u0173 \3\2\2\2\u0174\u0175")
    buf.write(u"\7\60\2\2\u0175\u0176\7\60\2\2\u0176\u0177\7\60\2\2\u0177")
    buf.write(u"\"\3\2\2\2\u0178\u0179\7\60\2\2\u0179$\3\2\2\2\u017a")
    buf.write(u"\u017b\7-\2\2\u017b\u017c\7-\2\2\u017c&\3\2\2\2\u017d")
    buf.write(u"\u017e\7/\2\2\u017e\u017f\7/\2\2\u017f(\3\2\2\2\u0180")
    buf.write(u"\u0181\7-\2\2\u0181*\3\2\2\2\u0182\u0183\7/\2\2\u0183")
    buf.write(u",\3\2\2\2\u0184\u0185\7\u0080\2\2\u0185.\3\2\2\2\u0186")
    buf.write(u"\u0187\7#\2\2\u0187\60\3\2\2\2\u0188\u0189\7,\2\2\u0189")
    buf.write(u"\62\3\2\2\2\u018a\u018b\7\61\2\2\u018b\64\3\2\2\2\u018c")
    buf.write(u"\u018d\7\'\2\2\u018d\66\3\2\2\2\u018e\u018f\7,\2\2\u018f")
    buf.write(u"\u0190\7,\2\2\u01908\3\2\2\2\u0191\u0192\7A\2\2\u0192")
    buf.write(u"\u0193\7A\2\2\u0193:\3\2\2\2\u0194\u0195\7%\2\2\u0195")
    buf.write(u"<\3\2\2\2\u0196\u0197\7@\2\2\u0197\u0198\7@\2\2\u0198")
    buf.write(u">\3\2\2\2\u0199\u019a\7>\2\2\u019a\u019b\7>\2\2\u019b")
    buf.write(u"@\3\2\2\2\u019c\u019d\7@\2\2\u019d\u019e\7@\2\2\u019e")
    buf.write(u"\u019f\7@\2\2\u019fB\3\2\2\2\u01a0\u01a1\7>\2\2\u01a1")
    buf.write(u"D\3\2\2\2\u01a2\u01a3\7@\2\2\u01a3F\3\2\2\2\u01a4\u01a5")
    buf.write(u"\7>\2\2\u01a5\u01a6\7?\2\2\u01a6H\3\2\2\2\u01a7\u01a8")
    buf.write(u"\7@\2\2\u01a8\u01a9\7?\2\2\u01a9J\3\2\2\2\u01aa\u01ab")
    buf.write(u"\7?\2\2\u01ab\u01ac\7?\2\2\u01acL\3\2\2\2\u01ad\u01ae")
    buf.write(u"\7#\2\2\u01ae\u01af\7?\2\2\u01afN\3\2\2\2\u01b0\u01b1")
    buf.write(u"\7?\2\2\u01b1\u01b2\7?\2\2\u01b2\u01b3\7?\2\2\u01b3P")
    buf.write(u"\3\2\2\2\u01b4\u01b5\7#\2\2\u01b5\u01b6\7?\2\2\u01b6")
    buf.write(u"\u01b7\7?\2\2\u01b7R\3\2\2\2\u01b8\u01b9\7(\2\2\u01b9")
    buf.write(u"T\3\2\2\2\u01ba\u01bb\7`\2\2\u01bbV\3\2\2\2\u01bc\u01bd")
    buf.write(u"\7~\2\2\u01bdX\3\2\2\2\u01be\u01bf\7(\2\2\u01bf\u01c0")
    buf.write(u"\7(\2\2\u01c0Z\3\2\2\2\u01c1\u01c2\7~\2\2\u01c2\u01c3")
    buf.write(u"\7~\2\2\u01c3\\\3\2\2\2\u01c4\u01c5\7,\2\2\u01c5\u01c6")
    buf.write(u"\7?\2\2\u01c6^\3\2\2\2\u01c7\u01c8\7\61\2\2\u01c8\u01c9")
    buf.write(u"\7?\2\2\u01c9`\3\2\2\2\u01ca\u01cb\7\'\2\2\u01cb\u01cc")
    buf.write(u"\7?\2\2\u01ccb\3\2\2\2\u01cd\u01ce\7-\2\2\u01ce\u01cf")
    buf.write(u"\7?\2\2\u01cfd\3\2\2\2\u01d0\u01d1\7/\2\2\u01d1\u01d2")
    buf.write(u"\7?\2\2\u01d2f\3\2\2\2\u01d3\u01d4\7>\2\2\u01d4\u01d5")
    buf.write(u"\7>\2\2\u01d5\u01d6\7?\2\2\u01d6h\3\2\2\2\u01d7\u01d8")
    buf.write(u"\7@\2\2\u01d8\u01d9\7@\2\2\u01d9\u01da\7?\2\2\u01daj")
    buf.write(u"\3\2\2\2\u01db\u01dc\7@\2\2\u01dc\u01dd\7@\2\2\u01dd")
    buf.write(u"\u01de\7@\2\2\u01de\u01df\7?\2\2\u01dfl\3\2\2\2\u01e0")
    buf.write(u"\u01e1\7(\2\2\u01e1\u01e2\7?\2\2\u01e2n\3\2\2\2\u01e3")
    buf.write(u"\u01e4\7`\2\2\u01e4\u01e5\7?\2\2\u01e5p\3\2\2\2\u01e6")
    buf.write(u"\u01e7\7~\2\2\u01e7\u01e8\7?\2\2\u01e8r\3\2\2\2\u01e9")
    buf.write(u"\u01ea\7,\2\2\u01ea\u01eb\7,\2\2\u01eb\u01ec\7?\2\2\u01ec")
    buf.write(u"t\3\2\2\2\u01ed\u01ee\7?\2\2\u01ee\u01ef\7@\2\2\u01ef")
    buf.write(u"v\3\2\2\2\u01f0\u01f1\7p\2\2\u01f1\u01f2\7w\2\2\u01f2")
    buf.write(u"\u01f3\7n\2\2\u01f3\u01f4\7n\2\2\u01f4x\3\2\2\2\u01f5")
    buf.write(u"\u01f6\7v\2\2\u01f6\u01f7\7t\2\2\u01f7\u01f8\7w\2\2\u01f8")
    buf.write(u"\u01ff\7g\2\2\u01f9\u01fa\7h\2\2\u01fa\u01fb\7c\2\2\u01fb")
    buf.write(u"\u01fc\7n\2\2\u01fc\u01fd\7u\2\2\u01fd\u01ff\7g\2\2\u01fe")
    buf.write(u"\u01f5\3\2\2\2\u01fe\u01f9\3\2\2\2\u01ffz\3\2\2\2\u0200")
    buf.write(u"\u0201\5\u0111\u0089\2\u0201\u0202\7\60\2\2\u0202\u0206")
    buf.write(u"\t\3\2\2\u0203\u0205\t\4\2\2\u0204\u0203\3\2\2\2\u0205")
    buf.write(u"\u0208\3\2\2\2\u0206\u0204\3\2\2\2\u0206\u0207\3\2\2")
    buf.write(u"\2\u0207\u020a\3\2\2\2\u0208\u0206\3\2\2\2\u0209\u020b")
    buf.write(u"\5\u0113\u008a\2\u020a\u0209\3\2\2\2\u020a\u020b\3\2")
    buf.write(u"\2\2\u020b\u021c\3\2\2\2\u020c\u020d\7\60\2\2\u020d\u0211")
    buf.write(u"\t\3\2\2\u020e\u0210\t\4\2\2\u020f\u020e\3\2\2\2\u0210")
    buf.write(u"\u0213\3\2\2\2\u0211\u020f\3\2\2\2\u0211\u0212\3\2\2")
    buf.write(u"\2\u0212\u0215\3\2\2\2\u0213\u0211\3\2\2\2\u0214\u0216")
    buf.write(u"\5\u0113\u008a\2\u0215\u0214\3\2\2\2\u0215\u0216\3\2")
    buf.write(u"\2\2\u0216\u021c\3\2\2\2\u0217\u0219\5\u0111\u0089\2")
    buf.write(u"\u0218\u021a\5\u0113\u008a\2\u0219\u0218\3\2\2\2\u0219")
    buf.write(u"\u021a\3\2\2\2\u021a\u021c\3\2\2\2\u021b\u0200\3\2\2")
    buf.write(u"\2\u021b\u020c\3\2\2\2\u021b\u0217\3\2\2\2\u021c|\3\2")
    buf.write(u"\2\2\u021d\u021e\7\62\2\2\u021e\u021f\t\5\2\2\u021f\u0223")
    buf.write(u"\t\6\2\2\u0220\u0222\5\u010f\u0088\2\u0221\u0220\3\2")
    buf.write(u"\2\2\u0222\u0225\3\2\2\2\u0223\u0221\3\2\2\2\u0223\u0224")
    buf.write(u"\3\2\2\2\u0224~\3\2\2\2\u0225\u0223\3\2\2\2\u0226\u0228")
    buf.write(u"\7\62\2\2\u0227\u0229\t\7\2\2\u0228\u0227\3\2\2\2\u0229")
    buf.write(u"\u022a\3\2\2\2\u022a\u0228\3\2\2\2\u022a\u022b\3\2\2")
    buf.write(u"\2\u022b\u022c\3\2\2\2\u022c\u022d\6@\4\2\u022d\u0080")
    buf.write(u"\3\2\2\2\u022e\u022f\7\62\2\2\u022f\u0230\t\b\2\2\u0230")
    buf.write(u"\u0234\t\7\2\2\u0231\u0233\t\t\2\2\u0232\u0231\3\2\2")
    buf.write(u"\2\u0233\u0236\3\2\2\2\u0234\u0232\3\2\2\2\u0234\u0235")
    buf.write(u"\3\2\2\2\u0235\u0082\3\2\2\2\u0236\u0234\3\2\2\2\u0237")
    buf.write(u"\u0238\7\62\2\2\u0238\u0239\t\n\2\2\u0239\u023d\t\13")
    buf.write(u"\2\2\u023a\u023c\t\f\2\2\u023b\u023a\3\2\2\2\u023c\u023f")
    buf.write(u"\3\2\2\2\u023d\u023b\3\2\2\2\u023d\u023e\3\2\2\2\u023e")
    buf.write(u"\u0084\3\2\2\2\u023f\u023d\3\2\2\2\u0240\u0241\7\62\2")
    buf.write(u"\2\u0241\u0242\t\5\2\2\u0242\u0246\t\6\2\2\u0243\u0245")
    buf.write(u"\5\u010f\u0088\2\u0244\u0243\3\2\2\2\u0245\u0248\3\2")
    buf.write(u"\2\2\u0246\u0244\3\2\2\2\u0246\u0247\3\2\2\2\u0247\u0249")
    buf.write(u"\3\2\2\2\u0248\u0246\3\2\2\2\u0249\u024a\7p\2\2\u024a")
    buf.write(u"\u0086\3\2\2\2\u024b\u024c\7\62\2\2\u024c\u024d\t\b\2")
    buf.write(u"\2\u024d\u0251\t\7\2\2\u024e\u0250\t\t\2\2\u024f\u024e")
    buf.write(u"\3\2\2\2\u0250\u0253\3\2\2\2\u0251\u024f\3\2\2\2\u0251")
    buf.write(u"\u0252\3\2\2\2\u0252\u0254\3\2\2\2\u0253\u0251\3\2\2")
    buf.write(u"\2\u0254\u0255\7p\2\2\u0255\u0088\3\2\2\2\u0256\u0257")
    buf.write(u"\7\62\2\2\u0257\u0258\t\n\2\2\u0258\u025c\t\13\2\2\u0259")
    buf.write(u"\u025b\t\f\2\2\u025a\u0259\3\2\2\2\u025b\u025e\3\2\2")
    buf.write(u"\2\u025c\u025a\3\2\2\2\u025c\u025d\3\2\2\2\u025d\u025f")
    buf.write(u"\3\2\2\2\u025e\u025c\3\2\2\2\u025f\u0260\7p\2\2\u0260")
    buf.write(u"\u008a\3\2\2\2\u0261\u0262\5\u0111\u0089\2\u0262\u0263")
    buf.write(u"\7p\2\2\u0263\u008c\3\2\2\2\u0264\u0265\7d\2\2\u0265")
    buf.write(u"\u0266\7t\2\2\u0266\u0267\7g\2\2\u0267\u0268\7c\2\2\u0268")
    buf.write(u"\u0269\7m\2\2\u0269\u008e\3\2\2\2\u026a\u026b\7f\2\2")
    buf.write(u"\u026b\u026c\7q\2\2\u026c\u0090\3\2\2\2\u026d\u026e\7")
    buf.write(u"k\2\2\u026e\u026f\7p\2\2\u026f\u0270\7u\2\2\u0270\u0271")
    buf.write(u"\7v\2\2\u0271\u0272\7c\2\2\u0272\u0273\7p\2\2\u0273\u0274")
    buf.write(u"\7e\2\2\u0274\u0275\7g\2\2\u0275\u0276\7q\2\2\u0276\u0277")
    buf.write(u"\7h\2\2\u0277\u0092\3\2\2\2\u0278\u0279\7v\2\2\u0279")
    buf.write(u"\u027a\7{\2\2\u027a\u027b\7r\2\2\u027b\u027c\7g\2\2\u027c")
    buf.write(u"\u027d\7q\2\2\u027d\u027e\7h\2\2\u027e\u0094\3\2\2\2")
    buf.write(u"\u027f\u0280\7e\2\2\u0280\u0281\7c\2\2\u0281\u0282\7")
    buf.write(u"u\2\2\u0282\u0283\7g\2\2\u0283\u0096\3\2\2\2\u0284\u0285")
    buf.write(u"\7g\2\2\u0285\u0286\7n\2\2\u0286\u0287\7u\2\2\u0287\u0288")
    buf.write(u"\7g\2\2\u0288\u0098\3\2\2\2\u0289\u028a\7p\2\2\u028a")
    buf.write(u"\u028b\7g\2\2\u028b\u028c\7y\2\2\u028c\u009a\3\2\2\2")
    buf.write(u"\u028d\u028e\7x\2\2\u028e\u028f\7c\2\2\u028f\u0290\7")
    buf.write(u"t\2\2\u0290\u009c\3\2\2\2\u0291\u0292\7e\2\2\u0292\u0293")
    buf.write(u"\7c\2\2\u0293\u0294\7v\2\2\u0294\u0295\7e\2\2\u0295\u0296")
    buf.write(u"\7j\2\2\u0296\u009e\3\2\2\2\u0297\u0298\7h\2\2\u0298")
    buf.write(u"\u0299\7k\2\2\u0299\u029a\7p\2\2\u029a\u029b\7c\2\2\u029b")
    buf.write(u"\u029c\7n\2\2\u029c\u029d\7n\2\2\u029d\u029e\7{\2\2\u029e")
    buf.write(u"\u00a0\3\2\2\2\u029f\u02a0\7t\2\2\u02a0\u02a1\7g\2\2")
    buf.write(u"\u02a1\u02a2\7v\2\2\u02a2\u02a3\7w\2\2\u02a3\u02a4\7")
    buf.write(u"t\2\2\u02a4\u02a5\7p\2\2\u02a5\u00a2\3\2\2\2\u02a6\u02a7")
    buf.write(u"\7x\2\2\u02a7\u02a8\7q\2\2\u02a8\u02a9\7k\2\2\u02a9\u02aa")
    buf.write(u"\7f\2\2\u02aa\u00a4\3\2\2\2\u02ab\u02ac\7e\2\2\u02ac")
    buf.write(u"\u02ad\7q\2\2\u02ad\u02ae\7p\2\2\u02ae\u02af\7v\2\2\u02af")
    buf.write(u"\u02b0\7k\2\2\u02b0\u02b1\7p\2\2\u02b1\u02b2\7w\2\2\u02b2")
    buf.write(u"\u02b3\7g\2\2\u02b3\u00a6\3\2\2\2\u02b4\u02b5\7h\2\2")
    buf.write(u"\u02b5\u02b6\7q\2\2\u02b6\u02b7\7t\2\2\u02b7\u00a8\3")
    buf.write(u"\2\2\2\u02b8\u02b9\7u\2\2\u02b9\u02ba\7y\2\2\u02ba\u02bb")
    buf.write(u"\7k\2\2\u02bb\u02bc\7v\2\2\u02bc\u02bd\7e\2\2\u02bd\u02be")
    buf.write(u"\7j\2\2\u02be\u00aa\3\2\2\2\u02bf\u02c0\7y\2\2\u02c0")
    buf.write(u"\u02c1\7j\2\2\u02c1\u02c2\7k\2\2\u02c2\u02c3\7n\2\2\u02c3")
    buf.write(u"\u02c4\7g\2\2\u02c4\u00ac\3\2\2\2\u02c5\u02c6\7f\2\2")
    buf.write(u"\u02c6\u02c7\7g\2\2\u02c7\u02c8\7d\2\2\u02c8\u02c9\7")
    buf.write(u"w\2\2\u02c9\u02ca\7i\2\2\u02ca\u02cb\7i\2\2\u02cb\u02cc")
    buf.write(u"\7g\2\2\u02cc\u02cd\7t\2\2\u02cd\u00ae\3\2\2\2\u02ce")
    buf.write(u"\u02cf\7h\2\2\u02cf\u02d0\7w\2\2\u02d0\u02d1\7p\2\2\u02d1")
    buf.write(u"\u02d2\7e\2\2\u02d2\u02d3\7v\2\2\u02d3\u02d4\7k\2\2\u02d4")
    buf.write(u"\u02d5\7q\2\2\u02d5\u02d6\7p\2\2\u02d6\u00b0\3\2\2\2")
    buf.write(u"\u02d7\u02d8\7v\2\2\u02d8\u02d9\7j\2\2\u02d9\u02da\7")
    buf.write(u"k\2\2\u02da\u02db\7u\2\2\u02db\u00b2\3\2\2\2\u02dc\u02dd")
    buf.write(u"\7y\2\2\u02dd\u02de\7k\2\2\u02de\u02df\7v\2\2\u02df\u02e0")
    buf.write(u"\7j\2\2\u02e0\u00b4\3\2\2\2\u02e1\u02e2\7f\2\2\u02e2")
    buf.write(u"\u02e3\7g\2\2\u02e3\u02e4\7h\2\2\u02e4\u02e5\7c\2\2\u02e5")
    buf.write(u"\u02e6\7w\2\2\u02e6\u02e7\7n\2\2\u02e7\u02e8\7v\2\2\u02e8")
    buf.write(u"\u00b6\3\2\2\2\u02e9\u02ea\7k\2\2\u02ea\u02eb\7h\2\2")
    buf.write(u"\u02eb\u00b8\3\2\2\2\u02ec\u02ed\7v\2\2\u02ed\u02ee\7")
    buf.write(u"j\2\2\u02ee\u02ef\7t\2\2\u02ef\u02f0\7q\2\2\u02f0\u02f1")
    buf.write(u"\7y\2\2\u02f1\u00ba\3\2\2\2\u02f2\u02f3\7f\2\2\u02f3")
    buf.write(u"\u02f4\7g\2\2\u02f4\u02f5\7n\2\2\u02f5\u02f6\7g\2\2\u02f6")
    buf.write(u"\u02f7\7v\2\2\u02f7\u02f8\7g\2\2\u02f8\u00bc\3\2\2\2")
    buf.write(u"\u02f9\u02fa\7k\2\2\u02fa\u02fb\7p\2\2\u02fb\u00be\3")
    buf.write(u"\2\2\2\u02fc\u02fd\7v\2\2\u02fd\u02fe\7t\2\2\u02fe\u02ff")
    buf.write(u"\7{\2\2\u02ff\u00c0\3\2\2\2\u0300\u0301\7c\2\2\u0301")
    buf.write(u"\u0302\7u\2\2\u0302\u00c2\3\2\2\2\u0303\u0304\7h\2\2")
    buf.write(u"\u0304\u0305\7t\2\2\u0305\u0306\7q\2\2\u0306\u0307\7")
    buf.write(u"o\2\2\u0307\u00c4\3\2\2\2\u0308\u0309\7e\2\2\u0309\u030a")
    buf.write(u"\7n\2\2\u030a\u030b\7c\2\2\u030b\u030c\7u\2\2\u030c\u030d")
    buf.write(u"\7u\2\2\u030d\u00c6\3\2\2\2\u030e\u030f\7g\2\2\u030f")
    buf.write(u"\u0310\7p\2\2\u0310\u0311\7w\2\2\u0311\u0312\7o\2\2\u0312")
    buf.write(u"\u00c8\3\2\2\2\u0313\u0314\7g\2\2\u0314\u0315\7z\2\2")
    buf.write(u"\u0315\u0316\7v\2\2\u0316\u0317\7g\2\2\u0317\u0318\7")
    buf.write(u"p\2\2\u0318\u0319\7f\2\2\u0319\u031a\7u\2\2\u031a\u00ca")
    buf.write(u"\3\2\2\2\u031b\u031c\7u\2\2\u031c\u031d\7w\2\2\u031d")
    buf.write(u"\u031e\7r\2\2\u031e\u031f\7g\2\2\u031f\u0320\7t\2\2\u0320")
    buf.write(u"\u00cc\3\2\2\2\u0321\u0322\7e\2\2\u0322\u0323\7q\2\2")
    buf.write(u"\u0323\u0324\7p\2\2\u0324\u0325\7u\2\2\u0325\u0326\7")
    buf.write(u"v\2\2\u0326\u00ce\3\2\2\2\u0327\u0328\7g\2\2\u0328\u0329")
    buf.write(u"\7z\2\2\u0329\u032a\7r\2\2\u032a\u032b\7q\2\2\u032b\u032c")
    buf.write(u"\7t\2\2\u032c\u032d\7v\2\2\u032d\u00d0\3\2\2\2\u032e")
    buf.write(u"\u032f\7k\2\2\u032f\u0330\7o\2\2\u0330\u0331\7r\2\2\u0331")
    buf.write(u"\u0332\7q\2\2\u0332\u0333\7t\2\2\u0333\u0334\7v\2\2\u0334")
    buf.write(u"\u00d2\3\2\2\2\u0335\u0336\7c\2\2\u0336\u0337\7u\2\2")
    buf.write(u"\u0337\u0338\7{\2\2\u0338\u0339\7p\2\2\u0339\u033a\7")
    buf.write(u"e\2\2\u033a\u00d4\3\2\2\2\u033b\u033c\7c\2\2\u033c\u033d")
    buf.write(u"\7y\2\2\u033d\u033e\7c\2\2\u033e\u033f\7k\2\2\u033f\u0340")
    buf.write(u"\7v\2\2\u0340\u00d6\3\2\2\2\u0341\u0342\7k\2\2\u0342")
    buf.write(u"\u0343\7o\2\2\u0343\u0344\7r\2\2\u0344\u0345\7n\2\2\u0345")
    buf.write(u"\u0346\7g\2\2\u0346\u0347\7o\2\2\u0347\u0348\7g\2\2\u0348")
    buf.write(u"\u0349\7p\2\2\u0349\u034a\7v\2\2\u034a\u034b\7u\2\2\u034b")
    buf.write(u"\u034c\3\2\2\2\u034c\u034d\6l\5\2\u034d\u00d8\3\2\2\2")
    buf.write(u"\u034e\u034f\7n\2\2\u034f\u0350\7g\2\2\u0350\u0351\7")
    buf.write(u"v\2\2\u0351\u0352\3\2\2\2\u0352\u0353\6m\6\2\u0353\u00da")
    buf.write(u"\3\2\2\2\u0354\u0355\7r\2\2\u0355\u0356\7t\2\2\u0356")
    buf.write(u"\u0357\7k\2\2\u0357\u0358\7x\2\2\u0358\u0359\7c\2\2\u0359")
    buf.write(u"\u035a\7v\2\2\u035a\u035b\7g\2\2\u035b\u035c\3\2\2\2")
    buf.write(u"\u035c\u035d\6n\7\2\u035d\u00dc\3\2\2\2\u035e\u035f\7")
    buf.write(u"r\2\2\u035f\u0360\7w\2\2\u0360\u0361\7d\2\2\u0361\u0362")
    buf.write(u"\7n\2\2\u0362\u0363\7k\2\2\u0363\u0364\7e\2\2\u0364\u0365")
    buf.write(u"\3\2\2\2\u0365\u0366\6o\b\2\u0366\u00de\3\2\2\2\u0367")
    buf.write(u"\u0368\7k\2\2\u0368\u0369\7p\2\2\u0369\u036a\7v\2\2\u036a")
    buf.write(u"\u036b\7g\2\2\u036b\u036c\7t\2\2\u036c\u036d\7h\2\2\u036d")
    buf.write(u"\u036e\7c\2\2\u036e\u036f\7e\2\2\u036f\u0370\7g\2\2\u0370")
    buf.write(u"\u0371\3\2\2\2\u0371\u0372\6p\t\2\u0372\u00e0\3\2\2\2")
    buf.write(u"\u0373\u0374\7r\2\2\u0374\u0375\7c\2\2\u0375\u0376\7")
    buf.write(u"e\2\2\u0376\u0377\7m\2\2\u0377\u0378\7c\2\2\u0378\u0379")
    buf.write(u"\7i\2\2\u0379\u037a\7g\2\2\u037a\u037b\3\2\2\2\u037b")
    buf.write(u"\u037c\6q\n\2\u037c\u00e2\3\2\2\2\u037d\u037e\7r\2\2")
    buf.write(u"\u037e\u037f\7t\2\2\u037f\u0380\7q\2\2\u0380\u0381\7")
    buf.write(u"v\2\2\u0381\u0382\7g\2\2\u0382\u0383\7e\2\2\u0383\u0384")
    buf.write(u"\7v\2\2\u0384\u0385\7g\2\2\u0385\u0386\7f\2\2\u0386\u0387")
    buf.write(u"\3\2\2\2\u0387\u0388\6r\13\2\u0388\u00e4\3\2\2\2\u0389")
    buf.write(u"\u038a\7u\2\2\u038a\u038b\7v\2\2\u038b\u038c\7c\2\2\u038c")
    buf.write(u"\u038d\7v\2\2\u038d\u038e\7k\2\2\u038e\u038f\7e\2\2\u038f")
    buf.write(u"\u0390\3\2\2\2\u0390\u0391\6s\f\2\u0391\u00e6\3\2\2\2")
    buf.write(u"\u0392\u0393\7{\2\2\u0393\u0394\7k\2\2\u0394\u0395\7")
    buf.write(u"g\2\2\u0395\u0396\7n\2\2\u0396\u0397\7f\2\2\u0397\u0398")
    buf.write(u"\3\2\2\2\u0398\u0399\6t\r\2\u0399\u00e8\3\2\2\2\u039a")
    buf.write(u"\u039e\5\u0117\u008c\2\u039b\u039d\5\u0115\u008b\2\u039c")
    buf.write(u"\u039b\3\2\2\2\u039d\u03a0\3\2\2\2\u039e\u039c\3\2\2")
    buf.write(u"\2\u039e\u039f\3\2\2\2\u039f\u00ea\3\2\2\2\u03a0\u039e")
    buf.write(u"\3\2\2\2\u03a1\u03a5\7$\2\2\u03a2\u03a4\5\u00f9}\2\u03a3")
    buf.write(u"\u03a2\3\2\2\2\u03a4\u03a7\3\2\2\2\u03a5\u03a3\3\2\2")
    buf.write(u"\2\u03a5\u03a6\3\2\2\2\u03a6\u03a8\3\2\2\2\u03a7\u03a5")
    buf.write(u"\3\2\2\2\u03a8\u03b2\7$\2\2\u03a9\u03ad\7)\2\2\u03aa")
    buf.write(u"\u03ac\5\u00fb~\2\u03ab\u03aa\3\2\2\2\u03ac\u03af\3\2")
    buf.write(u"\2\2\u03ad\u03ab\3\2\2\2\u03ad\u03ae\3\2\2\2\u03ae\u03b0")
    buf.write(u"\3\2\2\2\u03af\u03ad\3\2\2\2\u03b0\u03b2\7)\2\2\u03b1")
    buf.write(u"\u03a1\3\2\2\2\u03b1\u03a9\3\2\2\2\u03b2\u03b3\3\2\2")
    buf.write(u"\2\u03b3\u03b4\bv\5\2\u03b4\u00ec\3\2\2\2\u03b5\u03bb")
    buf.write(u"\7b\2\2\u03b6\u03b7\7^\2\2\u03b7\u03ba\7b\2\2\u03b8\u03ba")
    buf.write(u"\n\r\2\2\u03b9\u03b6\3\2\2\2\u03b9\u03b8\3\2\2\2\u03ba")
    buf.write(u"\u03bd\3\2\2\2\u03bb\u03b9\3\2\2\2\u03bb\u03bc\3\2\2")
    buf.write(u"\2\u03bc\u03be\3\2\2\2\u03bd\u03bb\3\2\2\2\u03be\u03bf")
    buf.write(u"\7b\2\2\u03bf\u00ee\3\2\2\2\u03c0\u03c2\t\16\2\2\u03c1")
    buf.write(u"\u03c0\3\2\2\2\u03c2\u03c3\3\2\2\2\u03c3\u03c1\3\2\2")
    buf.write(u"\2\u03c3\u03c4\3\2\2\2\u03c4\u03c5\3\2\2\2\u03c5\u03c6")
    buf.write(u"\bx\2\2\u03c6\u00f0\3\2\2\2\u03c7\u03c8\t\2\2\2\u03c8")
    buf.write(u"\u03c9\3\2\2\2\u03c9\u03ca\by\2\2\u03ca\u00f2\3\2\2\2")
    buf.write(u"\u03cb\u03cc\7>\2\2\u03cc\u03cd\7#\2\2\u03cd\u03ce\7")
    buf.write(u"/\2\2\u03ce\u03cf\7/\2\2\u03cf\u03d3\3\2\2\2\u03d0\u03d2")
    buf.write(u"\13\2\2\2\u03d1\u03d0\3\2\2\2\u03d2\u03d5\3\2\2\2\u03d3")
    buf.write(u"\u03d4\3\2\2\2\u03d3\u03d1\3\2\2\2\u03d4\u03d6\3\2\2")
    buf.write(u"\2\u03d5\u03d3\3\2\2\2\u03d6\u03d7\7/\2\2\u03d7\u03d8")
    buf.write(u"\7/\2\2\u03d8\u03d9\7@\2\2\u03d9\u03da\3\2\2\2\u03da")
    buf.write(u"\u03db\bz\2\2\u03db\u00f4\3\2\2\2\u03dc\u03dd\7>\2\2")
    buf.write(u"\u03dd\u03de\7#\2\2\u03de\u03df\7]\2\2\u03df\u03e0\7")
    buf.write(u"E\2\2\u03e0\u03e1\7F\2\2\u03e1\u03e2\7C\2\2\u03e2\u03e3")
    buf.write(u"\7V\2\2\u03e3\u03e4\7C\2\2\u03e4\u03e5\7]\2\2\u03e5\u03e9")
    buf.write(u"\3\2\2\2\u03e6\u03e8\13\2\2\2\u03e7\u03e6\3\2\2\2\u03e8")
    buf.write(u"\u03eb\3\2\2\2\u03e9\u03ea\3\2\2\2\u03e9\u03e7\3\2\2")
    buf.write(u"\2\u03ea\u03ec\3\2\2\2\u03eb\u03e9\3\2\2\2\u03ec\u03ed")
    buf.write(u"\7_\2\2\u03ed\u03ee\7_\2\2\u03ee\u03ef\7@\2\2\u03ef\u03f0")
    buf.write(u"\3\2\2\2\u03f0\u03f1\b{\2\2\u03f1\u00f6\3\2\2\2\u03f2")
    buf.write(u"\u03f3\13\2\2\2\u03f3\u03f4\3\2\2\2\u03f4\u03f5\b|\6")
    buf.write(u"\2\u03f5\u00f8\3\2\2\2\u03f6\u03fb\n\17\2\2\u03f7\u03f8")
    buf.write(u"\7^\2\2\u03f8\u03fb\5\u00fd\177\2\u03f9\u03fb\5\u010d")
    buf.write(u"\u0087\2\u03fa\u03f6\3\2\2\2\u03fa\u03f7\3\2\2\2\u03fa")
    buf.write(u"\u03f9\3\2\2\2\u03fb\u00fa\3\2\2\2\u03fc\u0401\n\20\2")
    buf.write(u"\2\u03fd\u03fe\7^\2\2\u03fe\u0401\5\u00fd\177\2\u03ff")
    buf.write(u"\u0401\5\u010d\u0087\2\u0400\u03fc\3\2\2\2\u0400\u03fd")
    buf.write(u"\3\2\2\2\u0400\u03ff\3\2\2\2\u0401\u00fc\3\2\2\2\u0402")
    buf.write(u"\u0408\5\u00ff\u0080\2\u0403\u0408\7\62\2\2\u0404\u0408")
    buf.write(u"\5\u0101\u0081\2\u0405\u0408\5\u0103\u0082\2\u0406\u0408")
    buf.write(u"\5\u0105\u0083\2\u0407\u0402\3\2\2\2\u0407\u0403\3\2")
    buf.write(u"\2\2\u0407\u0404\3\2\2\2\u0407\u0405\3\2\2\2\u0407\u0406")
    buf.write(u"\3\2\2\2\u0408\u00fe\3\2\2\2\u0409\u040c\5\u0107\u0084")
    buf.write(u"\2\u040a\u040c\5\u0109\u0085\2\u040b\u0409\3\2\2\2\u040b")
    buf.write(u"\u040a\3\2\2\2\u040c\u0100\3\2\2\2\u040d\u040e\7z\2\2")
    buf.write(u"\u040e\u040f\5\u010f\u0088\2\u040f\u0410\5\u010f\u0088")
    buf.write(u"\2\u0410\u0102\3\2\2\2\u0411\u0412\7w\2\2\u0412\u0413")
    buf.write(u"\5\u010f\u0088\2\u0413\u0414\5\u010f\u0088\2\u0414\u0415")
    buf.write(u"\5\u010f\u0088\2\u0415\u0416\5\u010f\u0088\2\u0416\u0422")
    buf.write(u"\3\2\2\2\u0417\u0418\7w\2\2\u0418\u0419\7}\2\2\u0419")
    buf.write(u"\u041b\5\u010f\u0088\2\u041a\u041c\5\u010f\u0088\2\u041b")
    buf.write(u"\u041a\3\2\2\2\u041c\u041d\3\2\2\2\u041d\u041b\3\2\2")
    buf.write(u"\2\u041d\u041e\3\2\2\2\u041e\u041f\3\2\2\2\u041f\u0420")
    buf.write(u"\7\177\2\2\u0420\u0422\3\2\2\2\u0421\u0411\3\2\2\2\u0421")
    buf.write(u"\u0417\3\2\2\2\u0422\u0104\3\2\2\2\u0423\u0424\7w\2\2")
    buf.write(u"\u0424\u0426\7}\2\2\u0425\u0427\5\u010f\u0088\2\u0426")
    buf.write(u"\u0425\3\2\2\2\u0427\u0428\3\2\2\2\u0428\u0426\3\2\2")
    buf.write(u"\2\u0428\u0429\3\2\2\2\u0429\u042a\3\2\2\2\u042a\u042b")
    buf.write(u"\7\177\2\2\u042b\u0106\3\2\2\2\u042c\u042d\t\21\2\2\u042d")
    buf.write(u"\u0108\3\2\2\2\u042e\u042f\n\22\2\2\u042f\u010a\3\2\2")
    buf.write(u"\2\u0430\u0433\5\u0107\u0084\2\u0431\u0433\t\23\2\2\u0432")
    buf.write(u"\u0430\3\2\2\2\u0432\u0431\3\2\2\2\u0433\u010c\3\2\2")
    buf.write(u"\2\u0434\u0435\7^\2\2\u0435\u0436\t\2\2\2\u0436\u010e")
    buf.write(u"\3\2\2\2\u0437\u0438\t\24\2\2\u0438\u0110\3\2\2\2\u0439")
    buf.write(u"\u0442\7\62\2\2\u043a\u043e\t\25\2\2\u043b\u043d\t\4")
    buf.write(u"\2\2\u043c\u043b\3\2\2\2\u043d\u0440\3\2\2\2\u043e\u043c")
    buf.write(u"\3\2\2\2\u043e\u043f\3\2\2\2\u043f\u0442\3\2\2\2\u0440")
    buf.write(u"\u043e\3\2\2\2\u0441\u0439\3\2\2\2\u0441\u043a\3\2\2")
    buf.write(u"\2\u0442\u0112\3\2\2\2\u0443\u0445\t\26\2\2\u0444\u0446")
    buf.write(u"\t\27\2\2\u0445\u0444\3\2\2\2\u0445\u0446\3\2\2\2\u0446")
    buf.write(u"\u0448\3\2\2\2\u0447\u0449\t\4\2\2\u0448\u0447\3\2\2")
    buf.write(u"\2\u0449\u044a\3\2\2\2\u044a\u0448\3\2\2\2\u044a\u044b")
    buf.write(u"\3\2\2\2\u044b\u0114\3\2\2\2\u044c\u0452\5\u0117\u008c")
    buf.write(u"\2\u044d\u0452\5\u011b\u008e\2\u044e\u0452\5\u011d\u008f")
    buf.write(u"\2\u044f\u0452\5\u011f\u0090\2\u0450\u0452\4\u200e\u200f")
    buf.write(u"\2\u0451\u044c\3\2\2\2\u0451\u044d\3\2\2\2\u0451\u044e")
    buf.write(u"\3\2\2\2\u0451\u044f\3\2\2\2\u0451\u0450\3\2\2\2\u0452")
    buf.write(u"\u0116\3\2\2\2\u0453\u0458\5\u0119\u008d\2\u0454\u0458")
    buf.write(u"\t\30\2\2\u0455\u0456\7^\2\2\u0456\u0458\5\u0103\u0082")
    buf.write(u"\2\u0457\u0453\3\2\2\2\u0457\u0454\3\2\2\2\u0457\u0455")
    buf.write(u"\3\2\2\2\u0458\u0118\3\2\2\2\u0459\u045b\t\31\2\2\u045a")
    buf.write(u"\u0459\3\2\2\2\u045b\u011a\3\2\2\2\u045c\u045e\t\32\2")
    buf.write(u"\2\u045d\u045c\3\2\2\2\u045e\u011c\3\2\2\2\u045f\u0461")
    buf.write(u"\t\33\2\2\u0460\u045f\3\2\2\2\u0461\u011e\3\2\2\2\u0462")
    buf.write(u"\u0464\t\34\2\2\u0463\u0462\3\2\2\2\u0464\u0120\3\2\2")
    buf.write(u"\2\u0465\u0470\n\35\2\2\u0466\u0470\5\u0127\u0094\2\u0467")
    buf.write(u"\u046b\7]\2\2\u0468\u046a\5\u0125\u0093\2\u0469\u0468")
    buf.write(u"\3\2\2\2\u046a\u046d\3\2\2\2\u046b\u0469\3\2\2\2\u046b")
    buf.write(u"\u046c\3\2\2\2\u046c\u046e\3\2\2\2\u046d\u046b\3\2\2")
    buf.write(u"\2\u046e\u0470\7_\2\2\u046f\u0465\3\2\2\2\u046f\u0466")
    buf.write(u"\3\2\2\2\u046f\u0467\3\2\2\2\u0470\u0122\3\2\2\2\u0471")
    buf.write(u"\u047c\n\36\2\2\u0472\u047c\5\u0127\u0094\2\u0473\u0477")
    buf.write(u"\7]\2\2\u0474\u0476\5\u0125\u0093\2\u0475\u0474\3\2\2")
    buf.write(u"\2\u0476\u0479\3\2\2\2\u0477\u0475\3\2\2\2\u0477\u0478")
    buf.write(u"\3\2\2\2\u0478\u047a\3\2\2\2\u0479\u0477\3\2\2\2\u047a")
    buf.write(u"\u047c\7_\2\2\u047b\u0471\3\2\2\2\u047b\u0472\3\2\2\2")
    buf.write(u"\u047b\u0473\3\2\2\2\u047c\u0124\3\2\2\2\u047d\u0480")
    buf.write(u"\n\37\2\2\u047e\u0480\5\u0127\u0094\2\u047f\u047d\3\2")
    buf.write(u"\2\2\u047f\u047e\3\2\2\2\u0480\u0126\3\2\2\2\u0481\u0482")
    buf.write(u"\7^\2\2\u0482\u0483\n\2\2\2\u0483\u0128\3\2\2\2\66\2")
    buf.write(u"\u0130\u0139\u0147\u0151\u0159\u01fe\u0206\u020a\u0211")
    buf.write(u"\u0215\u0219\u021b\u0223\u022a\u0234\u023d\u0246\u0251")
    buf.write(u"\u025c\u039e\u03a5\u03ad\u03b1\u03b9\u03bb\u03c3\u03d3")
    buf.write(u"\u03e9\u03fa\u0400\u0407\u040b\u041d\u0421\u0428\u0432")
    buf.write(u"\u043e\u0441\u0445\u044a\u0451\u0457\u045a\u045d\u0460")
    buf.write(u"\u0463\u046b\u046f\u0477\u047b\u047f\7\2\3\2\3\n\2\3")
    buf.write(u"\13\3\3v\4\2\4\2")
    return buf.getvalue()


class JavaScriptLexer(JavaScriptBaseLexer):

  atn = ATNDeserializer().deserialize(serializedATN())

  decisionsToDFA = [DFA(ds, i) for i, ds in enumerate(atn.decisionToState)]

  ERROR = 2

  HashBangLine = 1
  MultiLineComment = 2
  SingleLineComment = 3
  RegularExpressionLiteral = 4
  OpenBracket = 5
  CloseBracket = 6
  OpenParen = 7
  CloseParen = 8
  OpenBrace = 9
  CloseBrace = 10
  SemiColon = 11
  Comma = 12
  Assign = 13
  QuestionMark = 14
  Colon = 15
  Ellipsis = 16
  Dot = 17
  PlusPlus = 18
  MinusMinus = 19
  Plus = 20
  Minus = 21
  BitNot = 22
  Not = 23
  Multiply = 24
  Divide = 25
  Modulus = 26
  Power = 27
  NullCoalesce = 28
  Hashtag = 29
  RightShiftArithmetic = 30
  LeftShiftArithmetic = 31
  RightShiftLogical = 32
  LessThan = 33
  MoreThan = 34
  LessThanEquals = 35
  GreaterThanEquals = 36
  Equals_ = 37
  NotEquals = 38
  IdentityEquals = 39
  IdentityNotEquals = 40
  BitAnd = 41
  BitXOr = 42
  BitOr = 43
  And = 44
  Or = 45
  MultiplyAssign = 46
  DivideAssign = 47
  ModulusAssign = 48
  PlusAssign = 49
  MinusAssign = 50
  LeftShiftArithmeticAssign = 51
  RightShiftArithmeticAssign = 52
  RightShiftLogicalAssign = 53
  BitAndAssign = 54
  BitXorAssign = 55
  BitOrAssign = 56
  PowerAssign = 57
  ARROW = 58
  NullLiteral = 59
  BooleanLiteral = 60
  DecimalLiteral = 61
  HexIntegerLiteral = 62
  OctalIntegerLiteral = 63
  OctalIntegerLiteral2 = 64
  BinaryIntegerLiteral = 65
  BigHexIntegerLiteral = 66
  BigOctalIntegerLiteral = 67
  BigBinaryIntegerLiteral = 68
  BigDecimalIntegerLiteral = 69
  Break = 70
  Do = 71
  Instanceof = 72
  Typeof = 73
  Case = 74
  Else = 75
  New = 76
  Var = 77
  Catch = 78
  Finally = 79
  Return = 80
  Void = 81
  Continue = 82
  For = 83
  Switch = 84
  While = 85
  Debugger = 86
  Function = 87
  This = 88
  With = 89
  Default = 90
  If = 91
  Throw = 92
  Delete = 93
  In = 94
  Try = 95
  As = 96
  From = 97
  Class = 98
  Enum = 99
  Extends = 100
  Super = 101
  Const = 102
  Export = 103
  Import = 104
  Async = 105
  Await = 106
  Implements = 107
  Let = 108
  Private = 109
  Public = 110
  Interface = 111
  Package = 112
  Protected = 113
  Static = 114
  Yield = 115
  Identifier = 116
  StringLiteral = 117
  TemplateStringLiteral = 118
  WhiteSpaces = 119
  LineTerminator = 120
  HtmlComment = 121
  CDataComment = 122
  UnexpectedCharacter = 123

  channelNames = [u"DEFAULT_TOKEN_CHANNEL", u"HIDDEN", u"ERROR"]

  modeNames = [u"DEFAULT_MODE"]

  literalNames = [
      u"<INVALID>", u"'['", u"']'", u"'('", u"')'", u"'{'", u"'}'", u"';'",
      u"','", u"'='", u"'?'", u"':'", u"'...'", u"'.'", u"'++'", u"'--'",
      u"'+'", u"'-'", u"'~'", u"'!'", u"'*'", u"'/'", u"'%'", u"'**'", u"'??'",
      u"'#'", u"'>>'", u"'<<'", u"'>>>'", u"'<'", u"'>'", u"'<='", u"'>='",
      u"'=='", u"'!='", u"'==='", u"'!=='", u"'&'", u"'^'", u"'|'", u"'&&'",
      u"'||'", u"'*='", u"'/='", u"'%='", u"'+='", u"'-='", u"'<<='", u"'>>='",
      u"'>>>='", u"'&='", u"'^='", u"'|='", u"'**='", u"'=>'", u"'null'",
      u"'break'", u"'do'", u"'instanceof'", u"'typeof'", u"'case'", u"'else'",
      u"'new'", u"'var'", u"'catch'", u"'finally'", u"'return'", u"'void'",
      u"'continue'", u"'for'", u"'switch'", u"'while'", u"'debugger'",
      u"'function'", u"'this'", u"'with'", u"'default'", u"'if'", u"'throw'",
      u"'delete'", u"'in'", u"'try'", u"'as'", u"'from'", u"'class'", u"'enum'",
      u"'extends'", u"'super'", u"'const'", u"'export'", u"'import'",
      u"'async'", u"'await'", u"'implements'", u"'let'", u"'private'",
      u"'public'", u"'interface'", u"'package'", u"'protected'", u"'static'",
      u"'yield'"
  ]

  symbolicNames = [
      u"<INVALID>", u"HashBangLine", u"MultiLineComment", u"SingleLineComment",
      u"RegularExpressionLiteral", u"OpenBracket", u"CloseBracket",
      u"OpenParen", u"CloseParen", u"OpenBrace", u"CloseBrace", u"SemiColon",
      u"Comma", u"Assign", u"QuestionMark", u"Colon", u"Ellipsis", u"Dot",
      u"PlusPlus", u"MinusMinus", u"Plus", u"Minus", u"BitNot", u"Not",
      u"Multiply", u"Divide", u"Modulus", u"Power", u"NullCoalesce", u"Hashtag",
      u"RightShiftArithmetic", u"LeftShiftArithmetic", u"RightShiftLogical",
      u"LessThan", u"MoreThan", u"LessThanEquals", u"GreaterThanEquals",
      u"Equals_", u"NotEquals", u"IdentityEquals", u"IdentityNotEquals",
      u"BitAnd", u"BitXOr", u"BitOr", u"And", u"Or", u"MultiplyAssign",
      u"DivideAssign", u"ModulusAssign", u"PlusAssign", u"MinusAssign",
      u"LeftShiftArithmeticAssign", u"RightShiftArithmeticAssign",
      u"RightShiftLogicalAssign", u"BitAndAssign", u"BitXorAssign",
      u"BitOrAssign", u"PowerAssign", u"ARROW", u"NullLiteral",
      u"BooleanLiteral", u"DecimalLiteral", u"HexIntegerLiteral",
      u"OctalIntegerLiteral", u"OctalIntegerLiteral2", u"BinaryIntegerLiteral",
      u"BigHexIntegerLiteral", u"BigOctalIntegerLiteral",
      u"BigBinaryIntegerLiteral", u"BigDecimalIntegerLiteral", u"Break", u"Do",
      u"Instanceof", u"Typeof", u"Case", u"Else", u"New", u"Var", u"Catch",
      u"Finally", u"Return", u"Void", u"Continue", u"For", u"Switch", u"While",
      u"Debugger", u"Function", u"This", u"With", u"Default", u"If", u"Throw",
      u"Delete", u"In", u"Try", u"As", u"From", u"Class", u"Enum", u"Extends",
      u"Super", u"Const", u"Export", u"Import", u"Async", u"Await",
      u"Implements", u"Let", u"Private", u"Public", u"Interface", u"Package",
      u"Protected", u"Static", u"Yield", u"Identifier", u"StringLiteral",
      u"TemplateStringLiteral", u"WhiteSpaces", u"LineTerminator",
      u"HtmlComment", u"CDataComment", u"UnexpectedCharacter"
  ]

  ruleNames = [
      u"HashBangLine", u"MultiLineComment", u"SingleLineComment",
      u"RegularExpressionLiteral", u"OpenBracket", u"CloseBracket",
      u"OpenParen", u"CloseParen", u"OpenBrace", u"CloseBrace", u"SemiColon",
      u"Comma", u"Assign", u"QuestionMark", u"Colon", u"Ellipsis", u"Dot",
      u"PlusPlus", u"MinusMinus", u"Plus", u"Minus", u"BitNot", u"Not",
      u"Multiply", u"Divide", u"Modulus", u"Power", u"NullCoalesce", u"Hashtag",
      u"RightShiftArithmetic", u"LeftShiftArithmetic", u"RightShiftLogical",
      u"LessThan", u"MoreThan", u"LessThanEquals", u"GreaterThanEquals",
      u"Equals_", u"NotEquals", u"IdentityEquals", u"IdentityNotEquals",
      u"BitAnd", u"BitXOr", u"BitOr", u"And", u"Or", u"MultiplyAssign",
      u"DivideAssign", u"ModulusAssign", u"PlusAssign", u"MinusAssign",
      u"LeftShiftArithmeticAssign", u"RightShiftArithmeticAssign",
      u"RightShiftLogicalAssign", u"BitAndAssign", u"BitXorAssign",
      u"BitOrAssign", u"PowerAssign", u"ARROW", u"NullLiteral",
      u"BooleanLiteral", u"DecimalLiteral", u"HexIntegerLiteral",
      u"OctalIntegerLiteral", u"OctalIntegerLiteral2", u"BinaryIntegerLiteral",
      u"BigHexIntegerLiteral", u"BigOctalIntegerLiteral",
      u"BigBinaryIntegerLiteral", u"BigDecimalIntegerLiteral", u"Break", u"Do",
      u"Instanceof", u"Typeof", u"Case", u"Else", u"New", u"Var", u"Catch",
      u"Finally", u"Return", u"Void", u"Continue", u"For", u"Switch", u"While",
      u"Debugger", u"Function", u"This", u"With", u"Default", u"If", u"Throw",
      u"Delete", u"In", u"Try", u"As", u"From", u"Class", u"Enum", u"Extends",
      u"Super", u"Const", u"Export", u"Import", u"Async", u"Await",
      u"Implements", u"Let", u"Private", u"Public", u"Interface", u"Package",
      u"Protected", u"Static", u"Yield", u"Identifier", u"StringLiteral",
      u"TemplateStringLiteral", u"WhiteSpaces", u"LineTerminator",
      u"HtmlComment", u"CDataComment", u"UnexpectedCharacter",
      u"DoubleStringCharacter", u"SingleStringCharacter", u"EscapeSequence",
      u"CharacterEscapeSequence", u"HexEscapeSequence",
      u"UnicodeEscapeSequence", u"ExtendedUnicodeEscapeSequence",
      u"SingleEscapeCharacter", u"NonEscapeCharacter", u"EscapeCharacter",
      u"LineContinuation", u"HexDigit", u"DecimalIntegerLiteral",
      u"ExponentPart", u"IdentifierPart", u"IdentifierStart", u"UnicodeLetter",
      u"UnicodeCombiningMark", u"UnicodeDigit", u"UnicodeConnectorPunctuation",
      u"RegularExpressionFirstChar", u"RegularExpressionChar",
      u"RegularExpressionClassChar", u"RegularExpressionBackslashSequence"
  ]

  grammarFileName = u"JavaScriptLexer.g4"

  def __init__(self, input=None, output=sys.stdout):
    super(JavaScriptLexer, self).__init__(input, output=output)
    self.checkVersion("4.7.1")
    self._interp = LexerATNSimulator(self, self.atn, self.decisionsToDFA,
                                     PredictionContextCache())
    self._actions = None
    self._predicates = None

  def action(self, localctx, ruleIndex, actionIndex):
    if self._actions is None:
      actions = dict()
      actions[8] = self.OpenBrace_action
      actions[9] = self.CloseBrace_action
      actions[116] = self.StringLiteral_action
      self._actions = actions
    action = self._actions.get(ruleIndex, None)
    if action is not None:
      action(localctx, actionIndex)
    else:
      raise Exception("No registered action for:" + str(ruleIndex))

  def OpenBrace_action(self, localctx, actionIndex):
    if actionIndex == 0:
      self.ProcessOpenBrace()

  def CloseBrace_action(self, localctx, actionIndex):
    if actionIndex == 1:
      super(JavaScriptLexer, self).ProcessCloseBrace()

  def StringLiteral_action(self, localctx, actionIndex):
    if actionIndex == 2:
      super(JavaScriptLexer, self).ProcessStringLiteral()

  def sempred(self, localctx, ruleIndex, predIndex):
    if self._predicates is None:
      preds = dict()
      preds[0] = self.HashBangLine_sempred
      preds[3] = self.RegularExpressionLiteral_sempred
      preds[62] = self.OctalIntegerLiteral_sempred
      preds[106] = self.Implements_sempred
      preds[107] = self.Let_sempred
      preds[108] = self.Private_sempred
      preds[109] = self.Public_sempred
      preds[110] = self.Interface_sempred
      preds[111] = self.Package_sempred
      preds[112] = self.Protected_sempred
      preds[113] = self.Static_sempred
      preds[114] = self.Yield_sempred
      self._predicates = preds
    pred = self._predicates.get(ruleIndex, None)
    if pred is not None:
      return pred(localctx, predIndex)
    else:
      raise Exception("No registered predicate for:" + str(ruleIndex))

  def HashBangLine_sempred(self, localctx, predIndex):
    if predIndex == 0:
      return super(JavaScriptLexer, self).IsStartOfFile()

  def RegularExpressionLiteral_sempred(self, localctx, predIndex):
    if predIndex == 1:
      return super(JavaScriptLexer, self).IsRegExPossible()

  def OctalIntegerLiteral_sempred(self, localctx, predIndex):
    if predIndex == 2:
      return not super(JavaScriptLexer, self).IsStrictMode()

  def Implements_sempred(self, localctx, predIndex):
    if predIndex == 3:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Let_sempred(self, localctx, predIndex):
    if predIndex == 4:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Private_sempred(self, localctx, predIndex):
    if predIndex == 5:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Public_sempred(self, localctx, predIndex):
    if predIndex == 6:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Interface_sempred(self, localctx, predIndex):
    if predIndex == 7:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Package_sempred(self, localctx, predIndex):
    if predIndex == 8:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Protected_sempred(self, localctx, predIndex):
    if predIndex == 9:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Static_sempred(self, localctx, predIndex):
    if predIndex == 10:
      return super(JavaScriptLexer, self).IsStrictMode()

  def Yield_sempred(self, localctx, predIndex):
    if predIndex == 11:
      return super(JavaScriptLexer, self).IsStrictMode()
