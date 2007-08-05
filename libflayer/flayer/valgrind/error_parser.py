#!/usr/bin/python
#
# Copyright 2006-2007 Will Drewry <redpig@dataspill.org>
# Some portions copyright 2007 Google Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the 
# Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#

"""valgrind XML output parser for extracting error data"""

__author__ = 'Will Drewry'

from xml.sax._exceptions import SAXParseException
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import copy

class ErrorFrame:
  """Contains frame information"""
  def __init__(self):
    self.instruction_pointer = ''
    self.obj = ''
    self.function_name = ''
    self.dir = ''
    self.file = ''
    self.line = ''

  def __repr__(self):
    return self.__str__()

  def __str__(self):
    return '{instruction_pointer:%s, obj:%s, function_name:%s, dir:%s, file:%s, line:%s}' % (
      self.instruction_pointer, self.obj, self.function_name, self.dir, self.file, self.line)

  def __eq__(self, a):
    raise "TODO: ErrorFrame,__eq__"



class ErrorCount:
  """container class for XML error counts"""
  def __init__(self):
    self.unique = ''
    self.count = ''

class Error:
  """container class for XML error data"""
  def __init__(self):
    self.unique = ''
    self.tid = ''
    self.kind = ''
    self.what = ''
    self.frames = []
    self.count = 0

  def __eq__(self, a):
    if a.unique != self.unique:
      return False
    if a.tid != self.tid:
      return False
    if a.kind != self.kind:
      return False
    if a.what != self.what:
      return False
    if a.frames != self.frames:
      return False
    if a.count != self.count:
      return False
    return True

  def __repr__(self):
    return self.__str__()

  def __str__(self):
    return '{unique:%s, tid:%s, kind:%s, what:%s, count:%s, frames:%s}' % (
      self.unique, self.tid, self.kind, self.what, self.count, self.frames)

class HandlerState:
  """stack of elements and errors extracted"""
  def __init__(self):
    self.elements = []
    self.errors = []
    self.errorcounts = []

class Handler(ContentHandler):
  """handler for SAX XML processing of valgrind error output"""
  def __init__(self):
    self.__state = HandlerState()
    ContentHandler.__init__(self)

  def errorcounts(self):
    """provides a copy of populated errorcounts"""
    return copy.deepcopy(self.__state.errorcounts)

  def errors(self):
    """provides a copy of populated errors"""
    return copy.deepcopy(self.__state.errors)

  def startElement(self, name, attrs):
    """extracts error elements and their children"""
    # attrs is unused in valgrind output
    if len(attrs) != 0:
      pass # TODO: exception perhaps?
    self.__state.elements.insert(0, name)
    if name == 'error': # errors should never be nested
      self.__state.errors.insert(0, Error())
    elif name == 'frame':
      self.__state.errors[0].frames.insert(0, ErrorFrame())
    elif name == 'pair': # assume this only occurs in errorcounts
      self.__state.errorcounts.insert(0, ErrorCount())

  def endElement(self, name):
    """handles proper nesting of errors"""
    self.__state.elements.pop(0)
    if name == 'error':
      # Clean up frame ordering
      self.__state.errors[0].frames.reverse()

  def characters(self, ch):
    """appends CDATA to the appropriate data structure per character"""
    if len(self.__state.elements) < 2:
      return

    element = self.__state.elements[0]
    if self.__state.elements[1] == 'error':
      if element == 'unique':
        self.__state.errors[0].unique += ch
      elif element == 'tid':
        self.__state.errors[0].tid += ch
      elif element == 'kind':
        self.__state.errors[0].kind += ch
      elif element == 'what':
        self.__state.errors[0].what += ch
    elif self.__state.elements[1] == 'frame' and \
         self.__state.elements[2] == 'stack':
      if element == 'ip':
        self.__state.errors[0].frames[0].instruction_pointer += ch
      elif element == 'obj':
        self.__state.errors[0].frames[0].obj += ch
      elif element == 'fn':
        self.__state.errors[0].frames[0].function_name += ch
      elif element == 'dir':
        self.__state.errors[0].frames[0].dir += ch
      elif element == 'file':
        self.__state.errors[0].frames[0].file += ch
      elif element == 'line':
        self.__state.errors[0].frames[0].line += ch
    elif self.__state.elements[1] == 'pair' and \
         self.__state.elements[2] == 'errorcounts':
      if element == 'count':
        self.__state.errorcounts[0].count += ch
      elif element == 'unique':
        self.__state.errorcounts[0].unique += ch

class Parser:
  """complete encapsulation of the SAX parsing of valgrind error output"""
  def __init__(self):
    self.__parser = make_parser()
    self.__handler = Handler()
    self.__parser.setContentHandler(self.__handler)

  def parse(self, s=''):
    """calls the SAX parser and returns the parsed error array"""
    try:
      self.__parser.parse(s)
    except SAXParseException:
      # Accept what we could grab
      # TODO(wad@google.com): look primarily for the
      #                       "junk after document element" exc.
      print "[flayer] an error occurred during error parsing.\n"
      print "[flayer] some data may be missing.\n"
      pass

    errors = {}
    errorcount = {}
    for ec in self.__handler.errorcounts():
      if ec.unique != '' and ec.count != '':
        errorcount[int(ec.unique, 16)] = int(str(ec.count))

    for error in self.__handler.errors():
      key = int(error.unique, 16)
      errors[key] = copy.copy(error)
      # Sometimes the error count is lost with 
      # valgrind's malformed xml output.
      if errorcount.has_key(key):
        errors[key].count = errorcount[key]
    return errors

