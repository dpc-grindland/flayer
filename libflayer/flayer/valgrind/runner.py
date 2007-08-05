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


"""interface for running the valgrind command"""

__author__ = "Will Drewry"

import copy
import os
import subprocess

class InvalidExecutable(RuntimeError): pass

class Runner(dict):
  DEFAULT_ARGUMENTS = {
    'tool':'flayer',
    'xml':True,
    'db-attach':True,
    'db-command':'"xterm -e \"gdb -nw %f %p\""',
    'alter-branch':{},
    'taint-file':True,
    'taint-network':True,
    'file-filter':'',
    'log-file':'',
  }
  def __init__(self):
    self.update(Runner.DEFAULT_ARGUMENTS)
    self.bufsize = 4096
    self.executable = '/usr/bin/valgrind'
    self.environment = dict(os.environ)

  def _HandleArgumentValue(self, value):
    """takes a name and value and returns the final string"""
    if type(value) is str or type(value) is unicode:
      # Escape quotes only and set the value.
      # *** This is not for security!! ***
      escaped_value = copy.copy(value)
      # TODO: make these constants
      for pair in [["'", '"'], ['"', '\\"']]:
        escaped_value = escaped_value.replace(pair[0], pair[1])
      return escaped_value
    elif type(value) is bool:
      if value == True:
        return 'yes'
      else:
        return 'no'
    elif type(value) is list:
      return ','.join([self._HandleArgumentValue(v) for v in value])
    elif type(value) is dict:
      merged = []
      for item in value.items():
        merged.append(':'.join([item[0], self._HandleArgumentValue(item[1])]))
      return self._HandleArgumentValue(merged)
    else:
      return str(value)

  def _GetArguments(self):
    """returns the arguments as a usable array"""
    arguments = []
    for name in self.keys():
      value = self._HandleArgumentValue(self[name])
      arguments.append('='.join(['--'+name, value]))
    return arguments

  def __GetArguments(self):
    """indirect reference for 'arguments' property'"""
    return self._GetArguments()

  def _SetArguments(self, value):
    """will auto-set arguments"""
    raise NotYetImplemented, "this will be implemented later"

  def __SetArguments(self, value):
    """indirect reference for 'arguments' property'"""
    return self._SetArguments(value)

  arguments = property(__GetArguments, __SetArguments,
                       doc="""Get or set the current arguments""")

  def run(self, additional_arguments=[],verbose=False,*io):
    """executes valgrind with the options and returns the popen object"""
    # Test for correctness
    if type(self.executable) != str:
      raise InvalidExecutable, 'Executable must a string'
    if not os.path.exists(self.executable):
      raise InvalidExecutable, 'Executable not found. Full path required.'

    arguments = [self.executable] + self._GetArguments() + additional_arguments
    if verbose:
      print "Running %s\n" % ' '.join(arguments)

    stdin=subprocess.PIPE
    stdout=subprocess.PIPE
    stderr=subprocess.PIPE

    if len(io) > 0:
      stdin = io[0]
    if len(io) > 1:
      stdout = io[1]
    if len(io) > 2:
      stderr = io[2]

    process = subprocess.Popen(arguments,
                               self.bufsize,
                               env=self.environment,
                               stdin=stdin,
                               stdout=stdout,
                               stderr=stderr,
                               close_fds=True)
    return process
