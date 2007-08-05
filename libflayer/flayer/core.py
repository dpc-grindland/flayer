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
"""flayer - a fuzzing framework for bypassing basic structural error checking

   ...
"""
__author__ = 'Will Drewry'
__revision__ = '$Id: $'


import copy
from distutils.spawn import find_executable
import os
import shelve
import subprocess
import sys
import tempfile

import valgrind.error_parser
import valgrind.runner


class Flayer:
  """wrapper for valgrind/memcheck undef-as-taint and alter-branch arguments"""
  VERSION = '0.0.1'

  def __init__(self, program='/bin/true', args=[], env={}):
    self.__runner = valgrind.runner.Runner()
    self.__runner.executable = find_executable('valgrind')
    self.__args = []
    self.set_command(program, args, env)
    self.__taint = ''
    self.set_taint('nfs') # TODO: e
    self.__taint_filter = {}
    #self.set_taint_network_filter('')
    self.set_taint_file_filter('')
    self.__errors = {}
    self.__shelf = None

    self.__tmpdir = tempfile.mkdtemp()
    self.__runner['log-file'] = self.__tmpdir + '/flayer'

  def __cleanup_tmpdir(self):
    """attempts to cleanup the tmpdir"""
    for root, dirs, files in os.walk(self.__tmpdir):
      for f in files:
        os.unlink(os.path.join(root, f)) # todo use join
      os.rmdir(root)

  def __del__(self):
    """properly clean up the temporary files on destruction"""
    self.__cleanup_tmpdir()

  def Errors(self):
    """returns the valgrind output errors"""
    return copy.deepcopy(self.__errors)

  def GetTmpDir(self):
    """returns the tmpdir"""
    return self.__tmpdir

  def ResetTmpDir(self):
    """resets the tmpdir and cleans up one if it exists"""
    self.__cleanup_tmpdir()
    self.__tmpdir = tempfile.mkdtemp()
    self.__runner['log-file'] = self.__tmpdir + '/flayer'

  # TODO: change these to properties
  def get_taint(self):
    taint = ''
    if self.__runner.has_key('taint-network') and \
       self.__runner['taint-network']:
      taint += 'n'
    if self.__runner.has_key('taint-file') and \
       self.__runner['taint-file']:
      taint += 'f'
      taint += 's'
    return taint

  def set_taint(self, value):
    # TODO validate
    self.__runner['taint-network'] = False
    self.__runner['taint-file'] = False
    for ch in value:
      if ch == 'n':
        self.__runner['taint-network'] = True
      elif ch == 'f' or ch == 's': # no diff now...
        self.__runner['taint-file'] = True
      else:
        raise RuntimeError, "Request value not yet implemented: " + ch

  def set_taint_network_filter(self, value):
    """specified the host or port traffic to mark"""
    raise RuntimeError, "NOT YET IMPLEMENTED"

  def set_taint_file_filter(self, value):
    """specified the path prefix for file activity to mark"""
    self.__runner['file-filter'] = value

  def get_taint_file_filter(self):
    if self.__runner.has_key('file-filter'):
      return copy.copy(self.__runner['file-filter'])
    else:
      return ''

  def get_taint_network_filter(self):
    if self.__runner.has_key('network-filter'):
      return copy.copy(self.__runner['network-filter'])
    else:
      return ''

  def Run(self, verbose=False, *io):
    """runs the specified command under valgrind-flayer and gets the errors"""
    process = self.__runner.run(self.__args, verbose, *io)
    self.__errors_file = ''.join([self.__tmpdir, '/flayer.', str(process.pid)])
    return process

  def ProcessLastRun(self):
    self.__errors = {}
    self._ReadErrors(self.__errors_file)

  def _ReadErrors(self, f):
    """opens the valgrind error output and parses it"""
    p = valgrind.error_parser.Parser()
    self.__errors = p.parse(open(f))

  def clear_branch_alterations(self):
    self.__runner['alter-branch'] = {}

  def add_branch_alteration(self, address, action):
    if action:
      self.__runner['alter-branch'][address] = '1'
    else:
      self.__runner['alter-branch'][address] = '0'

  def del_branch_alteration(self, address):
    if self.__runner['alter-branch'].has_key(address):
      self.__runner['alter-branch'].pop(address)

  def get_branch_alterations(self):
    return copy.deepcopy(self.__runner['alter-branch'])

  def set_command(self, command, args=[], env={}):
    """sets the target program command, arguments, and environment"""
    self.__args = copy.copy(args)
    self.__args.insert(0, command)
    if env != {}:
      self.__runner.environment.update(env)

  def get_command(self):
    """gets the target program command, arguments, and env"""
    return (self.__args[0],  # command
            self.__args[1:],  # arguments
            copy.copy(self.__runner.environment)) # environment

  def About(self):
    """returns a nice 'about' text"""
    return """
      Flayer is a framework for automating and easing the use of
      two valgrind features: --undef-as-taint and --alter-branch.

      It is the proof of concept implementation of the paper.
      The flayer suite (libflayer, valgrind/flayer)
      provides a system which traces user input through memory
      and opens doors for it.

      What does this mean technically?  Traditional fuzzing is
      limited in its overall code coverage. It is often blocked
      early in the fuzzing process by protocol banner checks and other
      version and sanity checks.  This suite allows for these checks to be
      forcibly skipped at runtime.  This breathes new life into the
      good, ol' fashion Fuzz[1] technique by providing access to 
      program internals without specifying a complicated protocol.

      However, this system can be used with almost any existing fuzzing
      technique to allow for enhanced code coverage.

      Flayer was conceived of and written by Will Drewry <redpig@dataspill.org>.
      Tavis Ormandy <taviso@sdf.lonestar.org> created the manual fuzzing
      technique that flayer automates.

      [1] http://www.cs.wisc.edu/~bart/fuzz
    """

  def FullCommand(self):
    vg = [self.__runner.executable] + self.__runner.arguments
    command = ' '.join(vg + self.__args)
    return command

  def Banner(self):
    """display a banner when running in interactive shell mode"""
    vg = [self.__runner.executable] + self.__runner.arguments
    command = ' '.join(vg + self.__args)
    return """

    Welcome to Flayer %s!

    Type 'help()' for extra details or 'about()' for more
    on flayer.

    Current settings:
    - Command: %s
    - Taint settings: %s
    - Temporary directory: %s

    """ % (Flayer.VERSION, command, self.get_taint(), self.__tmpdir)


if __name__ == '__main__':
  program, args = ('', [])
  if len(sys.argv) >= 2:
    program = sys.argv[1]
    args = sys.argv[2:]
  import wrappers.commandline
  cli = wrappers.commandline.Shell(Flayer(program, args))
  cli.Export()
  cli.Banner()
