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

"""command line interface for flayer"""

__author__ = 'Will Drewry'
__revision__ = '$Id: $'

import copy
import os
import shelve
import signal
import subprocess
import sys

# A kludge to add "subtraction" to list.
class SList(list):
  def __sub__(self, a):
    res = []
    for value in self:
      try:
        a.index(value)
      except ValueError:
        res.append(value)
    return res


class Shell:
  # Should I just subclass Flayer?
  """makes the Flayer library suitable for interactive python shell use"""
  def __init__(self, flayer=None):
    if flayer == None:
      self.__flayer = Flayer()
    else:
      self.__flayer = flayer
    # Altered extra data
    self._altered = {}
    # Track the last files
    self._lastio = {}
    self._lastio['stdout'] = ''
    self._lastio['stderr'] = ''
    # Track past runs
    self._past_errors = []

  def Banner(self):
    """displays a welcome banner for the shell"""
    print "%s\n" % self.__flayer.Banner()

  def Export(self):
    """exports all functions starting with CLI_ and lower()s"""
    for exportable in filter(lambda x: x[:3] == '_E_', self.__class__.__dict__):
      name = exportable[3:].lower()
      sys.modules['__main__'].__dict__[name] = getattr(self, exportable)

  # All command line methods
  def _E_Summary(self):
    """outputs a summary of errors from valgrind

       This prints a formatted list of errors from
       valgrind by kind. In particular, it includes
       debugging information from the last frame of
       the error stack trace.

       Arguments:
       - none
    """
    header = " id    frame information"
    format = "%-5s  %-15s %s %s"

    # Sort into kinds
    kinds = {}
    for e in self.__flayer.Errors().values():
      if kinds.has_key(e.kind):
        kinds[e.kind].append(e)
      else:
        kinds[e.kind] = [e]

    for kind in kinds.items():
      print "==> " + kind[0]
      print header
      for e in kind[1]:
        file = os.path.join(e.frames[0].dir, e.frames[0].file) + ':' + \
               e.frames[0].line
        if file == ':':
          file = ''
        print format % (e.unique, e.frames[0].instruction_pointer,
                        e.frames[0].function_name, file)

  def _E_Details(self, error_id):
    """outputs detailed error information by id

       This prints all of the data collected about a particular
       error.

       Arguments:
       - error_id: error id integer
    """
    errors =  self.__flayer.Errors()
    if not errors.has_key(error_id):
      print "Error id '%s' not found." % error_id
      return
    error = errors[error_id]
    print "Error %s:" % error_id
    print "- Thread Id: %s" % error.tid
    print "- Kind: %s" % error.kind
    print "- What: %s" % error.what
    print "- Count: %d" % error.count
    print "- Frames:"
    for id in range(0, len(error.frames)):
      frame = error.frames[id]
      efile = os.path.join(frame.dir, frame.file)
      print "  Frame %d:" % id
      print "  - Instruction pointer: %s" % frame.instruction_pointer
      print "  - Object: %s" % frame.obj
      print "  - Function: %s" % frame.function_name
      print "  - File: %s" % efile
      print "  - Line number: %s" % frame.line

  def _E_Snippet(self, error_id, range=10):
    """outputs code snippet from the top level stack frame if available

       This command will output the first range lines before the conditional
       and the following range lines.

       Arguments:
       - error_id: error id integer
       - range: number of lines of code to show [10]
    """
    if range < 1:
      print "Range must be positive"
      return

    # TODO(wad): autoconvert error_id
    #if type(error_id) is int:

    errors =  self.__flayer.Errors()
    if not errors.has_key(error_id):
      print "Error id '%s' not found." % error_id
      return

    error = errors[error_id]
    if len(error.frames) == 0:
      print "Error id '%s' has no debugging information." % error_id
      return
    frame = error.frames[0]
    efile = os.path.join(frame.dir, frame.file)
    # TODO(wad): bust this out to a helper
    try:
      f = file(os.path.join(frame.dir, frame.file))
    # TODO(wad): catch explicit errors
    except:
      print ("Cannot open referenced file: %s" %
             os.path.join(frame.dir, frame.file))
      return
    line = 1
    try:
      while line < (int(frame.line) - range):
          f.readline() # eat it.
          line += 1
      while line < (int(frame.line) + range):
        # New lines included.
        if line == int(frame.line):
          sys.stdout.write('|%s' % f.readline())
        else:
          sys.stdout.write(' %s' % f.readline())
        line += 1
    # TODO(wad): except explicitly around each readline
    except:
      print "exception"
      return

  def _E_Taint(self, value=None):
    """gets or sets arguments for tainting

       This command will set or retrieve the value
       of the current valgrind/flayer tainting arguments.
       Each setting is a character and valid characters are
       as follows: n, f, and s. Later 'e' will be added.

       'f' indicates that file I/O buffers will be tainted.
       'n' indicates that network I/O buffers will be tainted.
       's' indicates that fd 0 I/O buffers will be tainted.
       'e' will indicate environment variable tainting.

       A value of None will result in a copy of the current 
       taint values being returned.

       Arguments:
       - value: a string containing the arguments above (def: None)
    """
    if value == None:
      return self.__flayer.get_taint()
    else:
      return self.__flayer.set_taint(value)

  def _E_Filter(self, file=None, network=None):
    """gets or sets filtering for taint arguments

       This command will set or retrieve the value
       of the --*-filter arguments used by
       valgrind/flayer. Specifically, file path prefixes are used
       to indicate which input buffers to taint while
       network host/port pairs can be specified.

       When all the arguments are None, the current settings
       will be returned.

       Arguments:
       - file: the path prefix of file to taint (def: None)
       - network: the "host:port" pair to taint (def: None)
    """
    if file == None and network == None:
      return {'file':self.__flayer.get_taint_file_filter(),
              'network':self.__flayer.get_taint_network_filter() }
    if file != None:
      self.__flayer.set_taint_file_filter(file)
    if network != None:
      self.__flayer.set_taint_network_filter(file)

  def _E_Command(self, command=None, args=[], env={}):
    """gets/sets the target command

       This function sets or gets the value of the target
       command and its arguments for use in valgrind.
       The command can be an explicit path or in the PATH
       environment variable.  The arguments should be a
       list. The environment should be a dict and will be added
       to the current environment variable - NOT override it.

       Currently, these will _NOT_ be run under a shell.

       Arguments:
       - command: string containing the target command (def: None)
       - args: list of arguments for the command (def: [])
       - env: dict of environment variables (def: {})
    """
    if command is None:
      return self.__flayer.get_command()
    return self.__flayer.set_command(command, args, env)

  def _E_Run(self, verbose=False):
    """calls valgrind with the configured target, args, and environment

       This command executes valgrind with the current
       configuration of target executable, arguments, and
       environment variables needed.  It will also automatically
       process the output log from valgrind.

       Arguments:
       - verbose: prints additional information (def: False)
    """
    # Setup stdout and stderr files for this process.
    try:
      os.unlink(self._lastio['stdout'])
      os.unlink(self._lastio['stderr'])
    except:
      pass  # Should be empty or valid. Kludge!

    # For now, this will clobber any past runs
    self._lastio['stdout'] = self.__flayer.GetTmpDir() + "/out"
    self._lastio['stderr'] = self.__flayer.GetTmpDir() + "/err"

    stdin = subprocess.PIPE
    stdout = open(self._lastio['stdout'], 'w')
    stderr = open(self._lastio['stderr'], 'w')
    process = self.__flayer.Run()

    # Setup a signal handler to make SIGINT kill the process
    def handler(signum, frame):
      os.kill(process.pid)

    orig_handler = signal.signal(signal.SIGINT, handler)


    process.stdin.close()
    print "Process ID: %d\n" % process.pid

    # XXX: dump out lastio on these calls.
    #print "You may check on its progress with the following commands: \n"
    #print "running(), exit_code(), stdout(), stderr()\n"
    print "Press Ctrl+C to send a SIGTERM to the running process.\n"
    try:
      ret, ret = os.wait() # pid is first - don't care.
    except:
      pass

    # Remove the SIGINT handler
    signal.signal(signal.SIGINT, orig_handler)
    stdout.close()
    stderr.close()

    if verbose:
      print "Return code: %d\n" % ret
    self.__flayer.ProcessLastRun()
    # XXX: does this need to be a deepcopy?
    self._past_errors.append(self.__flayer.Errors().values())

  def _E_ErrorDiff(self, run_a, run_b, kind='TaintedCondition'):
    """returns the difference between to ErrorSets

       This command will return the difference between the error sets
       generated by the specific runs.  See PastErrors() for more.

       Arguments:
       - run_a: integer index of the run's errors
       - run_b: integer index of the run's errors
    """
    a = SList(self._past_errors[run_a])
    b = SList(self._past_errors[run_b])
    return b - a

  def _E_PastErrors(self):
    """returns the list of past errors

       !!TODO!! make this print a pretty list

       Arguments:
       - None
    """
    return self._past_errors

  def _E_ClearErrors(self):
    """clears the list of past errors

       !!TODO!! make this print a pretty list

       Arguments:
       - None
    """
    self._past_errors = []

  def _E_Alter(self, error_id=None, action=None, address=None):
    """gets/sets runtime conditional behavior in the target

       This command gets or sets the branch altering
       functionality of valgrind.  It allows for conditional
       blocks that make use of tainted data to be forced
       to be followed or skipped. It will output a pretty
       summary of alterations and returns a dict of instruction
       pointer to action.

       If an error is listed and the action is not specified,
       the alteration will be removed if it exists.

       Arguments:
       - error_id: string of the unique error id (def: None)
       - action: bool specifying whether to follow the branch (def: None)
       - address: unsigned long specifying the address to modify (def: None)
    """
    # TODO(wad): store alter info by IP
    if error_id is None and address is None:
      print "address    action   frame information"
      alts = self.__flayer.get_branch_alterations()
      format = "%-7s   %-6s  %s %s"
      for ip, e in self._altered.items():
        if e is None:
          print format % (ip, alts[ip], 'unknown', '')
        else:
          file = os.path.join(e.frames[0].dir, e.frames[0].file) + ':' + \
                 e.frames[0].line
          if file == ':':
            file = ''
          print format % (ip, alts[ip],
                          e.frames[0].function_name, file)
      return self.__flayer.get_branch_alterations()

    instruction_pointer = address
    # Validate error_id, kind, and get address
    error = None
    if error_id is not None:
      errors =  self.__flayer.Errors()
      if errors.has_key(error_id):
        error = errors[error_id]
      if error is None:
        print "No matching error id found."
        return
      if error.kind != 'TaintedCondition':
        print 'Error must be of kind TaintedCondition'
        return
      instruction_pointer = error.frames[0].instruction_pointer

    if action is None and self._altered.has_key(instruction_pointer):
      # TODO: add another method for deletion
      self.__flayer.del_branch_alteration(instruction_pointer)
      return self._altered.pop(instruction_pointer)
    else:
      self.__flayer.add_branch_alteration(instruction_pointer, action)
      self._altered[instruction_pointer] = error
      return {instruction_pointer:action}

  def _E_Load(self, path):
    """loads an existing flayer session from file

       This loads an existing session including all
       relevant configured data.

       Arguments:
       - path: string with the path to the savefile
    """
    shelf = shelve.open(path)
    # TODO: FIX TEMP DIR PROBLEM ON RELOAD
    self.__flayer = shelf['flayer']
    self._altered = shelf['altered']
    shelf.close()
    self.__flayer.ResetTmpDir()

  def _E_Save(self, path=""):
    """saves the current session to file

       This saves all relevant configuration data to
       continue the current session from the point
       at which it is called.

       Arguments:
       - path: string with the path to the savefile
    """
    shelf = shelve.open(path)
    shelf['flayer'] = self.__flayer
    shelf['altered'] = self._altered
    # TODO  add readline history support
    shelf.sync()
    shelf.close()

  def _E_About(self):
    """returns more information about Flayer!

       Run it and see.

       Arguments:
       - none
    """
    print "%s\n" % self.__flayer.About()

  def _E_Help(self, topic='overview'):
    """provides overall and detail help for each shell command

       This provides the overview and detailed help
       you are reading now. In addition, it falls through
       to the builtin help if nothing matches.

       Arguments:
       - topic -- (default: 'overview')
    """
    if topic == 'overview':
      print "Available commands:"
      format = "  %-15s -- %s"
      for command in filter(lambda x: x[:3] == '_E_', self.__class__.__dict__):
        doc =  self.__class__.__dict__[command].__doc__
        name = command[3:].lower()
        if doc is None:
          print format % (name, "No documentation. Bad Developer!")
        else:
          print format % (name, doc.split("\n")[0])
      return
    for method in self.__class__.__dict__.items():
      name = method[0][3:].lower()
      if name == topic:
        doc = self.__class__.__dict__[method[0]].__doc__.split("\n")
        details = "\n".join([l.lstrip() for l in doc])
        print "%s -- %s" % (name, details)
        return

    print "Topic '%s' is unknown to Flayer.\n" % topic
    print "Attempting to use the builtin help function.\n"
    sys.modules['__builtin__'].help(topic)
