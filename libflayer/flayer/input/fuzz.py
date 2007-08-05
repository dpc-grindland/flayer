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
"""contains classes for fuzzing various inputs
   with the random class

   import input.fuzz
   f = input.fuzz.FuzzFile()
   f.Run()
   command(..,[f.get_target()],..)
   run()
"""

__author__ = "Will Drewry"

import binascii
import os
import random
import tempfile

#### Support classes - where should this go?
class Fuzz:
  def __init__(self, seed=0, block_size=4096):
    # Note: SystemRandom appears to ignore seeding.
    self._rand = random.Random()
    self._seed = seed
    self._rand.seed(seed)
    self._target = None # subclass must supply
    self._block_size = block_size
    self._max_bytes = 1024*1024

  def set_target(self, target=None):
    """sets the fuzz output target"""
    self._target = target

  def get_target(self):
    """returns the current target - not a copy"""
    return self._target

  def set_seed(self, seed=0):
    """sets the fuzz seed"""
    self._seed = seed
    self._rand.seed(seed)

  def get_seed(self):
    """returns the current seed"""
    return self._seed

  def set_block_size(self, size=4096):
    """sets the fuzz block_size"""
    self._block_size = size

  def get_block_size(self):
    """returns the current block_size"""
    return self._block_size

  def set_maximum_bytes(self, bytes):
    self._max_bytes = bytes

  def get_maximum_bytes(self, bytes):
    return self._max_bytes

  def __del__(self):
    self.CleanUp()

  def CleanUp(self):
    pass

  def Run(self):
    self._Run()

  def _Run(self):
    raise RuntimeError, "_Run() should be implemented in a subclass"

class FuzzWritable(Fuzz):
  def _Run(self):
    """writes up to the given limit to _target"""
    if self._target is None:
      raise RuntimeError, "No target set"
    bytes = 0
    while bytes < self._max_bytes:
      bytes += self._block_size
      bits = self._rand.getrandbits(self._block_size * 8)
      # annoying way to convert to bytes without looping.
      # haven't benchmarked - may be slower.
      hexed = hex(bits)[2:-1]
      if len(hexed) % 2 != 0:
        hexed += '0'
      payload = binascii.unhexlify(hexed)
      self._target.write(payload)

class FuzzFile(FuzzWritable):
  def __init__(self, seed=0, block_size=4096):
    FuzzWritable.__init__(self, seed, block_size)
    self.set_file()

  def set_file(self, filename=tempfile.mktemp()):
    # clean up any old files
    if self._target is not None:
      os.file.remove(self._target.name)
    self._target = file(filename, 'w')

  def get_file(self):
    return self._target.name

  def CleanUp(self):
    # Clean up tmp file
    if self._target is not None and \
       os.path.exists(self._target.name):
      os.remove(self._target.name)

  def set_target(self, target):
    self.set_file(target)

  def get_target(self):
    return self.get_file()
