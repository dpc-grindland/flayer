========================================
Flayer
========================================

Flayer & LibFLayer

Will Drewry <wad@gmail.com>, Tavis Ormandy <taviso@gmail.com>

Copyright 2007 Google Inc.



Quick summary
========================================

Flayer is a valgrind plugin. It implements taint tracing and throws
information errors when tainted information is used in a conditional or system
call.  In addition, strlen, strcmp, and other string/memory-related functions
will also throw a "client check" error where forced tainting is used to taint
the output of those functions.

Using this output, Flayer can forcibly bypass conditional jumps and/or step
over function calls.

.. code-block::sh

    $ valgrind --tool=flayer --help
    ......
    ......
    User options for Flayer:
    --alter-fn=0xADDR1:1,...         Inserts a forced jump over the function
                                     called from the given address and sets EAX
                                     to the 32-bit value.
    --taint-string=somestr           Taint bytes read() that match the string
    --alter-branch=0xADDR1:1,...     instrument branches (Ist_Exit) guards
                                     given addresses changing them to 1 or 0
    --taint-stdin=no|yes             enables stdin tainting [no]
    --taint-file=no|yes              enables file tainting [no]
    --taint-network=no|yes           enables network tainting [no]
    --file-filter=/path/prefix       enforces tainting on any files under
                                     the given prefix. []
    --verbose-instrumentation=no|yes enables verbose translation logging [no]



Installing Flayer
========================================

you can build by running:

.. code-block:: sh

    ./configure &&  make &&  make install

Despite valgrind supporting multiple architectures, currently Flayer only works
with 32-bit x86 code.  This is due to the system call wrapping code.  If you'd
like to submit a patch to add more platforms, better system call coverage, or
use of the valgrind syswrap code, please drop me a mail!



Using LibFlayer
========================================

Currently, there is no installer for LibFlayer.  Feel free to send a patch!

Until then, you can try it out by setting your PYTHONPATH. E.g.,

.. code-block:: sh

    PYTHONPATH=/opt/libflayer /opt/libflayer/examples/flayersh



Disclaimer
========================================

This software is a proof of concept.  It is not pretty, but it is functional.
Use at your own risk.  If you'd like to make it better, submit patches and
feedback!



License
========================================

All included source, unless otherwise noted, is released on the GPL version 2.
See docs/COPYING for details.
