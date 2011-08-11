SLIPFEST
--------

Version 1.01 'CanSecWest 2006 edition'

SLIPFEST (system level intrusion prevention framework evaluation suite and 
toolkit) is a toolkit to help the evaluation of HIPS systems such as CISCO CSA, 
McAfee Entercept, Ozone, Whentrust.. It is distributed under the conditions of 
GPL version 2

Additional information can be found on http://slipfest.cr0.org

The authors can be reached through <slipfest at cr0.org>

Yoann Guillot <john at ofjj.net> Julien Tinnes <julien at cr0.org>

FAQ:
----

Q: How can I compile Slipfest?
A: The driver can be compiled with the Windows DDK and the SPLIFEST application
can be compiled with Visual C++ 2005. You can get the express edition for
free from Microsoft http://msdn.microsoft.com/vstudio/express/

Q: Why does my target crash ?

A: You probably ran a search type shellcode (everything with a ".ret" ) in a 
remote process, and it did not find the right opcodes. You can try locally :
uncheck 'run in remote process', Slipfest will inject the opcodes automatically 
so that it cannot fail.

It could also be a protection (such as SafeSEH or NX) (nb: there is a version 
of the egghunt that tricks SafeSEH [Does'nt work under Vista for now])

Q: Why is UTRegister hooked (List all hooks) ?

A: When trying to ret to kernel32 in local process (run in remote process is 
unchecked) on the stack, SLIPFEST will patch UTRegister to inject some opcodes 
(see 'Why does it crash?')

Q: Why are there only two editbox ?

A: Each editbox has different purposes. For example the second editbox can be a 
proc name, an address or the number of process and threads to create with ASLR 
test, the number of bytes to patch, the dump filename, a binary string to patch 
or the 'target by mouse delay'. I know, it's crazy, but it helps preventing the 
GUI to be usable :)

Q: How does 'Test NX' work?

A: The shellcode will patch the unhandled exeption handler pointer in the TEB 
of the target process, then zeroes the load_config dir in the PE (to disable 
safeseh). Then it'll VirtualAlloc and VirtualProtect PAGE_READWRITE 
some code and run it. Depending on wether the exception handler is called 
or not it'll print a MessageBox telling that NX is enable or disabled.

Q: What is NX?

A: NX (AMD's name), called DEP (data execution prevention) by Microsoft and XD 
(eXecute Disable) by Intel is the support for non executable pages by the 
processor. If your version of Windows supports DEP (and it is enabled) and if 
your processor supports NX, Windows will use the processor in PAE mode and use 
the NX flags in the PTEs. This means that a page which is not marked as 
executable will not be executable.

Some HIPS will use PaX' splitted TLB instrumentation to 'emulate' NX.

Q: Why is "run in remote process" or "run on stack" unchecked when I select my 
shellcode?

A: Starting from version 1.01, there is an automatic consistency check which is 
done when you select your shellcode. Invalid combinations are not allowed.

However, beeing a research tool, SLIPFEST does'nt want to go in your way and 
will allow you to force an invalid combination by selecting it after the 
shellcode selection.

       HEAP   | PE      | K32
       -------+---------+--------
Local  STACK  | STACK   | STACK
       N/A    | NOSTACK | N/A
       -------+---------+--------
Remote N/A    | STACK   | STACK
       N/A    | NOSTACK | NOSTACK

N/A: not available
STACK: run on stack is checked
NOSTACK: run on stack is unchecked

The only way to return to the heap is by running from the current process'
stack. This is a limitation.

In the local (SLIPFEST) process, if not ran on stack you cannot return to 
anything but the PE. This is because in this situation the shellcode will be 
ran from the PE of slipfest.exe and cannot be relocated. This is not really a 
limitation, feel free to use SLIPFEST as your remote process.
