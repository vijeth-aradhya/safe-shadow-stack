# Safe ShadowCallStack Impl

## Notes

* Run `libcountcalls.so` dr client with a simple helloworld C program.

## Doubts

* Get a gdb-like (disassembled) instr by instr list (runtime)
* Catch call/ret
* How to get a safe/protected region in dynamorio?
* Hnadling arbitrary jmp instr or multi-threading?

## Resources

* [Code Manipulation API](http://dynamorio.org/docs/API_BT.html) (Dynamo docs)
* http://dynamorio.org/docs/using.html
* `drmgr_register_bb_instrumentation_event()`

## System

* Operating System: Ubuntu 16.04.6 LTS
* Kernel: Linux 4.15.0-45-generic
* Architecture: x86-64

## Helpful Blogs

* http://deniable.org/reversing/binary-instrumentation

## Additional Readings

1. https://clang.llvm.org/docs/ShadowCallStack.html#security
2. https://security.stackexchange.com/questions/185125/how-to-protect-the-shadow-stack
3. https://www.phoronix.com/scan.php?page=news_item&px=LLVM-Drops-ShadowCallStack-x64
4. https://en.wikipedia.org/wiki/Shadow_stack
