# Safe ShadowCallStack Impl

This is a Dynamorio client that maintains a return address (and stack pointer) shadow stack of a program. In case of buffer overflows, there is a control-flow transfer (to the adversary) through overwriting the return address on the stack. This client, during execution of the program, compares the return address of the current function with the top of the shadow stack (that is protected by the Dynamorio memory), right before the `ret` instruction is executed.

Additionally, this dr client also handles `longjmp()`. In particular, there are two cases: (1) backward jumps, and (2) forward jumps. `longjmp`s are typically used as a clever error handling / debugging technique. Forward jumps (usually) exhibit undefined behaviour, and therefore, should be handled carefully (exits with 139, indicating seg fault). On the other hand, backward jump, i.e., a jump from the current function to a previous function on the stack, is perfectly fine. And, these cases should be differentiated from a buffer overflow case, as in both cases, the return addresses (shadow return address and current-go-to return address) are different.

To do this, this dr client uses `drvector` (in `drcontainers`) to store both the return address and the value of the stack pointer (right before the `call` instruction is executed). An important observation is that, when the program returns from the _callee_ (to be specific, after the execution of `leave` instruction), the stack pointer is updated so that it still points to the top of the stack, after the program returns to _caller_. Thus, the difference between the `xsp` in the callee (check during `ret`) and `xsp` in the caller (on the shadow stack) is always <= 8.

Notice that, in case of buffer overflow attacks, the return address does not match, but the stack pointer does match. But, in case of `longjmp`, both the return address and stack pointer values do not match!

For someone who is new to `DBI` and Dynamorio, I recommend, running `libcountcalls.so` or `libinstrcalls.so` dr client with a simple helloworld C program; read the source code to get an idea about `dr_api.h`.

## Safety

_shadowcallstack_ makes use of Dynamorio's safe [thread-local storage](http://dynamorio.org/docs/dr__tools_8h.html#a4274226adda06339e247e4a311abdd9b); you can read more about Dynamorio's code cache and its safety in their [tutorial](http://dynamorio.org/tutorial-cgo17.html) (Page 129 onwards), or in their [doc](http://dynamorio.org/docs/using.html#sec_64bit_reach). In thid dr client, `drvector`s and files are stored in the reachable thread-specfic storage in `drcontext`.

Some of the protections in Dynamrio (see [this](https://www.google.com/url?q=https%3A%2F%2Fgithub.com%2FDynamoRIO%2Fdynamorio%2Fwiki%2FCode-Content%23security&sa=D&sntz=1&usg=AFQjCNGG1-MNdUfzBmKa-G2GtfoK85DVRQ) too):
  * ASLR of its memory: code cache, heap, and stack
  * Guard pages around every memory block: cache, heap, and stack
  * Dynamrio stack starts from the base again each time

## Using

* Set `DYNAMORIO_HOME` to the dynamrio directory (in `build.sh`)
* Set `SHADOWCALLSTACK_DIR` to this project directory
* `./build.sh` builds the dr client
* To use the client, `drrun -c $SHADOWCALLSTACK_DIR/build/libshadowcallstack.so -- <program>`

### Testing

* `bin/run_tests` is currently used to run the client against different tests

## Benchmarks

Program | Program without DynamoRio | Program with vanilla Dynamorio | Program with ShadowCallStack |
------- | ------------------------- | ------------------------------ | ---------------------------- |
`echo`  | 0.000                     | 0.094                          | 0.154                        |
`touch` | 0.004                     | 0.087                          | 0.142                        |
`md5sum`| 0.005                     | 0.093                          | 0.162                        |
`who`   | 0.005                     | 0.109                          | 0.211                        |
`pwd`   | 0.000                     | 0.081                          | 0.136                        |

## Notes

&#x2611; Handling multi-threading

&#x2611; Handling `longjmp`

&#x2611; Add extensive test suite

* *Note*: In addition to the basic tests, the following programs in [coreutils](http://www.maizure.org/projects/decoded-gnu-coreutils/) were run (on benign inputs) with shadowcallstack client: md5sum, who, ls, echo, uname, pwd, touch.
* Of course, more complicated test cases in `longjmp_progs` and `exploit_progs` category should be added.

&#x2611; Add benchmark results

## System

* Operating System: Ubuntu 16.04.6 LTS
* Cmake version: 3.14.7
* Architecture: x86-64
* Dynamorio version: [7.91.18229](https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-7.91.18229/DynamoRIO-x86_64-Linux-7.91.18229-0.tar.gz)

## Helpful Blogs

* http://deniable.org/reversing/binary-instrumentation
* http://vmresu.me/blog/2016/02/09/lets-understand-setjmp-slash-longjmp/

## Some Readings

1. https://clang.llvm.org/docs/ShadowCallStack.html#security
2. https://security.stackexchange.com/questions/185125/how-to-protect-the-shadow-stack
3. https://www.phoronix.com/scan.php?page=news_item&px=LLVM-Drops-ShadowCallStack-x64
4. https://en.wikipedia.org/wiki/Shadow_stack
5. x86-64 [cheatsheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf); [compiling](https://w3.cs.jmu.edu/lam2mo/cs261_2017_08/files/12-asm_ctrlflow.pdf) loops using `jmp`
