/*

Basic backward jump test
<print debug statements to STDERR>

*/


#include <setjmp.h>
#include <stdio.h>

jmp_buf env;

void func1();
void func2();

int main() {
    int ret = setjmp(env);
    if (!ret) {
        func1();
    }
    func2();
}

void func1() {
    int i;
    i = 1;
    fprintf(stderr, "Enter 1\n");
    longjmp(env, i);
}

void func2() {
    int i;
    i = 3;
    fprintf(stderr, "Enter 2\n");
}