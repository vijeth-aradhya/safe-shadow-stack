/*

backward jump test 2: more stack frames

*/


#include <setjmp.h>
#include <stdio.h>

jmp_buf env;

void func1();
void func2(int t);
void func3();

int main() {
    int ret = setjmp(env);
    if (!ret) {
        func2(1);
    }
    func1();
}

void func1() {
    int i;
    i = 1;
    fprintf(stderr, "Enter %d\n", i);
}

void func2(int t) {
    fprintf(stderr, "Enter 2.%d\n", t);
    if (t <= 50)
        func2(t+1);
    else
        func3();
}

void func3() {
    int i;
    i = 3;
    fprintf(stderr, "Enter %d\n", i);
    longjmp(env, i-2);
}
