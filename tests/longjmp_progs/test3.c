/*

forward jump test 3: seg fault

*/


#include <setjmp.h>
#include <stdio.h>

jmp_buf env;

void func1();
void func2(int t);
void func3();

int main() {
    func1();
    func2(1);
    longjmp(env, 1);
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
    int ret = setjmp(env);
    if (ret)
        fprintf(stderr, "Enter 3.1\n");
    fprintf(stderr, "Enter 3.0\n");
}