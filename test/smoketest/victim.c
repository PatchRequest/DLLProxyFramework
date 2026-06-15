#include <windows.h>
#include <stdio.h>

/* Statically imported from helper.dll — shows up in PE import table */
__declspec(dllimport) int helper_greet(void);
__declspec(dllimport) int helper_add(int a, int b);

int main(void) {
    int g = helper_greet();
    int s = helper_add(10, 7);

    printf("helper_greet() = %d (expect 42)\n", g);
    printf("helper_add(10,7) = %d (expect 17)\n", s);

    if (g == 42 && s == 17)
        printf("PASS: all exports forwarded correctly\n");
    else
        printf("FAIL: export forwarding broken\n");

    fflush(stdout);
    Sleep(500);
    return (g == 42 && s == 17) ? 0 : 1;
}
