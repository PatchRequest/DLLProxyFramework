#include <windows.h>

__declspec(dllexport) int helper_greet(void) {
    return 42;
}

__declspec(dllexport) int helper_add(int a, int b) {
    return a + b;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r; (void)reason;
    return TRUE;
}
