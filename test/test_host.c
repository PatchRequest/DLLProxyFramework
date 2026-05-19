#include <windows.h>
#include <stdio.h>

typedef BOOL (WINAPI *pfnGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *pfnGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);

int main(void) {
    printf("[host] Loading version.dll...\n");

    HMODULE hVer = LoadLibraryA("version.dll");
    if (!hVer) {
        printf("[host] FAIL: LoadLibrary returned NULL (error %lu)\n", GetLastError());
        return 1;
    }
    printf("[host] version.dll loaded at %p\n", (void*)hVer);

    pfnGetFileVersionInfoSizeA pSize =
        (pfnGetFileVersionInfoSizeA)GetProcAddress(hVer, "GetFileVersionInfoSizeA");
    if (pSize) {
        DWORD dwHandle = 0;
        DWORD size = pSize("C:\\Windows\\System32\\kernel32.dll", &dwHandle);
        printf("[host] GetFileVersionInfoSizeA(kernel32.dll) = %lu\n", size);
    } else {
        printf("[host] FAIL: GetProcAddress returned NULL\n");
    }

    printf("[host] About to exit immediately.\n");
    return 0;
}
