#include <windows.h>
#include <stdio.h>

__declspec(dllexport) void RunPayload(void) {
    FILE *f = fopen("payload_export_proof.txt", "w");
    if (f) { fprintf(f, "ok"); fclose(f); }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        FILE *f = fopen("payload_proof.txt", "w");
        if (f) { fprintf(f, "ok"); fclose(f); }
    }
    return TRUE;
}
