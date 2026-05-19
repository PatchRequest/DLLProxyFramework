#include "payload.h"
#include <stdio.h>

DWORD WINAPI payload_main(LPVOID lpParam) {
    (void)lpParam;
    FILE *f = fopen("proof.txt", "w");
    if (f) { fprintf(f, "ok"); fclose(f); }
    return 0;
}
