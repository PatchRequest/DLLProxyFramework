"""Verify that a proxy DLL has cloned metadata and signature from the original."""

import struct
import sys
from pathlib import Path

import pefile


def verify(original_path: str, proxy_path: str) -> bool:
    ok = True

    orig = pefile.PE(original_path)
    proxy = pefile.PE(proxy_path)

    # --- Check version info ---
    orig_strings = {}
    proxy_strings = {}

    for pe, target in [(orig, orig_strings), (proxy, proxy_strings)]:
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                for entry in fi:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                target[k.decode("utf-8", errors="replace")] = v.decode("utf-8", errors="replace")

    required_fields = [
        "CompanyName", "FileDescription", "FileVersion",
        "InternalName", "OriginalFilename", "ProductName",
    ]

    for field in required_fields:
        orig_val = orig_strings.get(field, "")
        proxy_val = proxy_strings.get(field, "")
        if not proxy_val:
            print(f"  FAIL: {field} missing in proxy")
            ok = False
        elif orig_val != proxy_val:
            print(f"  FAIL: {field} mismatch: '{orig_val}' vs '{proxy_val}'")
            ok = False

    # --- Check signature present ---
    with open(proxy_path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    cert_off = e_lfanew + 0x18 + (0x90 if magic == 0x20B else 0x80)
    cert_rva, cert_size = struct.unpack_from("<II", data, cert_off)

    # Check original has a signature
    orig_sec = orig.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if orig_sec.VirtualAddress != 0 and orig_sec.Size != 0:
        if cert_rva == 0 or cert_size == 0:
            print("  FAIL: original is signed but proxy has no signature")
            ok = False
        else:
            # Verify cert data starts with valid WIN_CERTIFICATE header
            if cert_rva + 8 <= len(data):
                wc_len, wc_rev, wc_type = struct.unpack_from("<IHH", data, cert_rva)
                if wc_rev != 0x0200 or wc_type != 0x0002:
                    print(f"  FAIL: invalid WIN_CERTIFICATE header (rev=0x{wc_rev:04X}, type=0x{wc_type:04X})")
                    ok = False

    orig.close()
    proxy.close()
    return ok


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: verify_meta.py <original_dll> <proxy_dll>")
        sys.exit(1)
    if verify(sys.argv[1], sys.argv[2]):
        print("  ALL CHECKS PASSED")
        sys.exit(0)
    else:
        sys.exit(1)
