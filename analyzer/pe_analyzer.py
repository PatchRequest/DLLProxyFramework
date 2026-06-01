import re
from dataclasses import dataclass, field
from pathlib import Path

import pefile


@dataclass
class ExportEntry:
    ordinal: int
    name: str | None
    safe_name: str
    forwarder: str | None = None
    forwarder_dll: str | None = None
    forwarder_func: str | None = None

    @property
    def is_named(self) -> bool:
        return self.name is not None

    @property
    def is_forwarded(self) -> bool:
        return self.forwarder is not None

    @property
    def is_ordinal_only(self) -> bool:
        return self.name is None


@dataclass
class VersionInfo:
    company_name: str = ""
    file_description: str = ""
    file_version: str = ""
    internal_name: str = ""
    legal_copyright: str = ""
    original_filename: str = ""
    product_name: str = ""
    product_version: str = ""
    file_version_ms: int = 0
    file_version_ls: int = 0
    product_version_ms: int = 0
    product_version_ls: int = 0

    @property
    def file_version_tuple(self) -> tuple[int, int, int, int]:
        return (
            (self.file_version_ms >> 16) & 0xFFFF,
            self.file_version_ms & 0xFFFF,
            (self.file_version_ls >> 16) & 0xFFFF,
            self.file_version_ls & 0xFFFF,
        )

    @property
    def product_version_tuple(self) -> tuple[int, int, int, int]:
        return (
            (self.product_version_ms >> 16) & 0xFFFF,
            self.product_version_ms & 0xFFFF,
            (self.product_version_ls >> 16) & 0xFFFF,
            self.product_version_ls & 0xFFFF,
        )


@dataclass
class ExportTable:
    dll_name: str
    dll_name_no_ext: str
    machine: int
    is_64bit: bool
    ordinal_base: int
    exports: list[ExportEntry] = field(default_factory=list)
    version_info: VersionInfo | None = None
    has_signature: bool = False

    @property
    def named_exports(self) -> list[ExportEntry]:
        return [e for e in self.exports if e.is_named]

    @property
    def ordinal_only_exports(self) -> list[ExportEntry]:
        return [e for e in self.exports if e.is_ordinal_only]

    @property
    def forwarded_exports(self) -> list[ExportEntry]:
        return [e for e in self.exports if e.is_forwarded]

    @property
    def max_ordinal(self) -> int:
        return max((e.ordinal for e in self.exports), default=0)


_REPLACEMENTS = {
    '?': '_Q', '@': '_A', '$': '_D', '<': '_L', '>': '_G',
    ',': '_C', ' ': '_S', '-': '_H', ':': '_K', '~': '_T',
    '(': '_OP', ')': '_CP', '[': '_OB', ']': '_CB',
    '{': '_OC', '}': '_CC', '=': '_EQ', '+': '_P',
    '&': '_R', '*': '_X', '!': '_N', '#': '_SH',
}


def sanitize_identifier(name: str) -> str:
    result = name
    for old, new in _REPLACEMENTS.items():
        result = result.replace(old, new)
    result = re.sub(r'[^a-zA-Z0-9_]', '_', result)
    if result and result[0].isdigit():
        result = '_' + result
    return result


class PEAnalyzer:
    def analyze(self, dll_path: str | Path) -> ExportTable:
        dll_path = Path(dll_path)
        if not dll_path.exists():
            raise FileNotFoundError(f"DLL not found: {dll_path}")

        pe = pefile.PE(str(dll_path), fast_load=False)

        machine = pe.FILE_HEADER.Machine
        is_64bit = machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            raise ValueError(f"DLL has no export directory: {dll_path}")

        export_dir = pe.DIRECTORY_ENTRY_EXPORT
        dll_name = dll_path.name
        dll_name_no_ext = dll_path.stem

        table = ExportTable(
            dll_name=dll_name,
            dll_name_no_ext=dll_name_no_ext,
            machine=machine,
            is_64bit=is_64bit,
            ordinal_base=export_dir.struct.Base,
        )

        for sym in export_dir.symbols:
            name = sym.name.decode('ascii') if sym.name else None
            forwarder = sym.forwarder.decode('ascii') if sym.forwarder else None

            if name:
                safe_name = sanitize_identifier(name)
            else:
                safe_name = f"ordinal_{sym.ordinal}"

            forwarder_dll = None
            forwarder_func = None
            if forwarder:
                parts = forwarder.split('.', 1)
                if len(parts) == 2:
                    forwarder_dll = parts[0]
                    forwarder_func = parts[1]

            entry = ExportEntry(
                ordinal=sym.ordinal,
                name=name,
                safe_name=safe_name,
                forwarder=forwarder,
                forwarder_dll=forwarder_dll,
                forwarder_func=forwarder_func,
            )
            table.exports.append(entry)

        table.exports.sort(key=lambda e: e.ordinal)

        # Extract version info
        vi = VersionInfo()
        string_fields = {
            b'CompanyName': 'company_name',
            b'FileDescription': 'file_description',
            b'FileVersion': 'file_version',
            b'InternalName': 'internal_name',
            b'LegalCopyright': 'legal_copyright',
            b'OriginalFilename': 'original_filename',
            b'ProductName': 'product_name',
            b'ProductVersion': 'product_version',
        }
        if hasattr(pe, 'FileInfo'):
            for fi in pe.FileInfo:
                for entry in fi:
                    if hasattr(entry, 'StringTable'):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                attr = string_fields.get(k)
                                if attr:
                                    setattr(vi, attr, v.decode('utf-8', errors='replace'))
        if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
            ffi = pe.VS_FIXEDFILEINFO[0]
            vi.file_version_ms = ffi.FileVersionMS
            vi.file_version_ls = ffi.FileVersionLS
            vi.product_version_ms = ffi.ProductVersionMS
            vi.product_version_ls = ffi.ProductVersionLS

        if vi.company_name or vi.file_description:
            table.version_info = vi

        # Check for Authenticode signature
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        table.has_signature = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0

        pe.close()
        return table
