import shutil
from pathlib import Path


class ResourceEmbedder:
    def copy_original(self, source_dll: str | Path, output_dir: str | Path) -> str:
        source_dll = Path(source_dll)
        output_dir = Path(output_dir)
        dest_name = f"original_{source_dll.name}"
        shutil.copy2(source_dll, output_dir / dest_name)
        return dest_name

    def copy_payload_bin(self, source_bin: str | Path, output_dir: str | Path,
                         dest_name: str = "payload_bin.dat") -> str:
        source_bin = Path(source_bin)
        output_dir = Path(output_dir)
        shutil.copy2(source_bin, output_dir / dest_name)
        return dest_name
