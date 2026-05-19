import shutil
from pathlib import Path


class ResourceEmbedder:
    def copy_original(self, source_dll: str | Path, output_dir: str | Path) -> str:
        source_dll = Path(source_dll)
        output_dir = Path(output_dir)
        dest_name = f"original_{source_dll.name}"
        shutil.copy2(source_dll, output_dir / dest_name)
        return dest_name
