"""Adblock/uBlock Origin writer: ||domain^"""

from __future__ import annotations

import os
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line


class AdblockWriter(BaseWriter):
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-adblock.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"! Processed blocklist (Adblock) - generated: {meta.now_str}\n")
            fh.write("! Format: Adblock Filter Syntax (||domain^)\n")
            fh.writelines(summary_line(meta, "!"))
            fh.write("! Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, "!")
            fh.write("\n! ---- merged entries ----\n")
            for d in domains:
                fh.write(f"||{d}^\n")
        return path
