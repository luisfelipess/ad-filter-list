"""Adblock/uBlock Origin writer: ||domain^ and ||*.domain^ for wildcards."""

from __future__ import annotations

import os
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line, split_wildcard_domains


class AdblockWriter(BaseWriter):
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-adblock.txt")
        exact, wildcards = split_wildcard_domains(domains, meta.wildcard_domains)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"! Processed blocklist (Adblock) - generated: {meta.now_str}\n")
            fh.write("! Format: Adblock Filter Syntax (||domain^ / ||*.domain^)\n")
            fh.writelines(summary_line(meta, "!"))
            fh.write("! Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, "!")
            fh.write("\n! ---- merged entries ----\n")
            for d in wildcards:
                fh.write(f"||*.{d}^\n")
            for d in exact:
                fh.write(f"||{d}^\n")
        return path
