"""Unbound writer: local-zone always_nxdomain entries."""

from __future__ import annotations

import os
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line


class UnboundWriter(BaseWriter):
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-unbound.conf")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# Processed blocklist (Unbound) - generated: {meta.now_str}\n")
            fh.write('# Format: local-zone: "domain." always_nxdomain\n')
            fh.writelines(summary_line(meta, "#"))
            fh.write("# Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, "#")
            fh.write("# ---- merged entries ----\n")
            for d in domains:
                fh.write(f'local-zone: "{d}." always_nxdomain\n')
        return path
