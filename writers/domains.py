"""Plain domain-only writer: one domain per line, no IP prefix."""

from __future__ import annotations

import os
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line


class DomainsWriter(BaseWriter):
    optimize_subdomains = False

    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-domains.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# Processed blocklist (domains) - generated: {meta.now_str}\n")
            fh.write("# Format: one domain per line\n")
            fh.writelines(summary_line(meta, "#", optimized=False))
            fh.write("# Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, "#")
            fh.write("# ---- merged entries ----\n")
            for d in domains:
                fh.write(f"{d}\n")
        return path
