"""dnsmasq writer: address=/domain/# (returns NXDOMAIN for all record types)."""

from __future__ import annotations

import os
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line


class DnsmasqWriter(BaseWriter):
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-dnsmasq.conf")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# Processed blocklist (dnsmasq) - generated: {meta.now_str}\n")
            fh.write("# Format: address=/domain/# (NXDOMAIN)\n")
            fh.writelines(summary_line(meta, "#"))
            fh.write("# Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, "#")
            fh.write("# ---- merged entries ----\n")
            for d in domains:
                fh.write(f"address=/{d}/#\n")
        return path
