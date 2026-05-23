"""BIND9 RPZ writer: gzip-compressed zone file with CNAME . records."""

from __future__ import annotations

import gzip
import os
from datetime import datetime, timezone
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line


class RpzWriter(BaseWriter):
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-bind9.zone.gz")
        serial = int(datetime.now(timezone.utc).timestamp())
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(f"; Processed blocklist (BIND9 RPZ) - generated: {meta.now_str}\n")
            fh.write("; Format: BIND9 RPZ zone file (CNAME to .)\n")
            fh.writelines(summary_line(meta, ";"))
            fh.write("; Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, ";")
            fh.write("\n$TTL 2h\n")
            fh.write("@ IN SOA ns.rpz.local. hostmaster.rpz.local. (\n")
            fh.write(f"    {serial} ; Serial\n")
            fh.write("    1h         ; Refresh\n")
            fh.write("    15m        ; Retry\n")
            fh.write("    30d        ; Expire\n")
            fh.write("    2h         ; Minimum TTL\n")
            fh.write(")\n")
            fh.write("@ IN NS ns.rpz.local.\n")
            fh.write("ns IN A 127.0.0.1\n\n")
            fh.write("; ---- merged entries ----\n")
            for d in domains:
                fh.write(f"{d} IN CNAME .\n")
                fh.write(f"*.{d} IN CNAME .\n")
        return path
