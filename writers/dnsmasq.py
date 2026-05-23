"""dnsmasq writer: address=/domain/# — covers subdomains natively."""

from __future__ import annotations

import os
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line, split_wildcard_domains


class DnsmasqWriter(BaseWriter):
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-dnsmasq.conf")
        # dnsmasq address=/domain/# already matches all subdomains, so wildcard
        # entries need no special syntax — just deduplicate covered exact entries.
        exact, wildcards = split_wildcard_domains(domains, meta.wildcard_domains)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# Processed blocklist (dnsmasq) - generated: {meta.now_str}\n")
            fh.write("# Format: address=/domain/# (NXDOMAIN, matches subdomains)\n")
            fh.writelines(summary_line(meta, "#"))
            fh.write("# Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, "#")
            fh.write("# ---- merged entries ----\n")
            for d in wildcards:
                fh.write(f"address=/{d}/#\n")
            for d in exact:
                fh.write(f"address=/{d}/#\n")
        return path
