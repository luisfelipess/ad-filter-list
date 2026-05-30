"""Unbound writer: gzip-compressed local-zone always_nxdomain config."""

from __future__ import annotations

import gzip
import os
from writers import BaseWriter, WriterMeta, write_source_credits, summary_line, split_wildcard_domains


class UnboundWriter(BaseWriter):
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        path = os.path.join(out_dir, "blocklist-unbound.conf.gz")
        # unbound local-zone covers all subdomains, so wildcard entries need no
        # special syntax — just deduplicate covered exact entries.
        exact, wildcards = split_wildcard_domains(domains, meta.wildcard_domains)
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(f"# Processed blocklist (Unbound) - generated: {meta.now_str}\n")
            fh.write('# Format: local-zone: "domain." always_nxdomain (matches subdomains)\n')
            fh.writelines(summary_line(meta, "#"))
            fh.write("# Sources and original headers (credits):\n\n")
            write_source_credits(fh, meta.source_infos, "#")
            fh.write("# ---- merged entries ----\n")
            for d in wildcards:
                fh.write(f'local-zone: "{d}." always_nxdomain\n')
            for d in exact:
                fh.write(f'local-zone: "{d}." always_nxdomain\n')
        return path
