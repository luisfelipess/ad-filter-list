# ad-filter-list

Tool to fetch multiple host/blocklist sources, merge them, remove duplicates, and produce a single processed blocklist formatted for network devices (MikroTik-friendly).

------

Quick start

From the `ad-filter-list/` directory run:

```bash
./update-lists
```

Options

- `--unsorted` (passed to `./update-lists`) — preserve first-seen/source order instead of alphabetical sort
- `--raw` (merge.py) — directory where sources are downloaded (default `raw`)
- `--map` (merge.py) — mapping file produced during fetch (default `raw/sources.map`)
- `--out` (merge.py) — output file path (default `processed/blocklist.txt`)

Outputs

- `processed/blocklist.txt` — merged, deduplicated, and formatted output
- `processed/rejected-entries.txt` — records lines that couldn't be parsed or unsupported source files
- `processed/blocklist-report.json` — per-source JSON report with counts and reasons
- `raw/` — downloaded copies of each source (excluded from git by default)
- `raw/sources.map` — mapping between downloaded filenames and original URLs

MikroTik compatibility

The output uses `0.0.0.0 domain` format which is compatible with many devices and can be transformed or imported into MikroTik adlists using the companion scripts in the repository (see `mikrotik-adlist/transform.sh` for examples). The preserved per-source headers help with auditing and attribution when publishing.
