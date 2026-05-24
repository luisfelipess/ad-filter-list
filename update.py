#!/usr/bin/env python3
# DEPRECATED — kept for backward compatibility only.
#
# The pipeline has been restructured:
#   run.py      full pipeline entry point (download + merge + post-run)
#   fetch.py    download sources only
#   merge.py    merge and deduplicate (unchanged)
#   post_run.py update README stats
#
# This shim forwards all arguments to run.py so existing callers continue
# to work, but you should switch to:
#
#   python3 run.py [same flags]

import sys

print(
    "Warning: update.py is deprecated. Use: python3 run.py",
    file=sys.stderr,
)

import run
sys.exit(run.main(sys.argv[1:]))
