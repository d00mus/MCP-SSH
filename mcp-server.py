#!/usr/bin/env python3
"""Run the gateway from a source checkout: `python mcp-server.py --servers-config servers.json`."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_ssh_gateway.main import main  # noqa: E402

if __name__ == "__main__":
    main()
