"""MCP server that gives an AI agent SSH terminals."""

import warnings

__version__ = "7.0.0"

# paramiko 3.x still takes TripleDES from where `cryptography` deprecated it, and the warning would
# land in the MCP client's log at every start. The gateway does not depend on that cipher.
warnings.filterwarnings("ignore", message="TripleDES has been moved", module=r"paramiko\.")
