"""Entrypoint for python -m jwt_audit_sentinel"""

import sys
from jwt_audit_sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
