#!/usr/bin/env python3
"""Group3r - AD Group Policy enumeration and exploitation tool (Python port)."""

import sys
import os

# Ensure the package directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from group3r.__main__ import main

if __name__ == "__main__":
    main()
