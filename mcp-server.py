#!/usr/bin/env python3
import sys
import os

# Add the current directory to sys.path to allow absolute imports from src
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.main import main

if __name__ == "__main__":
    main()
