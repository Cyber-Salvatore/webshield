"""
Allow running WebShield as a module:  python -m webshield <target> [options]
"""
import sys
import os

# Ensure the parent directory is in path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import main  # noqa: E402

if __name__ == "__main__":
    main()
