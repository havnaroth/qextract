# Entry point for PyInstaller (a package __main__ cannot use relative imports when frozen).
from qextract.cli import main

raise SystemExit(main())
