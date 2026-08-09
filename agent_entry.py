"""
Standalone entry point used to build the packaged agent .exe with
PyInstaller. Not used when running from source - there, use
`python -m agent.run` instead.

This exists because agent/run.py uses package-relative imports
(`from . import config`), which only resolve correctly when it's
imported as `agent.run`. PyInstaller runs its entry script directly as
`__main__`, so it must be a plain absolute import like this one rather
than the package's own CLI module.
"""
from agent.run import main

if __name__ == "__main__":
    main()
