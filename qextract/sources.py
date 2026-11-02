"""Source definitions: which files to collect, and how to decode them, per product.

Each *.json file describes one product:

{
  "id": "defender",                       unique; a file with the same id loaded later replaces it
  "name": "Microsoft Defender",
  "references": ["https://..."],          optional, where the locations come from
  "artifacts": [
    {
      "name": "Quarantine",
      "kind": "quarantine",               quarantine | log | eventlog | database | other
      "paths": ["ProgramData/Microsoft/Windows Defender/Quarantine/**"],
      "decoder": "defender",              optional, see decoders/__init__.py
      "parser": "defender_evtx",          optional, adds rows to detections.csv, see parsers/__init__.py
      "options": {}                       optional, passed to the decoder / parser
    }
  ]
}

Paths are relative to the root of a Windows volume and case-insensitive.
'*' and '?' match within one name, '**' matches any number of folders, and a segment
written as 'regex:<expression>' is matched as a regular expression (as in KAPE FileMask).
"""

import glob
import json
import os
import re
import sys

from .decoders import DECODERS
from .fs import _segment
from .parsers import PARSERS

# Compiled from the location database by tools/locations.py (not in git).
BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sources')


def exe_sources_dir():
    """The 'sources' folder next to the exe (user additions), None when run from source."""
    return os.path.join(os.path.dirname(sys.executable), 'sources') if getattr(sys, 'frozen', False) else None


def default_dirs(exe_dir=True):
    """Built-in definitions, then the 'sources' folder next to the exe unless exe_dir is
    False (as administrator: whoever can write next to the exe must not be able to make an
    administrator copy files of their choice)."""
    extra = exe_sources_dir()
    return [BUILTIN_DIR] + ([extra] if exe_dir and extra else [])


def _validate(src):
    """A definition file is user input: anything that is not the expected shape is refused
    with a message, never allowed to break the run."""
    if not isinstance(src, dict):
        raise ValueError('must be a JSON object with "id", "name" and "artifacts"')
    for key in ('id', 'name'):
        if not isinstance(src.get(key), str) or not src[key].strip():
            raise ValueError(f'"{key}" must be a non-empty string')
    arts = src.get('artifacts')
    if not isinstance(arts, list) or not arts:
        raise ValueError('"artifacts" must be a non-empty list')
    for n, art in enumerate(arts, 1):
        if not isinstance(art, dict):
            raise ValueError(f'artifact {n} must be an object')
        paths = art.get('paths')
        if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p.strip() for p in paths):
            raise ValueError(f'artifact {n}: "paths" must be a non-empty list of strings')
        for p in paths:      # compiled the same way the search will, so it cannot fail later
            try:
                for part in p.replace('\\', '/').split('/'):
                    _segment(part)
            except re.error as e:
                raise ValueError(f'artifact {n}: bad pattern "{p}": {e}') from e
        art.setdefault('name', art.get('kind', 'files'))
        art.setdefault('kind', 'other')
        for key in ('name', 'kind'):
            if not isinstance(art[key], str):
                raise ValueError(f'artifact {n}: "{key}" must be a string')
        for key, known in (('decoder', DECODERS), ('parser', PARSERS)):
            value = art.get(key)
            if value is not None and (not isinstance(value, str) or value not in known):
                raise ValueError(f'artifact {n}: unknown {key} "{value}" (known: {", ".join(sorted(known))})')
        if not isinstance(art.setdefault('options', {}), dict):
            raise ValueError(f'artifact {n}: "options" must be an object')


def load_sources(extra_dirs=(), log=print, exe_dir=True):
    """Return ({id: source}, [error messages])."""
    sources, errors = {}, []
    for d in default_dirs(exe_dir) + list(extra_dirs):
        if not os.path.isdir(d):
            if d in extra_dirs:
                errors.append(f'sources folder not found: {d}')
            continue
        for path in sorted(glob.glob(os.path.join(d, '*.json'))):
            try:
                with open(path, encoding='utf-8-sig') as f:
                    src = json.load(f)
                _validate(src)
            except (OSError, ValueError) as e:
                errors.append(f'{path}: {e}')
                continue
            src['file'] = path
            if src['id'] in sources and d != BUILTIN_DIR:
                log(f'Source "{src["id"]}" replaced by {path}')
            sources[src['id']] = src
    return sources, errors
