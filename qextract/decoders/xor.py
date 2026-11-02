"""Single-byte XOR, for products that only obfuscate quarantined files.

Options: "key" (number or "0x..", required), "skip" (header bytes to drop, default 0),
"match" (glob on the file name, default "*").
"""

import fnmatch

from . import decoder
from .util import guard, recovered, xor


@decoder('xor')
def decode(ctx, files, options):
    key = options.get('key')
    if key is None:
        ctx.warn('xor decoder: "key" option is missing')
        return []
    key = int(key, 0) if isinstance(key, str) else int(key)
    skip = int(options.get('skip', 0))
    rows = []
    for f in files:
        if not fnmatch.fnmatch(f.name.lower(), options.get('match', '*').lower()):
            continue
        with guard(rows, f):
            rows.append(recovered(ctx, {'container': f.path, 'item_type': 'file'},
                                  xor(ctx.read(f)[skip:], key), name=f.name))
    return rows
