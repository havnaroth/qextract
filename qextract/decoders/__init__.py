"""Quarantine decoders.

A decoder turns the files one quarantine artifact matched into readable rows and,
where it can, the original (malicious) files. Register one with @decoder('name')
and reference it from a source definition: {"kind": "quarantine", "decoder": "name"}.

    def decode(ctx, files, options) -> list[dict]

ctx.read(entry)                        bytes of a matched file
ctx.save(name, data)                   stores a recovered file, returns where it went
ctx.warn(message)                      adds a warning to the report
files                                  fs.Entry objects matched by the artifact
options                                the artifact's "options" object (may be empty)

Rows use the columns in collect.QUARANTINE_COLUMNS; missing ones stay empty.
"""

DECODERS = {}


def decoder(name):
    def register(fn):
        DECODERS[name] = fn
        return fn
    return register


# registers the built-in decoders
from . import (avast, avira, bitdefender, defender, emsisoft, eset, forticlient, gdata, kaspersky,  # noqa: E402,F401
               malwarebytes, mcafee, roguekiller, superantispyware, symantec, withsecure, xor)
