"""Log parsers: turn collected logs into rows of detections.csv, one timeline for all products.

Register one with @parser('name') and reference it from a source definition:
{"kind": "eventlog", "parser": "name", "options": {...}}.

    def parse(ctx, files, options) -> list[dict]

ctx and files are the same as for decoders (see decoders/__init__.py). Rows use the
columns in collect.DETECTION_COLUMNS; missing ones stay empty.
"""

PARSERS = {}


def parser(name):
    def register(fn):
        PARSERS[name] = fn
        return fn
    return register


from . import avast, emsisoft, evtx, kaspersky, mplog, roguekiller, superantispyware, withsecure  # noqa: E402,F401  (registers the built-in parsers)
