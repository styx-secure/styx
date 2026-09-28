"""Neutral input corpus for the ratified V9 isolated-authority witness."""

from __future__ import annotations

import hashlib
from typing import Any


_ROWS = (
    ("R.0", "R", 0, "ACTION", None, None, ()),
    ("R.1", "R", 1, "ACTION", None, "R.0", ()),
    ("R.2", "R", 2, "ACTION", None, "R.1", ()),
    ("R.3", "R", 3, "GRANT", None, "R.2", ()),
    ("R.4", "R", 4, "ACTION", None, "R.3", ()),
    ("R.5", "R", 5, "GRANT", None, "R.4", ()),
    ("R.6", "R", 6, "ACTION", None, "R.5", ()),
    ("R.7a", "R", 7, "GRANT", None, "R.6", ()),
    ("R.7b", "R", 7, "ACTION", None, "R.6", ("X2.5",)),
    ("R.8a", "R", 8, "REVOKE", "X3", "R.7b", ()),
    ("R.8b", "R", 8, "REVOKE", "X3", "R.7a", ("Y.0",)),
    ("X1.0", "X1", 0, "REVOKE", "X2", None, ("X3.2b",)),
    ("X1.1", "X1", 1, "REVOKE", "Z", "X1.0", ()),
    ("X1.2", "X1", 2, "REVOKE", "X3", "X1.1", ("X2.5",)),
    ("X2.0", "X2", 0, "ACTION", None, None, ("R.5",)),
    ("X2.1", "X2", 1, "ACTION", None, "X2.0", ()),
    ("X2.2", "X2", 2, "ACTION", None, "X2.1", ()),
    ("X2.3", "X2", 3, "ACTION", None, "X2.2", ("R.7a",)),
    ("X2.4", "X2", 4, "ACTION", None, "X2.3", ()),
    ("X2.5", "X2", 5, "ACTION", None, "X2.4", ()),
    ("X2.6", "X2", 6, "ACTION", None, "X2.5", ()),
    ("X2.7", "X2", 7, "ACTION", None, "X2.6", ("X1.2",)),
    ("X3.0", "X3", 0, "GRANT", None, None, ("R.7a", "X2.2")),
    ("X3.1", "X3", 1, "GRANT", None, "X3.0", ()),
    ("X3.2a", "X3", 2, "REVOKE", "X1", "X3.1", ("Z.1",)),
    ("X3.2b", "X3", 2, "REVOKE", "Y", "X3.1", ("Z.3",)),
    ("X3.3", "X3", 3, "ACTION", None, "X3.2b", ()),
    ("Y.0", "Y", 0, "ACTION", None, None, ("X2.7",)),
    ("Z.0", "Z", 0, "ACTION", None, None, ("X3.1",)),
    ("Z.1", "Z", 1, "ACTION", None, "Z.0", ()),
    ("Z.2", "Z", 2, "ACTION", None, "Z.1", ()),
    ("Z.3", "Z", 3, "ACTION", None, "Z.2", ()),
)


def isolated_authority_states_witness(
    *, state_limit: int, transition_limit: int
) -> dict[str, Any]:
    """Return the same raw graph facts consumed independently by both runtimes."""

    references = {
        name: hashlib.sha256(name.encode("ascii")).hexdigest()
        for name, *_ in _ROWS
    }
    credentials = {
        "R": "11" * 32,
        "X1": references["R.3"],
        "X2": references["R.5"],
        "X3": references["R.7a"],
        "Y": references["X3.0"],
        "Z": references["X3.1"],
    }
    direct = {
        name: set(([predecessor] if predecessor else []) + list(parents))
        for name, _, _, _, _, predecessor, parents in _ROWS
    }
    ancestors = {name: set() for name in direct}
    for _ in range(len(_ROWS)):
        previous = {name: set(value) for name, value in ancestors.items()}
        for name, dependencies in direct.items():
            ancestors[name] = set(dependencies).union(
                *(ancestors[item] for item in dependencies)
            )
        if ancestors == previous:
            break
    else:
        raise RuntimeError("isolated authority witness is cyclic")
    return {
        "events": [
            {
                "actor": credentials[actor],
                "ancestors": sorted(references[item] for item in ancestors[name]),
                "dependencies": sorted(references[item] for item in direct[name]),
                "kind": kind,
                "reference": references[name],
                "sequence": sequence,
                "targetCredential": credentials[target] if target else None,
            }
            for name, actor, sequence, kind, target, _, _ in _ROWS
        ],
        "forks": [
            {
                "credential": credentials[actor],
                "sequence": sequence,
                "siblings": sorted(references[name] for name in names),
            }
            for actor, sequence, names in (
                ("R", 7, ("R.7a", "R.7b")),
                ("R", 8, ("R.8a", "R.8b")),
                ("X3", 2, ("X3.2a", "X3.2b")),
            )
        ],
        "lineage": [
            {"credential": credentials["R"], "parent": None},
            {"credential": credentials["X1"], "parent": credentials["R"]},
            {"credential": credentials["X2"], "parent": credentials["R"]},
            {"credential": credentials["X3"], "parent": credentials["R"]},
            {"credential": credentials["Y"], "parent": credentials["X3"]},
            {"credential": credentials["Z"], "parent": credentials["X3"]},
        ],
        "rootCredential": credentials["R"],
        "stateLimit": state_limit,
        "transitionLimit": transition_limit,
    }

