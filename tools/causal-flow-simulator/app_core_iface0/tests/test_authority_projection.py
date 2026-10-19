from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))

from authority_projection import (  # noqa: E402
    AuthorityEvent,
    AuthorityProjectionUnavailable,
    authority_ready_width,
    fold_authority,
)
from v3 import protocol_model_v3 as v3  # noqa: E402


class AuthorityProjectionTests(unittest.TestCase):
    ROOT = "11" * 32
    GRANT = "22" * 32

    def test_grant_and_reduction_use_acting_prefix_authority(self) -> None:
        grant = AuthorityEvent(
            reference=self.GRANT,
            actor=self.ROOT,
            sequence=0,
            kind="GRANT",
            dependencies=frozenset(),
            ancestors=frozenset(),
        )
        child_action = AuthorityEvent(
            reference="33" * 32,
            actor=self.GRANT,
            sequence=0,
            kind="ACTION",
            dependencies=frozenset({self.GRANT}),
            ancestors=frozenset({self.GRANT}),
        )
        revoke = AuthorityEvent(
            reference="44" * 32,
            actor=self.ROOT,
            sequence=1,
            kind="REVOKE",
            dependencies=frozenset({self.GRANT, child_action.reference}),
            ancestors=frozenset({self.GRANT, child_action.reference}),
            target_credential=self.GRANT,
        )
        after_revoke = AuthorityEvent(
            reference="55" * 32,
            actor=self.GRANT,
            sequence=1,
            kind="ACTION",
            dependencies=frozenset({child_action.reference, revoke.reference}),
            ancestors=frozenset(
                {self.GRANT, child_action.reference, revoke.reference}
            ),
        )
        value = fold_authority(
            (grant, child_action, revoke, after_revoke),
            {
                self.ROOT: (None, self.ROOT),
                self.GRANT: (self.ROOT, self.GRANT),
            },
            self.ROOT,
            {},
            state_limit=256,
            transition_limit=512,
        )
        self.assertEqual(
            value.accepted_controls, frozenset({grant.reference, revoke.reference})
        )
        self.assertEqual(value.event_authority[child_action.reference], "MUST_AUTH")
        self.assertEqual(value.event_authority[after_revoke.reference], "NO_AUTH")
        self.assertEqual(value.revoked, frozenset({self.GRANT}))
        self.assertEqual(value.terminated, frozenset({self.GRANT}))
        self.assertEqual(value.terminal_authority, frozenset({self.ROOT}))
        self.assertEqual(value.max_concurrent_controls, 1)
        self.assertGreater(value.ordinary_prefix_query_max, 0)
        self.assertEqual(
            value.replayed_event_work,
            4 + value.transition_count + 2,
        )

    def test_concurrent_control_limit_fails_before_fold_release(self) -> None:
        controls = tuple(
            AuthorityEvent(
                reference=f"{index + 2:064x}",
                actor=self.ROOT,
                sequence=index,
                kind="GRANT",
                dependencies=frozenset(),
                ancestors=frozenset(),
            )
            for index in range(4)
        )
        lineage = {self.ROOT: (None, self.ROOT)}
        lineage.update(
            {event.reference: (self.ROOT, event.reference) for event in controls}
        )
        with self.assertRaisesRegex(
            AuthorityProjectionUnavailable, "AUTHORITY_CONCURRENT_CONTROLS"
        ):
            fold_authority(
                controls,
                lineage,
                self.ROOT,
                {},
                state_limit=256,
                transition_limit=512,
                concurrent_limit=3,
            )

    def test_v9_isolated_authority_states_witness_is_exact(self) -> None:
        rows = (
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
        references = {
            name: hashlib.sha256(name.encode("ascii")).hexdigest()
            for name, *_ in rows
        }
        credentials = {
            "R": self.ROOT,
            "X1": references["R.3"],
            "X2": references["R.5"],
            "X3": references["R.7a"],
            "Y": references["X3.0"],
            "Z": references["X3.1"],
        }
        direct = {
            name: set(([predecessor] if predecessor else []) + list(parents))
            for name, _, _, _, _, predecessor, parents in rows
        }
        ancestors = {name: set() for name in direct}
        for _ in range(len(rows)):
            previous = {name: set(value) for name, value in ancestors.items()}
            for name, dependencies in direct.items():
                ancestors[name] = set(dependencies).union(
                    *(ancestors[item] for item in dependencies)
                )
            if ancestors == previous:
                break
        else:
            self.fail("isolated authority witness is cyclic")
        events = tuple(
            AuthorityEvent(
                reference=references[name],
                actor=credentials[actor],
                sequence=sequence,
                kind=kind,
                dependencies=frozenset(references[item] for item in direct[name]),
                ancestors=frozenset(references[item] for item in ancestors[name]),
                target_credential=credentials[target] if target else None,
            )
            for name, actor, sequence, kind, target, _, _ in rows
        )
        lineage = {
            credentials["R"]: (None, credentials["R"]),
            credentials["X1"]: (credentials["R"], references["R.3"]),
            credentials["X2"]: (credentials["R"], references["R.5"]),
            credentials["X3"]: (credentials["R"], references["R.7a"]),
            credentials["Y"]: (credentials["X3"], references["X3.0"]),
            credentials["Z"]: (credentials["X3"], references["X3.1"]),
        }
        forks = {
            (credentials["R"], 7): tuple(
                sorted((references["R.7a"], references["R.7b"]))
            ),
            (credentials["R"], 8): tuple(
                sorted((references["R.8a"], references["R.8b"]))
            ),
            (credentials["X3"], 2): tuple(
                sorted((references["X3.2a"], references["X3.2b"]))
            ),
        }
        self.assertEqual(authority_ready_width(events, forks), (3, 63))
        unbounded = fold_authority(
            events,
            lineage,
            credentials["R"],
            forks,
            state_limit=1000,
            transition_limit=1000,
        )
        self.assertEqual(unbounded.reachable_state_count, 273)
        self.assertEqual(unbounded.transition_count, 500)
        self.assertEqual(unbounded.max_concurrent_controls, 3)
        self.assertEqual(unbounded.ordinary_prefix_query_max, 9)
        self.assertEqual(unbounded.replayed_event_work, 1199)
        with self.assertRaisesRegex(
            AuthorityProjectionUnavailable, "AUTHORITY_STATES"
        ):
            fold_authority(
                events,
                lineage,
                credentials["R"],
                forks,
                state_limit=256,
                transition_limit=512,
            )

    def test_same_slot_fork_terminates_only_credential_lineage(self) -> None:
        left = AuthorityEvent(
            reference="66" * 32,
            actor=self.ROOT,
            sequence=0,
            kind="ACTION",
            dependencies=frozenset(),
            ancestors=frozenset(),
        )
        right = AuthorityEvent(
            reference="77" * 32,
            actor=self.ROOT,
            sequence=0,
            kind="ACTION",
            dependencies=frozenset(),
            ancestors=frozenset(),
        )
        value = fold_authority(
            (left, right),
            {self.ROOT: (None, self.ROOT)},
            self.ROOT,
            {(self.ROOT, 0): (left.reference, right.reference)},
            state_limit=256,
            transition_limit=512,
        )
        self.assertEqual(value.forked_credentials, frozenset({self.ROOT}))
        self.assertEqual(value.terminated, frozenset({self.ROOT}))
        self.assertEqual(value.event_authority[left.reference], "MUST_AUTH")
        self.assertEqual(value.event_authority[right.reference], "MUST_AUTH")

    def test_fold_matches_the_independent_v3_model_on_a_control_history(self) -> None:
        root = v3.Binding(
            credential_id=self.ROOT,
            suite_id="0x0001",
            verification_key="aa" * 32,
            issuer_id=None,
            grant_reference=self.ROOT,
            genesis=True,
        )
        grant = v3.make_event(
            "grant",
            root,
            role=v3.Role.CREDENTIAL_CONTROL,
            kind=v3.Kind.GRANT,
            grantee_suite="0x0001",
            grantee_key="bb" * 32,
        )
        child = v3.grant_binding(grant)
        action = v3.make_event("action", child, parents=(grant.reference,))
        revoke = v3.make_event(
            "revoke",
            root,
            sequence=1,
            predecessor=grant.reference,
            parents=(action.reference,),
            role=v3.Role.CREDENTIAL_CONTROL,
            kind=v3.Kind.REVOKE,
            target_id=child.credential_id,
        )
        scenario = v3.Scenario(
            events=(grant, action, revoke), genesis_bindings=(root,)
        )
        oracle = v3.project(scenario)
        ancestors = v3._causal_ancestors(scenario.events)
        mapped = tuple(
            AuthorityEvent(
                reference=event.reference,
                actor=event.actor_id,
                sequence=event.sequence,
                kind=event.kind.value,
                dependencies=frozenset(
                    item
                    for item in (*event.parents, event.predecessor)
                    if item is not None
                ),
                ancestors=ancestors[event.reference],
                target_credential=event.target_id,
            )
            for event in scenario.events
        )
        observed = fold_authority(
            mapped,
            {
                root.credential_id: (None, root.grant_reference),
                child.credential_id: (child.issuer_id, child.grant_reference),
            },
            root.credential_id,
            {},
            state_limit=256,
            transition_limit=512,
        )
        self.assertEqual(observed.accepted_controls, oracle.accepted_controls)
        self.assertEqual(observed.revoked, oracle.revoked)
        self.assertEqual(observed.terminated, oracle.terminated)
        self.assertEqual(observed.terminal_authority, oracle.terminal_authority)
        self.assertEqual(
            observed.event_authority,
            {key: value.value for key, value in oracle.event_authority.items()},
        )


if __name__ == "__main__":
    unittest.main()
