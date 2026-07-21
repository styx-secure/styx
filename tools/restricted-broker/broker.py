"""The sole authoritative orchestrator.

Explicit two-branch dispatch, a fixed validation pipeline, one central
error->result mapping, and exactly one audit record per attempt. No exception
escapes ``execute``.

Idempotency lifecycle:
- Failures BEFORE the client call (fresh evidence revalidation, fresh
  repository-state check, policy/internal prep) ``abort`` the reservation, so the
  same key stays retryable — nothing was executed.
- Once the client is invoked, the outcome (success OR a client-produced failure)
  is ``complete``d as a terminal recorded result. A replay returns that recorded
  outcome without re-invoking the client, with a fresh audit record / audit_id.

Audit failure is fail-closed and non-recursive: the primary sink is attempted
exactly once; if it raises, a broker-owned in-memory emergency sink records an
``INTERNAL_ERROR`` / ``audit_sink_failure`` marker and supplies the response
``audit_id``. Because the key is already terminal before the primary audit on a
success path, an audit failure cannot enable a second side effect with that key.
"""
from __future__ import annotations

import dataclasses

import audit as audit_mod
import canonical
import evidence as evidence_mod
import idempotency as idem
import jsonparse
import model
import policy as policy_mod
import repository as repo_mod
from model import (
    OPEN_PR,
    PUSH,
    AuthUnavailable,
    ConflictError,
    EvidenceError,
    PolicyError,
    RemoteFailure,
)

RESPONSE_SCHEMA = "styx.restricted-broker-response/v1"


def _evidence_hashes(ev) -> dict:
    return {
        "scope_report_sha256": ev.hashes.scope_report_sha256,
        "runner_status_sha256": ev.hashes.runner_status_sha256,
        "hook_attestation_sha256": ev.hashes.hook_attestation_sha256,
    }


def _derived_dict(target) -> dict:
    return {
        "repository": target.repository,
        "branch": target.branch,
        "base_sha": target.base_sha,
        "head_sha": target.head_sha,
        "force": target.force,
        "draft": target.draft,
    }


def _outcome_dict(result) -> dict:
    return dict(dataclasses.asdict(result))


def _bind_request_to_evidence(request, ev) -> None:
    if request.issue_number != ev.issue_number:
        raise EvidenceError("request issue_number does not match evidence")
    if request.execution_id != ev.execution_id:
        raise EvidenceError("request execution_id does not match evidence")


class RestrictedBroker:
    def __init__(self, *, fake_client, idempotency_store, audit_sink, repository_inspector):
        self._fake_client = fake_client
        self._idempotency = idempotency_store
        self._audit_sink = audit_sink
        self._repository_inspector = repository_inspector
        # Broker-owned, not configurable from task input; only used when the
        # primary audit sink fails. In-memory, so it cannot itself fail.
        self._emergency_sink = audit_mod.InMemoryAuditSink()

    def execute(self, raw: bytes, *, _between_validations=None) -> dict:
        request_sha256 = canonical.sha256_hex(raw)
        ctx = {
            "execution_id": None,
            "issue_number": None,
            "operation": None,
            "idempotency_key": None,
            "evidence_hashes": None,
            "derived": None,
        }
        try:
            obj = jsonparse.load_object(raw)
            request = model.build_request(obj)
            ctx["idempotency_key"] = request.idempotency_key
            ctx["execution_id"] = request.execution_id
            ctx["issue_number"] = request.issue_number

            if request.operation not in (PUSH, OPEN_PR):
                raise PolicyError(f"operation not permitted: {request.operation!r}")
            ctx["operation"] = request.operation

            ev1 = evidence_mod.validate(request.evidence)
            _bind_request_to_evidence(request, ev1)
            ctx["evidence_hashes"] = _evidence_hashes(ev1)
            target = policy_mod.derive(ev1, request.operation)
            ctx["derived"] = _derived_dict(target)
            fingerprint = canonical.canonical_sha256(
                [request.operation, ctx["derived"], ctx["evidence_hashes"]]
            )

            decision = self._idempotency.begin(request.idempotency_key, fingerprint)
            if decision == idem.CONFLICT:
                raise ConflictError("idempotency key reused with a different request")
            if decision == idem.PENDING:
                # Concurrent/incomplete reservation with the same request: deny
                # deterministically, never re-invoke, never KeyError.
                raise ConflictError("idempotency key has a concurrent in-flight reservation")
            if decision == idem.REPLAY:
                terminal = self._idempotency.recorded_outcome(request.idempotency_key)
                return self._respond(
                    terminal["result"], ctx, request_sha256, terminal["outcome"], replayed=True
                )

            # decision == MISS_RESERVED
            # Pre-call phase: any failure here executed nothing -> release the key.
            try:
                if _between_validations is not None:  # test-only seam
                    _between_validations()
                ev2 = evidence_mod.validate(request.evidence)  # fresh re-parse from canonical bytes
                _bind_request_to_evidence(request, ev2)
                target2 = policy_mod.derive(ev2, request.operation)
                repo_mod.validate_fresh_state(self._repository_inspector, ev2, target2)
            except BaseException:
                self._idempotency.abort(request.idempotency_key)
                raise

            # Call phase: from here the key becomes terminal regardless of outcome.
            terminal = self._invoke(request.operation, target2)
            self._idempotency.complete(request.idempotency_key, terminal)
            return self._respond(
                terminal["result"], ctx, request_sha256, terminal["outcome"], replayed=False
            )

        except PolicyError as exc:
            return self._deny("DENIED_POLICY", ctx, request_sha256, exc)
        except EvidenceError as exc:
            return self._deny("DENIED_EVIDENCE", ctx, request_sha256, exc)
        except ConflictError as exc:
            return self._deny("CONFLICT_IDEMPOTENT", ctx, request_sha256, exc)
        except AuthUnavailable as exc:
            return self._deny("AUTH_UNAVAILABLE", ctx, request_sha256, exc)
        except RemoteFailure as exc:
            return self._deny("REMOTE_FAILURE", ctx, request_sha256, exc)
        except Exception as exc:  # noqa: BLE001 — central fail-closed boundary
            return self._deny("INTERNAL_ERROR", ctx, request_sha256, exc)

    def _invoke(self, operation, target) -> dict:
        """Invoke the fake client. Any outcome — success or a client-produced
        failure — is a terminal recorded result carrying its result class."""
        try:
            if operation == PUSH:
                result = self._fake_client.publish_task_branch(target)
            else:
                result = self._fake_client.create_draft_pr(target)
            return {"result": "SUCCESS", "outcome": _outcome_dict(result)}
        except (RemoteFailure, AuthUnavailable) as exc:
            return {"result": exc.code, "outcome": {"reason": audit_mod.sanitize(str(getattr(exc, "message", exc)))}}
        except Exception as exc:  # noqa: BLE001
            return {"result": "INTERNAL_ERROR", "outcome": {"reason": audit_mod.sanitize(str(exc))}}

    def _respond(self, result, ctx, request_sha256, outcome, *, replayed) -> dict:
        event = audit_mod.AuditEvent(
            request_sha256=request_sha256,
            execution_id=ctx["execution_id"],
            issue_number=ctx["issue_number"],
            operation=ctx["operation"],
            idempotency_key=ctx["idempotency_key"],
            evidence_hashes=ctx["evidence_hashes"],
            decision=result,
            derived=ctx["derived"],
            outcome=outcome,
        )
        try:
            record = self._audit_sink.append(event)  # attempted exactly once
            if not isinstance(record, audit_mod.AuditRecord):
                # A sink that returns None/non-record instead of raising must not
                # let `record.audit_id` blow up outside this guard.
                raise TypeError("audit sink did not return an AuditRecord")
            final_result, final_outcome = result, outcome
        except Exception:  # noqa: BLE001 — non-recursive emergency path
            record = self._emergency_audit(ctx, request_sha256)
            final_result, final_outcome = "INTERNAL_ERROR", {"reason": "audit_sink_failure"}
        return {
            "schema": RESPONSE_SCHEMA,
            "result": final_result,
            "operation": ctx["operation"],
            "idempotency_key": ctx["idempotency_key"],
            "replayed": replayed,
            "audit_id": record.audit_id,
            "outcome": final_outcome,
        }

    def _emergency_audit(self, ctx, request_sha256):
        return self._emergency_sink.append(
            audit_mod.AuditEvent(
                request_sha256=request_sha256,
                execution_id=ctx["execution_id"],
                issue_number=ctx["issue_number"],
                operation=ctx["operation"],
                idempotency_key=ctx["idempotency_key"],
                evidence_hashes=ctx["evidence_hashes"],
                decision="INTERNAL_ERROR",
                derived=ctx["derived"],
                outcome={"reason": "audit_sink_failure"},
            )
        )

    def _deny(self, result, ctx, request_sha256, exc) -> dict:
        outcome = {"reason": audit_mod.sanitize(str(getattr(exc, "message", exc)))}
        return self._respond(result, ctx, request_sha256, outcome, replayed=False)
