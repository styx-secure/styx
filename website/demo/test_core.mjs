import assert from "node:assert/strict";
import test from "node:test";

import {
  filterMutations,
  filterScenarios,
  labelFromId,
  moveStep,
  outcomeTone,
  shortDigest,
  sourceSummary,
} from "./core.mjs";

const scenarios = [
  {
    id: "scenario-flow-author_application_event",
    modelId: "flow",
    steps: [{ expected: { actor: "authorized_endpoint", candidateAction: "Construct transcript", expectedOutcome: "APPLIED", inputVectorId: "vec-1" } }],
  },
  {
    id: "scenario-counterexample-ce_fork",
    modelId: "counterexample",
    steps: [{ expected: { actor: "kernel", candidateAction: "Quarantine fork", expectedOutcome: "FORK_QUARANTINED", inputVectorId: "vec-2" } }],
  },
];

test("scenario labels are derived without changing identifiers", () => {
  assert.equal(labelFromId(scenarios[0].id), "Author Application Event");
});

test("scenario filters combine category and content search", () => {
  assert.deepEqual(filterScenarios(scenarios, { model: "flow" }), [scenarios[0]]);
  assert.deepEqual(filterScenarios(scenarios, { query: "quarantine" }), [scenarios[1]]);
  assert.deepEqual(filterScenarios(scenarios, { query: "missing" }), []);
});

test("mutation filtering searches frozen evidence fields", () => {
  const mutations = [{ id: "m-1", detector: "SIGNATURE_FAILURE", violatedInvariant: "INV_AUTH" }];
  assert.deepEqual(filterMutations(mutations, "signature"), mutations);
  assert.deepEqual(filterMutations(mutations, "transport"), []);
});

test("step navigation stays in the available trace", () => {
  assert.equal(moveStep(0, "previous", 3), 0);
  assert.equal(moveStep(0, "next", 3), 1);
  assert.equal(moveStep(2, "next", 3), 2);
  assert.equal(moveStep(2, "reset", 3), 0);
  assert.equal(moveStep(4, "next", 0), 0);
});

test("digest and outcome presentation remain bounded", () => {
  assert.equal(shortDigest("1234567890abcdef", 8), "12345678…");
  assert.equal(shortDigest(null), "—");
  assert.equal(outcomeTone("APPLIED"), "positive");
  assert.equal(outcomeTone("OPENING_MISSING"), "pending");
  assert.equal(outcomeTone("STRUCTURAL_REJECTION"), "negative");
});

test("source summary states corpus scale and profile", () => {
  assert.equal(
    sourceSummary({ counts: { scenarios: 118, mutations: 501 }, source: { profile: "TRANSCRIPT_ONLY" } }),
    "118 scenarios · 501 mutations · TRANSCRIPT_ONLY",
  );
});
