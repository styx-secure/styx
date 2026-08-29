export const MODEL_LABELS = Object.freeze({
  ap_projection: "Authority projection",
  counterexample: "Counterexample",
  dependency: "Dependency",
  flow: "Protocol flow",
  history: "History",
  invariant: "Invariant witness",
  k_admission: "Kernel admission",
  pending_replay: "Pending replay",
  vector: "Transcript vector",
});

export function labelFromId(identifier = "") {
  return identifier
    .replace(/^scenario-(?:flow|counterexample|invariant|state|vector|dependency)-/, "")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function shortDigest(value, length = 12) {
  if (!value) return "—";
  const text = String(value);
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

export function filterScenarios(scenarios, { query = "", model = "all" } = {}) {
  const needle = query.trim().toLocaleLowerCase();
  return scenarios.filter((scenario) => {
    if (model !== "all" && scenario.modelId !== model) return false;
    if (!needle) return true;
    const searchable = [
      scenario.id,
      scenario.modelId,
      labelFromId(scenario.id),
      ...scenario.steps.flatMap(({ expected }) => [
        expected.actor,
        expected.candidateAction,
        expected.expectedOutcome,
        expected.inputVectorId,
      ]),
    ]
      .filter(Boolean)
      .join(" ")
      .toLocaleLowerCase();
    return searchable.includes(needle);
  });
}

export function filterMutations(mutations, query = "") {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return mutations;
  return mutations.filter((mutation) =>
    [
      mutation.id,
      mutation.mutationClass,
      mutation.transformation,
      mutation.violatedInvariant,
      mutation.detector,
      mutation.sourceRecordId,
    ]
      .filter(Boolean)
      .join(" ")
      .toLocaleLowerCase()
      .includes(needle),
  );
}

export function moveStep(current, direction, count) {
  if (!Number.isInteger(count) || count < 1) return 0;
  if (direction === "reset") return 0;
  const delta = direction === "previous" ? -1 : 1;
  return Math.max(0, Math.min(count - 1, current + delta));
}

export function outcomeTone(outcome = "") {
  const normalized = String(outcome).toUpperCase();
  if (normalized === "APPLIED" || normalized === "VALID" || normalized === "ADMITTED") {
    return "positive";
  }
  if (normalized.includes("PENDING") || normalized.includes("MISSING") || normalized.includes("STALE")) {
    return "pending";
  }
  if (
    normalized.includes("REJECT") ||
    normalized.includes("INVALID") ||
    normalized.includes("QUARANTINE") ||
    normalized.includes("UNAVAILABLE")
  ) {
    return "negative";
  }
  return "neutral";
}

export function sourceSummary(data) {
  return `${data.counts.scenarios} scenarios · ${data.counts.mutations} mutations · ${data.source.profile}`;
}
