import {
  MODEL_LABELS,
  filterMutations,
  filterScenarios,
  labelFromId,
  moveStep,
  outcomeTone,
  shortDigest,
  sourceSummary,
} from "./core.mjs";

const byId = (id) => document.getElementById(id);

const elements = {
  workspace: document.querySelector(".workspace"),
  sourceSummary: byId("source-summary"),
  scenarioSearch: byId("scenario-search"),
  modelFilter: byId("model-filter"),
  scenarioCount: byId("scenario-count"),
  scenarioList: byId("scenario-list"),
  scenarioFamily: byId("scenario-family"),
  scenarioTitle: byId("scenario-title"),
  scenarioId: byId("scenario-id"),
  scenarioSteps: byId("scenario-steps"),
  previousStep: byId("previous-step"),
  resetStep: byId("reset-step"),
  nextStep: byId("next-step"),
  stepTimeline: byId("step-timeline"),
  stepLive: byId("step-live"),
  stepAction: byId("step-action"),
  stepActor: byId("step-actor"),
  stepVector: byId("step-vector"),
  stepStage: byId("step-stage"),
  stepOutcome: byId("step-outcome"),
  stepRemote: byId("step-remote"),
  stepDependency: byId("step-dependency"),
  stepTranscript: byId("step-transcript"),
  stepSignature: byId("step-signature"),
  stepCommitment: byId("step-commitment"),
  stepAdmission: byId("step-admission"),
  stepAuthority: byId("step-authority"),
  stepEffects: byId("step-effects"),
  stepPreState: byId("step-pre-state"),
  stepPostState: byId("step-post-state"),
  stepRequires: byId("step-requires"),
  stepProduces: byId("step-produces"),
  vectorValidity: byId("vector-validity"),
  vectorKind: byId("vector-kind"),
  vectorRole: byId("vector-role"),
  vectorType: byId("vector-type"),
  vectorSequence: byId("vector-sequence"),
  vectorParents: byId("vector-parents"),
  vectorContent: byId("vector-content"),
  vectorOctets: byId("vector-octets"),
  vectorSuite: byId("vector-suite"),
  vectorMutation: byId("vector-mutation"),
  observationDigest: byId("observation-digest"),
  semanticDigest: byId("semantic-digest"),
  scenarioCitations: byId("scenario-citations"),
  mutationSearch: byId("mutation-search"),
  mutationCount: byId("mutation-count"),
  mutationList: byId("mutation-list"),
  mutationTitle: byId("mutation-title"),
  mutationClass: byId("mutation-class"),
  mutationTransformation: byId("mutation-transformation"),
  mutationInvariant: byId("mutation-invariant"),
  mutationDetector: byId("mutation-detector"),
  mutationStage: byId("mutation-stage"),
  mutationOutcome: byId("mutation-outcome"),
  mutationSource: byId("mutation-source"),
  nonClaims: byId("non-claims"),
};

const state = {
  data: null,
  scenario: null,
  step: 0,
  mutation: null,
};

function setText(element, value) {
  element.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
}

function setOutcome(element, value) {
  setText(element, value);
  element.dataset.tone = outcomeTone(value);
}

function makeButton(identity, label, metadata, onSelect, current) {
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.evidenceId = identity;
  button.setAttribute("aria-current", current ? "true" : "false");
  const strong = document.createElement("strong");
  strong.textContent = label;
  const span = document.createElement("span");
  span.textContent = metadata;
  button.append(strong, span);
  button.addEventListener("click", onSelect);
  return button;
}

function updateCurrentSelection(container, selectedId) {
  for (const button of container.querySelectorAll("button[data-evidence-id]")) {
    button.setAttribute("aria-current", button.dataset.evidenceId === selectedId ? "true" : "false");
  }
}

function renderScenarioList() {
  const scenarios = filterScenarios(state.data.scenarios, {
    query: elements.scenarioSearch.value,
    model: elements.modelFilter.value,
  });
  elements.scenarioCount.textContent = `${scenarios.length} of ${state.data.counts.scenarios} scenarios`;
  const items = scenarios.map((scenario) => {
    const item = document.createElement("li");
    item.append(
      makeButton(
        scenario.id,
        labelFromId(scenario.id),
        MODEL_LABELS[scenario.modelId] || scenario.modelId,
        () => selectScenario(scenario),
        state.scenario?.id === scenario.id,
      ),
    );
    return item;
  });
  elements.scenarioList.replaceChildren(...items);
}

function renderTimeline() {
  const items = state.scenario.steps.map((_, index) => {
    const item = document.createElement("li");
    item.className = index < state.step ? "complete" : index === state.step ? "current" : "";
    item.setAttribute("aria-label", `Step ${index + 1}${index === state.step ? ", current" : ""}`);
    return item;
  });
  elements.stepTimeline.replaceChildren(...items);
}

function renderCitations() {
  const items = state.scenario.citations.map((citation) => {
    const item = document.createElement("li");
    const source = citation.path || citation.source_id || "normative source";
    item.textContent = `${source} — ${citation.anchor}`;
    return item;
  });
  elements.scenarioCitations.replaceChildren(...items);
}

function renderStep() {
  const { expected, observed } = state.scenario.steps[state.step];
  const vector = state.data.vectors.find((candidate) => candidate.id === expected.inputVectorId);
  const total = state.scenario.steps.length;
  setText(elements.scenarioSteps, `Step ${state.step + 1} / ${total}`);
  setText(elements.stepAction, expected.candidateAction);
  setText(elements.stepActor, expected.actor);
  setText(elements.stepVector, expected.inputVectorId);
  setText(elements.stepStage, observed.stage);
  setOutcome(elements.stepOutcome, observed.localOutcome);
  setOutcome(elements.stepRemote, observed.remoteClass);
  setOutcome(elements.stepDependency, observed.dependencyStatus);
  setOutcome(elements.stepTranscript, observed.transcriptVerification);
  setOutcome(elements.stepSignature, observed.signatureVerification);
  setOutcome(elements.stepCommitment, observed.commitmentVerification);
  setOutcome(elements.stepAdmission, observed.kBindingAdmission);
  setOutcome(elements.stepAuthority, observed.apAuthorityResult);
  setText(elements.stepEffects, observed.externalEffects?.length ? observed.externalEffects.join(", ") : "None");
  setText(elements.stepPreState, shortDigest(observed.preStateDigest, 18));
  elements.stepPreState.title = observed.preStateDigest || "";
  setText(elements.stepPostState, shortDigest(observed.postStateDigest, 18));
  elements.stepPostState.title = observed.postStateDigest || "";
  setText(elements.stepRequires, expected.requiredPriorEvidence?.length ? expected.requiredPriorEvidence.join(", ") : "None");
  setText(elements.stepProduces, expected.providedEvidence);
  setOutcome(elements.vectorValidity, vector?.validity);
  setText(elements.vectorKind, vector?.kind);
  setText(elements.vectorRole, vector?.eventRole);
  setText(elements.vectorType, vector?.eventTypeId);
  setText(elements.vectorSequence, vector?.authorSequence);
  setText(elements.vectorParents, vector?.causalParentCount);
  setText(elements.vectorContent, vector?.contentClass);
  setText(elements.vectorOctets, vector ? `${vector.transcriptOctets} octets` : null);
  setText(elements.vectorSuite, vector?.signatureSuiteId);
  setText(elements.vectorMutation, vector?.mutation || "None");
  elements.previousStep.disabled = state.step === 0;
  elements.resetStep.disabled = state.step === 0;
  elements.nextStep.disabled = state.step === total - 1;
  elements.stepLive.textContent = `Showing step ${state.step + 1} of ${total}: ${expected.candidateAction}. Outcome ${observed.localOutcome}.`;
  renderTimeline();
}

function selectScenario(scenario) {
  state.scenario = scenario;
  state.step = 0;
  elements.scenarioFamily.textContent = MODEL_LABELS[scenario.modelId] || scenario.modelId;
  elements.scenarioTitle.textContent = labelFromId(scenario.id);
  elements.scenarioId.textContent = scenario.id;
  setText(elements.observationDigest, scenario.observationDigest);
  setText(elements.semanticDigest, scenario.semanticObservationDigest);
  renderCitations();
  renderStep();
  updateCurrentSelection(elements.scenarioList, scenario.id);
}

function navigate(direction) {
  if (!state.scenario) return;
  state.step = moveStep(state.step, direction, state.scenario.steps.length);
  renderStep();
}

function renderMutationList() {
  const mutations = filterMutations(state.data.mutations, elements.mutationSearch.value);
  elements.mutationCount.textContent = `${mutations.length} of ${state.data.counts.mutations} mutations`;
  const visible = mutations.slice(0, 100);
  const items = visible.map((mutation) => {
    const item = document.createElement("li");
    item.append(
      makeButton(
        mutation.id,
        mutation.id,
        `${mutation.mutationClass} · ${mutation.violatedInvariant}`,
        () => selectMutation(mutation),
        state.mutation?.id === mutation.id,
      ),
    );
    return item;
  });
  if (mutations.length > visible.length) {
    const notice = document.createElement("li");
    notice.className = "result-count";
    notice.textContent = `Showing the first ${visible.length}; refine the search to inspect another entry.`;
    items.push(notice);
  }
  elements.mutationList.replaceChildren(...items);
}

function selectMutation(mutation) {
  state.mutation = mutation;
  setText(elements.mutationTitle, mutation.id);
  setText(elements.mutationClass, mutation.mutationClass);
  setText(elements.mutationTransformation, mutation.transformation);
  setText(elements.mutationInvariant, mutation.violatedInvariant);
  setText(elements.mutationDetector, mutation.detector);
  setText(elements.mutationStage, mutation.expectedStage);
  setText(elements.mutationOutcome, mutation.expectedOutcome);
  setText(elements.mutationSource, mutation.sourceRecordId);
  updateCurrentSelection(elements.mutationList, mutation.id);
}

function populateModelFilter() {
  const models = [...new Set(state.data.scenarios.map((scenario) => scenario.modelId))].sort();
  const options = models.map((model) => {
    const option = document.createElement("option");
    option.value = model;
    option.textContent = MODEL_LABELS[model] || model;
    return option;
  });
  elements.modelFilter.append(...options);
}

function renderNonClaims() {
  const items = state.data.nonClaims.map((claim) => {
    const item = document.createElement("li");
    item.textContent = claim.replaceAll("_", " ");
    return item;
  });
  elements.nonClaims.replaceChildren(...items);
}

async function loadEvidence() {
  try {
    const response = await fetch("./data/c03-evidence.json", { cache: "no-store", credentials: "same-origin" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (
      data.schema !== "styx-c03-evidence-explorer/v1" ||
      data.source.synthetic !== true ||
      data.authority.c03Verdict !== "NO_GO" ||
      data.counts.scenarios !== 118 ||
      data.counts.mutations !== 501
    ) {
      throw new Error("projection identity mismatch");
    }
    state.data = data;
    elements.workspace.dataset.enhanced = "true";
    elements.scenarioSearch.disabled = false;
    elements.modelFilter.disabled = false;
    elements.mutationSearch.disabled = false;
    elements.sourceSummary.textContent = `${sourceSummary(data)} · manifest ${shortDigest(data.source.manifestSha256, 16)}`;
    populateModelFilter();
    renderNonClaims();
    renderScenarioList();
    selectScenario(data.scenarios[0]);
    renderMutationList();
    selectMutation(data.mutations[0]);
  } catch (error) {
    elements.sourceSummary.textContent = `Evidence projection unavailable: ${error.message}. No result is inferred.`;
    elements.scenarioCount.textContent = "Fail-closed: no scenario loaded.";
    elements.mutationCount.textContent = "Fail-closed: no mutation loaded.";
  }
}

elements.scenarioSearch.addEventListener("input", renderScenarioList);
elements.modelFilter.addEventListener("change", renderScenarioList);
elements.mutationSearch.addEventListener("input", renderMutationList);
elements.previousStep.addEventListener("click", () => navigate("previous"));
elements.resetStep.addEventListener("click", () => navigate("reset"));
elements.nextStep.addEventListener("click", () => navigate("next"));

loadEvidence();
