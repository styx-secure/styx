// Pure data-only M2 adapter decision core. No imports or effects.

const TABLES = {"states":["EMPTY","ACTIVE","RECONCILIATION_REQUIRED"],"operations":["CREATE","RESTORE","JOIN_WELCOME","PROTECT_APPLICATION","OPEN_APPLICATION","SELF_UPDATE","APPLY_PEER_UPDATE","RECONCILE_INDETERMINATE"],"stateRows":{"EMPTY|CREATE":{"scenario":"CAPI-G001","disposition":"ALLOW","resultKind":null,"stateAfter":"EMPTY","persistence":"OPERATION_ROW"},"EMPTY|RESTORE":{"scenario":"CAPI-G002","disposition":"ALLOW","resultKind":null,"stateAfter":"EMPTY","persistence":"OPERATION_ROW"},"EMPTY|JOIN_WELCOME":{"scenario":"CAPI-G003","disposition":"ALLOW","resultKind":null,"stateAfter":"EMPTY","persistence":"OPERATION_ROW"},"EMPTY|PROTECT_APPLICATION":{"scenario":"CAPI-G004","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY","persistence":"NONE"},"EMPTY|OPEN_APPLICATION":{"scenario":"CAPI-G005","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY","persistence":"NONE"},"EMPTY|SELF_UPDATE":{"scenario":"CAPI-G006","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY","persistence":"NONE"},"EMPTY|APPLY_PEER_UPDATE":{"scenario":"CAPI-G007","disposition":"NO_ACTIVE_SESSION","resultKind":"REJECTED","stateAfter":"EMPTY","persistence":"NONE"},"EMPTY|RECONCILE_INDETERMINATE":{"scenario":"CAPI-G008","disposition":"NO_RECONCILIATION_PENDING","resultKind":"REJECTED","stateAfter":"EMPTY","persistence":"NONE"},"ACTIVE|CREATE":{"scenario":"CAPI-G009","disposition":"SESSION_ALREADY_EXISTS","resultKind":"REJECTED","stateAfter":"ACTIVE","persistence":"NONE"},"ACTIVE|RESTORE":{"scenario":"CAPI-G010","disposition":"SESSION_ALREADY_EXISTS","resultKind":"REJECTED","stateAfter":"ACTIVE","persistence":"NONE"},"ACTIVE|JOIN_WELCOME":{"scenario":"CAPI-G011","disposition":"SESSION_ALREADY_EXISTS","resultKind":"REJECTED","stateAfter":"ACTIVE","persistence":"NONE"},"ACTIVE|PROTECT_APPLICATION":{"scenario":"CAPI-G012","disposition":"ALLOW","resultKind":null,"stateAfter":"ACTIVE","persistence":"OPERATION_ROW"},"ACTIVE|OPEN_APPLICATION":{"scenario":"CAPI-G013","disposition":"ALLOW","resultKind":null,"stateAfter":"ACTIVE","persistence":"OPERATION_ROW"},"ACTIVE|SELF_UPDATE":{"scenario":"CAPI-G014","disposition":"ALLOW","resultKind":null,"stateAfter":"ACTIVE","persistence":"OPERATION_ROW"},"ACTIVE|APPLY_PEER_UPDATE":{"scenario":"CAPI-G015","disposition":"ALLOW","resultKind":null,"stateAfter":"ACTIVE","persistence":"OPERATION_ROW"},"ACTIVE|RECONCILE_INDETERMINATE":{"scenario":"CAPI-G016","disposition":"NO_RECONCILIATION_PENDING","resultKind":"REJECTED","stateAfter":"ACTIVE","persistence":"NONE"},"RECONCILIATION_REQUIRED|CREATE":{"scenario":"CAPI-G017","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED","persistence":"NONE"},"RECONCILIATION_REQUIRED|RESTORE":{"scenario":"CAPI-G018","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED","persistence":"NONE"},"RECONCILIATION_REQUIRED|JOIN_WELCOME":{"scenario":"CAPI-G019","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED","persistence":"NONE"},"RECONCILIATION_REQUIRED|PROTECT_APPLICATION":{"scenario":"CAPI-G020","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED","persistence":"NONE"},"RECONCILIATION_REQUIRED|OPEN_APPLICATION":{"scenario":"CAPI-G021","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED","persistence":"NONE"},"RECONCILIATION_REQUIRED|SELF_UPDATE":{"scenario":"CAPI-G022","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED","persistence":"NONE"},"RECONCILIATION_REQUIRED|APPLY_PEER_UPDATE":{"scenario":"CAPI-G023","disposition":"RECONCILIATION_REQUIRED","resultKind":"REJECTED","stateAfter":"RECONCILIATION_REQUIRED","persistence":"NONE"},"RECONCILIATION_REQUIRED|RECONCILE_INDETERMINATE":{"scenario":"CAPI-G024","disposition":"ALLOW","resultKind":null,"stateAfter":"RECONCILIATION_REQUIRED","persistence":"OPERATION_ROW"}},"errorRows":{"UNKNOWN_FIELD":{"scenario":"CAPI-E001","errorCode":"UNKNOWN_FIELD","precedenceLevel":"P01"},"INVALID_REQUEST":{"scenario":"CAPI-E002","errorCode":"INVALID_REQUEST","precedenceLevel":"P01"},"UNKNOWN_VALUE":{"scenario":"CAPI-E003","errorCode":"UNKNOWN_VALUE","precedenceLevel":"P01"},"UNSUPPORTED_API_VERSION":{"scenario":"CAPI-E004","errorCode":"UNSUPPORTED_API_VERSION","precedenceLevel":"P02"},"UNSUPPORTED_PROFILE":{"scenario":"CAPI-E005","errorCode":"UNSUPPORTED_PROFILE","precedenceLevel":"P03"},"BINDING_MISMATCH":{"scenario":"CAPI-E006","errorCode":"BINDING_MISMATCH","precedenceLevel":"P03"},"UNSUPPORTED_OPERATION":{"scenario":"CAPI-E007","errorCode":"UNSUPPORTED_OPERATION","precedenceLevel":"P04"},"SESSION_ALREADY_EXISTS":{"scenario":"CAPI-E008","errorCode":"SESSION_ALREADY_EXISTS","precedenceLevel":"P05"},"NO_ACTIVE_SESSION":{"scenario":"CAPI-E009","errorCode":"NO_ACTIVE_SESSION","precedenceLevel":"P05"},"NO_STORED_SESSION":{"scenario":"CAPI-E010","errorCode":"NO_STORED_SESSION","precedenceLevel":"P05"},"RECONCILIATION_REQUIRED":{"scenario":"CAPI-E011","errorCode":"RECONCILIATION_REQUIRED","precedenceLevel":"P05"},"NO_RECONCILIATION_PENDING":{"scenario":"CAPI-E012","errorCode":"NO_RECONCILIATION_PENDING","precedenceLevel":"P05"},"RECONCILIATION_REFERENCE_MISMATCH":{"scenario":"CAPI-E013","errorCode":"RECONCILIATION_REFERENCE_MISMATCH","precedenceLevel":"P05"},"VALUE_OUT_OF_RANGE":{"scenario":"CAPI-E014","errorCode":"VALUE_OUT_OF_RANGE","precedenceLevel":"P06"},"EPOCH_OUTSIDE_RETAINED_WINDOW":{"scenario":"CAPI-E015","errorCode":"EPOCH_OUTSIDE_RETAINED_WINDOW","precedenceLevel":"P07"},"FUTURE_EPOCH":{"scenario":"CAPI-E016","errorCode":"FUTURE_EPOCH","precedenceLevel":"P07"},"AUTHENTICATION_FAILED":{"scenario":"CAPI-E017","errorCode":"AUTHENTICATION_FAILED","precedenceLevel":"P08"},"AUTHENTICATED_STATE_INCONSISTENT":{"scenario":"CAPI-E018","errorCode":"AUTHENTICATED_STATE_INCONSISTENT","precedenceLevel":"P08"},"UNSUPPORTED_ONBOARDING":{"scenario":"CAPI-E019","errorCode":"UNSUPPORTED_ONBOARDING","precedenceLevel":"P09"},"STORED_SESSION_INCOMPATIBLE":{"scenario":"CAPI-E020","errorCode":"STORED_SESSION_INCOMPATIBLE","precedenceLevel":"P09"},"WELCOME_NO_MATCHING_KEY_PACKAGE":{"scenario":"CAPI-E021","errorCode":"WELCOME_NO_MATCHING_KEY_PACKAGE","precedenceLevel":"P09"},"UNSUPPORTED_UPDATE_FORM":{"scenario":"CAPI-E022","errorCode":"UNSUPPORTED_UPDATE_FORM","precedenceLevel":"P09"},"UNSUPPORTED_COMMIT_SHAPE":{"scenario":"CAPI-E023","errorCode":"UNSUPPORTED_COMMIT_SHAPE","precedenceLevel":"P09"},"KEY_PACKAGE_ALREADY_CONSUMED":{"scenario":"CAPI-E024","errorCode":"KEY_PACKAGE_ALREADY_CONSUMED","precedenceLevel":"P09"},"FAIL_CLOSED_INTERNAL":{"scenario":"CAPI-E025","errorCode":"FAIL_CLOSED_INTERNAL","precedenceLevel":"P10"}},"decisionRows":{"CAPI-S001":{"scenario":"CAPI-S001","operation":"CREATE","stateBefore":"EMPTY","precedenceLevel":"P10","persistence":"RS_TRI_STATE","stateAfter":"ACTIVE","code":"CREATED","kind":"SUCCESS"},"CAPI-S002":{"scenario":"CAPI-S002","operation":"CREATE","stateBefore":"EMPTY","precedenceLevel":"P09","persistence":"NONE","stateAfter":"EMPTY","code":"UNSUPPORTED_ONBOARDING","kind":"REJECTED"},"CAPI-S003":{"scenario":"CAPI-S003","operation":"RESTORE","stateBefore":"EMPTY","precedenceLevel":"P10","persistence":"NONE","stateAfter":"ACTIVE","code":"RESTORED","kind":"SUCCESS"},"CAPI-S004":{"scenario":"CAPI-S004","operation":"RESTORE","stateBefore":"EMPTY","precedenceLevel":"P08","persistence":"NONE","stateAfter":"EMPTY","code":"AUTHENTICATED_STATE_INCONSISTENT","kind":"REJECTED"},"CAPI-S005":{"scenario":"CAPI-S005","operation":"RESTORE","stateBefore":"EMPTY","precedenceLevel":"P08","persistence":"NONE","stateAfter":"EMPTY","code":"AUTHENTICATION_FAILED","kind":"REJECTED"},"CAPI-S006":{"scenario":"CAPI-S006","operation":"JOIN_WELCOME","stateBefore":"EMPTY","precedenceLevel":"P10","persistence":"RS_TRI_STATE","stateAfter":"ACTIVE","code":"JOINED","kind":"SUCCESS"},"CAPI-S007":{"scenario":"CAPI-S007","operation":"JOIN_WELCOME","stateBefore":"EMPTY","precedenceLevel":"P09","persistence":"NONE","stateAfter":"EMPTY","code":"KEY_PACKAGE_ALREADY_CONSUMED","kind":"REJECTED"},"CAPI-S008":{"scenario":"CAPI-S008","operation":"JOIN_WELCOME","stateBefore":"EMPTY","precedenceLevel":"P09","persistence":"NONE","stateAfter":"EMPTY","code":"UNSUPPORTED_ONBOARDING","kind":"REJECTED"},"CAPI-S009":{"scenario":"CAPI-S009","operation":"PROTECT_APPLICATION","stateBefore":"ACTIVE","precedenceLevel":"P10","persistence":"RS_TRI_STATE","stateAfter":"ACTIVE","code":"APPLICATION_PROTECTED","kind":"SUCCESS"},"CAPI-S010":{"scenario":"CAPI-S010","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","precedenceLevel":"P10","persistence":"RS_TRI_STATE","stateAfter":"ACTIVE","code":"APPLICATION_OPENED","kind":"SUCCESS"},"CAPI-S011":{"scenario":"CAPI-S011","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","precedenceLevel":"P10","persistence":"NONE","stateAfter":"ACTIVE","code":"DUPLICATE_IGNORED","kind":"NO_CHANGE"},"CAPI-S012":{"scenario":"CAPI-S012","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","precedenceLevel":"P07","persistence":"NONE","stateAfter":"ACTIVE","code":"EPOCH_OUTSIDE_RETAINED_WINDOW","kind":"REJECTED"},"CAPI-S013":{"scenario":"CAPI-S013","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","precedenceLevel":"P07","persistence":"NONE","stateAfter":"ACTIVE","code":"FUTURE_EPOCH","kind":"REJECTED"},"CAPI-S014":{"scenario":"CAPI-S014","operation":"SELF_UPDATE","stateBefore":"ACTIVE","precedenceLevel":"P10","persistence":"RS_TRI_STATE","stateAfter":"ACTIVE","code":"SELF_UPDATED","kind":"SUCCESS"},"CAPI-S015":{"scenario":"CAPI-S015","operation":"SELF_UPDATE","stateBefore":"ACTIVE","precedenceLevel":"P09","persistence":"NONE","stateAfter":"ACTIVE","code":"UNSUPPORTED_UPDATE_FORM","kind":"REJECTED"},"CAPI-S016":{"scenario":"CAPI-S016","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","precedenceLevel":"P10","persistence":"RS_TRI_STATE","stateAfter":"ACTIVE","code":"PEER_UPDATE_APPLIED","kind":"SUCCESS"},"CAPI-S017":{"scenario":"CAPI-S017","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","precedenceLevel":"P10","persistence":"RS_TRI_STATE","stateAfter":"ACTIVE","code":"CANDIDATE_SELECTED","kind":"SUCCESS"},"CAPI-S018":{"scenario":"CAPI-S018","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","precedenceLevel":"P09","persistence":"NONE","stateAfter":"ACTIVE","code":"UNSUPPORTED_UPDATE_FORM","kind":"REJECTED"},"CAPI-S019":{"scenario":"CAPI-S019","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","precedenceLevel":"P09","persistence":"NONE","stateAfter":"ACTIVE","code":"UNSUPPORTED_COMMIT_SHAPE","kind":"REJECTED"},"CAPI-S020":{"scenario":"CAPI-S020","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","precedenceLevel":"P10","persistence":"NONE","stateAfter":"ACTIVE","code":"RECONCILED_COMMITTED","kind":"SUCCESS"},"CAPI-S021":{"scenario":"CAPI-S021","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","precedenceLevel":"P10","persistence":"NONE","stateAfter":"EMPTY","code":"NOT_COMMITTED","kind":"NOT_COMMITTED"},"CAPI-S022":{"scenario":"CAPI-S022","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","precedenceLevel":"P10","persistence":"NONE","stateAfter":"ACTIVE","code":"RECONCILED_COMMITTED","kind":"SUCCESS"},"CAPI-S023":{"scenario":"CAPI-S023","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","precedenceLevel":"P10","persistence":"NONE","stateAfter":"ACTIVE","code":"NOT_COMMITTED","kind":"NOT_COMMITTED"},"CAPI-S024":{"scenario":"CAPI-S024","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","precedenceLevel":"P10","persistence":"NONE","stateAfter":"RECONCILIATION_REQUIRED","code":"INDETERMINATE","kind":"INDETERMINATE"},"CAPI-S025":{"scenario":"CAPI-S025","operation":"RESTORE","stateBefore":"EMPTY","precedenceLevel":"P05","persistence":"NONE","stateAfter":"EMPTY","code":"NO_STORED_SESSION","kind":"REJECTED"},"CAPI-S026":{"scenario":"CAPI-S026","operation":"RESTORE","stateBefore":"EMPTY","precedenceLevel":"P09","persistence":"NONE","stateAfter":"EMPTY","code":"STORED_SESSION_INCOMPATIBLE","kind":"REJECTED"},"CAPI-S027":{"scenario":"CAPI-S027","operation":"JOIN_WELCOME","stateBefore":"EMPTY","precedenceLevel":"P09","persistence":"NONE","stateAfter":"EMPTY","code":"WELCOME_NO_MATCHING_KEY_PACKAGE","kind":"REJECTED"},"CAPI-S028":{"scenario":"CAPI-S028","operation":"RECONCILE_INDETERMINATE","stateBefore":"RECONCILIATION_REQUIRED","precedenceLevel":"P05","persistence":"NONE","stateAfter":"RECONCILIATION_REQUIRED","code":"RECONCILIATION_REFERENCE_MISMATCH","kind":"REJECTED"},"CAPI-S029":{"scenario":"CAPI-S029","operation":"RESTORE","stateBefore":"EMPTY","precedenceLevel":"P08","persistence":"NONE","stateAfter":"EMPTY","code":"AUTHENTICATED_STATE_INCONSISTENT","kind":"REJECTED"}},"errorOrder":["UNKNOWN_FIELD","INVALID_REQUEST","UNKNOWN_VALUE","UNSUPPORTED_API_VERSION","UNSUPPORTED_PROFILE","BINDING_MISMATCH","UNSUPPORTED_OPERATION","RECONCILIATION_REQUIRED","SESSION_ALREADY_EXISTS","NO_ACTIVE_SESSION","NO_STORED_SESSION","NO_RECONCILIATION_PENDING","RECONCILIATION_REFERENCE_MISMATCH","VALUE_OUT_OF_RANGE","EPOCH_OUTSIDE_RETAINED_WINDOW","FUTURE_EPOCH","AUTHENTICATION_FAILED","AUTHENTICATED_STATE_INCONSISTENT","STORED_SESSION_INCOMPATIBLE","UNSUPPORTED_ONBOARDING","WELCOME_NO_MATCHING_KEY_PACKAGE","UNSUPPORTED_UPDATE_FORM","UNSUPPORTED_COMMIT_SHAPE","KEY_PACKAGE_ALREADY_CONSUMED","FAIL_CLOSED_INTERNAL"],"mutationPlans":{"CAPI-S001":{"scenario":"CAPI-S001","operation":"CREATE","stateBefore":"EMPTY","stateAfterCommitted":"ACTIVE","successCode":"CREATED","outputKind":"EMBEDDED_TREE_WELCOME","selectionEffect":"NOT_APPLICABLE","retainedParentEffect":"NOT_APPLICABLE","components":[{"id":"SESSION_TRANSITION","disposition":"CHANGED","fact":"FOUNDER_STATE"},{"id":"BINDING_METADATA","disposition":"CHANGED","fact":"INITIAL_EXACT_BINDING_AND_PROFILE"},{"id":"REPLAY_RETENTION_STATE","disposition":"CHANGED","fact":"INITIAL_BASELINE"},{"id":"AUTHENTICATED_MANIFEST_UPDATE","disposition":"CHANGED","fact":"FOUNDER_MANIFEST"},{"id":"COMMIT_RESULT_EVIDENCE","disposition":"CREATED","fact":"BOUND_TO_OPERATION_IDENTITY"},{"id":"OUTPUT_ESCROW","disposition":"HELD","fact":"EMBEDDED_TREE_WELCOME"}]},"CAPI-S006":{"scenario":"CAPI-S006","operation":"JOIN_WELCOME","stateBefore":"EMPTY","stateAfterCommitted":"ACTIVE","successCode":"JOINED","outputKind":"NONE","selectionEffect":"NOT_APPLICABLE","retainedParentEffect":"NOT_APPLICABLE","components":[{"id":"SESSION_TRANSITION","disposition":"CHANGED","fact":"JOINED_STATE"},{"id":"BINDING_METADATA","disposition":"CHANGED","fact":"JOINED_EXACT_BINDING_AND_PROFILE"},{"id":"REPLAY_RETENTION_STATE","disposition":"CHANGED","fact":"JOINED_BASELINE"},{"id":"AUTHENTICATED_MANIFEST_UPDATE","disposition":"CHANGED","fact":"JOINED_MANIFEST"},{"id":"COMMIT_RESULT_EVIDENCE","disposition":"CREATED","fact":"BOUND_TO_OPERATION_IDENTITY"},{"id":"KEY_PACKAGE_CONSUMPTION","disposition":"CONSUMED","fact":"MATCHING_LOCAL_ONE_SHOT_REFERENCE"}]},"CAPI-S009":{"scenario":"CAPI-S009","operation":"PROTECT_APPLICATION","stateBefore":"ACTIVE","stateAfterCommitted":"ACTIVE","successCode":"APPLICATION_PROTECTED","outputKind":"PROTECTED_APPLICATION_BYTES","selectionEffect":"PRESERVE","retainedParentEffect":"PRESERVE","components":[{"id":"SESSION_TRANSITION","disposition":"CHANGED","fact":"SENDER_RATCHET_ADVANCEMENT"},{"id":"BINDING_METADATA","disposition":"UNCHANGED","fact":"EXACT_BINDING_AND_PROFILE"},{"id":"REPLAY_RETENTION_STATE","disposition":"CHANGED","fact":"SENDER_RATCHET_RETENTION"},{"id":"AUTHENTICATED_MANIFEST_UPDATE","disposition":"CHANGED","fact":"RATCHET_STATE_MANIFEST"},{"id":"COMMIT_RESULT_EVIDENCE","disposition":"CREATED","fact":"BOUND_TO_OPERATION_IDENTITY"},{"id":"OUTPUT_ESCROW","disposition":"HELD","fact":"PROTECTED_APPLICATION_BYTES"},{"id":"SELECTION_METADATA","disposition":"UNCHANGED","fact":"EPOCH_PRESERVING_ELIGIBILITY"},{"id":"RETAINED_PARENT_REFERENCE","disposition":"UNCHANGED","fact":"PRESERVED_IF_PRESENT"}]},"CAPI-S010":{"scenario":"CAPI-S010","operation":"OPEN_APPLICATION","stateBefore":"ACTIVE","stateAfterCommitted":"ACTIVE","successCode":"APPLICATION_OPENED","outputKind":"APPLICATION_BYTES","selectionEffect":"PRESERVE","retainedParentEffect":"PRESERVE","components":[{"id":"SESSION_TRANSITION","disposition":"CHANGED","fact":"RECEIVER_RATCHET_ADVANCEMENT"},{"id":"BINDING_METADATA","disposition":"UNCHANGED","fact":"EXACT_BINDING_AND_PROFILE"},{"id":"REPLAY_RETENTION_STATE","disposition":"CHANGED","fact":"REPLAY_ACCEPTANCE_AND_RECEIVER_RETENTION"},{"id":"AUTHENTICATED_MANIFEST_UPDATE","disposition":"CHANGED","fact":"RATCHET_AND_REPLAY_MANIFEST"},{"id":"COMMIT_RESULT_EVIDENCE","disposition":"CREATED","fact":"BOUND_TO_OPERATION_IDENTITY"},{"id":"OUTPUT_ESCROW","disposition":"HELD","fact":"APPLICATION_BYTES"},{"id":"SELECTION_METADATA","disposition":"UNCHANGED","fact":"EPOCH_PRESERVING_ELIGIBILITY"},{"id":"RETAINED_PARENT_REFERENCE","disposition":"UNCHANGED","fact":"PRESERVED_IF_PRESENT"}]},"CAPI-S014":{"scenario":"CAPI-S014","operation":"SELF_UPDATE","stateBefore":"ACTIVE","stateAfterCommitted":"ACTIVE","successCode":"SELF_UPDATED","outputKind":"PROTECTED_COMMIT_BYTES","selectionEffect":"ESTABLISH","retainedParentEffect":"ESTABLISH_FOR_CAPI_S017_ONLY","components":[{"id":"SESSION_TRANSITION","disposition":"CHANGED","fact":"LOCAL_UPDATE_STATE"},{"id":"BINDING_METADATA","disposition":"UNCHANGED","fact":"EXACT_BINDING_AND_PROFILE"},{"id":"REPLAY_RETENTION_STATE","disposition":"CHANGED","fact":"EPOCH_WINDOW_ADVANCEMENT"},{"id":"AUTHENTICATED_MANIFEST_UPDATE","disposition":"CHANGED","fact":"LOCAL_UPDATE_MANIFEST"},{"id":"COMMIT_RESULT_EVIDENCE","disposition":"CREATED","fact":"BOUND_TO_OPERATION_IDENTITY"},{"id":"OUTPUT_ESCROW","disposition":"HELD","fact":"PROTECTED_COMMIT_BYTES"},{"id":"SELECTION_METADATA","disposition":"ESTABLISHED","fact":"IMMEDIATELY_PRECEDING_LOCAL_UPDATE_ELIGIBILITY"},{"id":"RETAINED_PARENT_REFERENCE","disposition":"ESTABLISHED","fact":"PARENT_REQUIRED_BY_CAPI_S017"}]},"CAPI-S016":{"scenario":"CAPI-S016","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","stateAfterCommitted":"ACTIVE","successCode":"PEER_UPDATE_APPLIED","outputKind":"NONE","selectionEffect":"INVALIDATE","retainedParentEffect":"INVALIDATE_SELECTION_ROLE","components":[{"id":"SESSION_TRANSITION","disposition":"CHANGED","fact":"PEER_UPDATE_STATE"},{"id":"BINDING_METADATA","disposition":"UNCHANGED","fact":"EXACT_BINDING_AND_PROFILE"},{"id":"REPLAY_RETENTION_STATE","disposition":"CHANGED","fact":"EPOCH_WINDOW_ADVANCEMENT"},{"id":"AUTHENTICATED_MANIFEST_UPDATE","disposition":"CHANGED","fact":"PEER_UPDATE_MANIFEST"},{"id":"COMMIT_RESULT_EVIDENCE","disposition":"CREATED","fact":"BOUND_TO_OPERATION_IDENTITY"},{"id":"SELECTION_METADATA","disposition":"INVALIDATED","fact":"ANY_CAPI_S014_ELIGIBILITY"},{"id":"RETAINED_PARENT_REFERENCE","disposition":"INVALIDATED","fact":"NO_LONGER_SELECTION_AUTHORIZING"},{"id":"LOSING_CANDIDATE_EVIDENCE","disposition":"INVALIDATED","fact":"ANY_RETAINED_LOSER_EVIDENCE"}]},"CAPI-S017":{"scenario":"CAPI-S017","operation":"APPLY_PEER_UPDATE","stateBefore":"ACTIVE","stateAfterCommitted":"ACTIVE","successCode":"CANDIDATE_SELECTED","outputKind":"SELECTED_CANDIDATE_REF","selectionEffect":"TERMINATE","retainedParentEffect":"TERMINATE_SELECTION_ROLE","components":[{"id":"SESSION_TRANSITION","disposition":"CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE","fact":"CURRENT_WINNER_UNCHANGED_INCOMING_WINNER_CHANGED"},{"id":"BINDING_METADATA","disposition":"UNCHANGED","fact":"EXACT_BINDING_AND_PROFILE"},{"id":"REPLAY_RETENTION_STATE","disposition":"CHANGED","fact":"SELECTED_EPOCH_WINDOW"},{"id":"AUTHENTICATED_MANIFEST_UPDATE","disposition":"CHANGED","fact":"SELECTED_STATE_MANIFEST"},{"id":"COMMIT_RESULT_EVIDENCE","disposition":"CREATED","fact":"BOUND_TO_OPERATION_IDENTITY"},{"id":"OUTPUT_ESCROW","disposition":"HELD","fact":"SELECTED_CANDIDATE_REF"},{"id":"SELECTION_METADATA","disposition":"TERMINATED","fact":"NO_FURTHER_SELECTION_FROM_OLD_PARENT"},{"id":"RETAINED_PARENT_REFERENCE","disposition":"TERMINATED","fact":"NO_LONGER_SELECTION_AUTHORIZING"},{"id":"LOSING_CANDIDATE_EVIDENCE","disposition":"RETAINED_NON_AUTHORITATIVE","fact":"BOUNDED_VALID_LOSER"}]}}};

function freezeData(value) {
  if (value === null || typeof value !== 'object') return value;
  if (ArrayBuffer.isView(value)) return value;
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (Object.hasOwn(descriptor, 'value')) freezeData(descriptor.value);
  }
  return Object.freeze(value);
}

function cloneData(value) {
  if (value === null || typeof value !== 'object') return value;
  if (isUint8Array(value)) return new Uint8Array(value);
  if (Array.isArray(value)) return value.map(cloneData);
  const output = {};
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (Object.hasOwn(descriptor, 'value')) output[key] = cloneData(descriptor.value);
  }
  return output;
}

freezeData(TABLES);

export const STATES = TABLES.states;
export const OPERATIONS = TABLES.operations;
export const MUTATION_PLANS = TABLES.mutationPlans;

const ERROR_RANK = new Map(TABLES.errorOrder.map((code, index) => [code, index]));
const KNOWN_ERRORS = new Set(Object.keys(TABLES.errorRows));
const KNOWN_OPERATIONS = new Set(OPERATIONS);
const NORMAL_STATES = new Set(['EMPTY', 'ACTIVE']);
const MUTATION_SCENARIOS = new Set(Object.keys(MUTATION_PLANS));
const HOLD_KEYS = ['originalStateBefore', 'scenario', 'mutationPlanIdentity', 'operationIdentity', 'expectedSuccessCode', 'expectedStateAfter', 'outputKind', 'reconciliationRef', 'selectedCandidateRef', 'terminalEvidenceStatus'];
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag).get;
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteLength').get;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value)) return false;
  try {
    return Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

function closedObject(value, allowed, required = allowed) {
  if (!isPlainObject(value)) return { error: 'INVALID_REQUEST', values: null };
  let keys;
  let descriptors;
  try {
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return { error: 'INVALID_REQUEST', values: null };
  }
  if (keys.some((key) => typeof key !== 'string')) return { error: 'UNKNOWN_FIELD', values: null };
  for (const key of keys) {
    if (!allowed.includes(key)) return { error: 'UNKNOWN_FIELD', values: null };
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return { error: 'INVALID_REQUEST', values: null };
  }
  for (const key of required) {
    if (!Object.hasOwn(descriptors, key)) return { error: 'INVALID_REQUEST', values: null };
  }
  const values = {};
  for (const key of keys) values[key] = descriptors[key].value;
  return { error: null, values };
}

function closedArray(value) {
  if (!Array.isArray(value)) return { error: 'INVALID_REQUEST', values: null };
  let keys;
  let descriptors;
  try {
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return { error: 'INVALID_REQUEST', values: null };
  }
  if (keys.some((key) => typeof key !== 'string')) return { error: 'UNKNOWN_FIELD', values: null };
  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, 'value')) return { error: 'INVALID_REQUEST', values: null };
  const length = lengthDescriptor.value;
  const output = [];
  for (const key of keys) {
    if (key === 'length') continue;
    if (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= length) return { error: 'UNKNOWN_FIELD', values: null };
    if (!Object.hasOwn(descriptors[key], 'value') || descriptors[key].enumerable !== true) return { error: 'INVALID_REQUEST', values: null };
  }
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return { error: 'INVALID_REQUEST', values: null };
    output.push(descriptor.value);
  }
  return { error: null, values: output };
}

function isUint8Array(value) {
  try {
    return ArrayBuffer.isView(value)
      && TYPED_ARRAY_TAG.call(value) === 'Uint8Array'
      && Object.getPrototypeOf(value) === Uint8Array.prototype;
  } catch {
    return false;
  }
}

function makeSnapshot(state, held = null) {
  return freezeData({ state, held: held === null ? null : cloneData(held) });
}

export function createAdapterSnapshot(state = 'EMPTY') {
  if (!NORMAL_STATES.has(state)) throw new TypeError('state must be EMPTY or ACTIVE');
  return makeSnapshot(state);
}

function inspectHeld(held) {
  const shape = closedObject(held, HOLD_KEYS);
  if (shape.error) return { error: shape.error, held: null };
  const value = shape.values;
  if (!NORMAL_STATES.has(value.originalStateBefore)) return { error: 'UNKNOWN_VALUE', held: null };
  if (typeof value.scenario !== 'string' || !MUTATION_SCENARIOS.has(value.scenario)) return { error: 'UNKNOWN_VALUE', held: null };
  const plan = MUTATION_PLANS[value.scenario];
  if (typeof value.operationIdentity !== 'string' || value.operationIdentity.length === 0) {
    return { error: 'INVALID_REQUEST', held: null };
  }
  const expectedRef = `I-SM-HOLD:${value.operationIdentity}`;
  if (value.mutationPlanIdentity !== value.scenario
      || plan.stateBefore !== value.originalStateBefore
      || value.expectedSuccessCode !== plan.successCode
      || value.expectedStateAfter !== plan.stateAfterCommitted
      || value.outputKind !== plan.outputKind
      || value.reconciliationRef !== expectedRef
      || !['PENDING', 'COMMITTED'].includes(value.terminalEvidenceStatus)) {
    return { error: 'INVALID_REQUEST', held: null };
  }
  if (value.scenario === 'CAPI-S017') {
    if (typeof value.selectedCandidateRef !== 'string' || value.selectedCandidateRef.length === 0) return { error: 'INVALID_REQUEST', held: null };
  } else if (value.selectedCandidateRef !== null) {
    return { error: 'INVALID_REQUEST', held: null };
  }
  return { error: null, held: value };
}

function inferState(snapshot) {
  if (snapshot === null || typeof snapshot !== 'object') return 'RECONCILIATION_REQUIRED';
  try {
    const descriptor = Object.getOwnPropertyDescriptor(snapshot, 'state');
    return descriptor && Object.hasOwn(descriptor, 'value') && STATES.includes(descriptor.value)
      ? descriptor.value
      : 'RECONCILIATION_REQUIRED';
  } catch {
    return 'RECONCILIATION_REQUIRED';
  }
}

function inspectSnapshot(snapshot) {
  const shape = closedObject(snapshot, ['state', 'held']);
  if (shape.error) return { error: shape.error, state: inferState(snapshot), snapshot: null };
  const { state, held } = shape.values;
  if (!STATES.includes(state)) return { error: 'UNKNOWN_VALUE', state: inferState(snapshot), snapshot: null };
  if (NORMAL_STATES.has(state)) {
    if (held !== null) return { error: 'INVALID_REQUEST', state, snapshot: null };
    return { error: null, state, snapshot: makeSnapshot(state) };
  }
  const heldInspection = inspectHeld(held);
  if (heldInspection.error) return { error: heldInspection.error, state, snapshot: null };
  return { error: null, state, snapshot: makeSnapshot(state, heldInspection.held) };
}

function resultEnvelope(result, mutation = null, nextSnapshot = null) {
  return freezeData({
    snapshot: nextSnapshot === null ? null : cloneData(nextSnapshot),
    result: cloneData(result),
    mutation: mutation === null ? null : cloneData(mutation),
  });
}

function errorResult(snapshot, code) {
  const row = TABLES.errorRows[code] ?? TABLES.errorRows.FAIL_CLOSED_INTERNAL;
  return resultEnvelope({
    scenario: row.scenario,
    kind: 'REJECTED',
    code: row.errorCode,
    stateBefore: snapshot.state,
    stateAfter: snapshot.state,
  }, null, snapshot);
}

function invalidSnapshotResult(state, code) {
  const row = TABLES.errorRows[code] ?? TABLES.errorRows.INVALID_REQUEST;
  return resultEnvelope({ scenario: row.scenario, kind: 'REJECTED', code: row.errorCode, stateBefore: state, stateAfter: state });
}

function stateGateResult(snapshot, row) {
  return resultEnvelope({ scenario: row.scenario, kind: row.resultKind, code: row.disposition, stateBefore: snapshot.state, stateAfter: row.stateAfter }, null, snapshot);
}

function candidateForError(code, priority = 30) {
  const row = TABLES.errorRows[code] ?? TABLES.errorRows.FAIL_CLOSED_INTERNAL;
  return { type: 'error', code: row.errorCode, level: Number(row.precedenceLevel.slice(1)), rank: ERROR_RANK.get(row.errorCode), priority };
}

function rowCodeRank(code) {
  return ERROR_RANK.has(code) ? ERROR_RANK.get(code) : Number.MAX_SAFE_INTEGER;
}

function candidateForGate(row) {
  return { type: 'gate', row, level: 5, rank: rowCodeRank(row.disposition), priority: 10 };
}

function candidateForDecision(selection) {
  const row = TABLES.decisionRows[selection.scenario];
  return { type: 'decision', selection, row, level: Number(row.precedenceLevel.slice(1)), rank: rowCodeRank(row.code), priority: 20 };
}

function chooseCandidate(candidates) {
  return [...candidates].sort((left, right) => left.level - right.level || left.rank - right.rank || left.priority - right.priority)[0];
}

function factRejectionCode(operation, facts) {
  if (typeof facts === 'string') {
    const mapping = {
      UNSUPPORTED_ONBOARDING: 'UNSUPPORTED_ONBOARDING', NO_STORED_SESSION: 'NO_STORED_SESSION',
      STORED_SESSION_INCOMPATIBLE: 'STORED_SESSION_INCOMPATIBLE', AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
      AUTHENTICATED_RECORD_INCONSISTENT: 'AUTHENTICATED_STATE_INCONSISTENT',
      MULTIPLE_OR_MIXED_NONLEGACY_CANDIDATES: 'AUTHENTICATED_STATE_INCONSISTENT',
      KEY_PACKAGE_ALREADY_CONSUMED: 'KEY_PACKAGE_ALREADY_CONSUMED',
      WELCOME_NO_MATCHING_KEY_PACKAGE: 'WELCOME_NO_MATCHING_KEY_PACKAGE',
      PAST_OUTSIDE_WINDOW: 'EPOCH_OUTSIDE_RETAINED_WINDOW', FUTURE: 'FUTURE_EPOCH',
      UNSUPPORTED_UPDATE_FORM: 'UNSUPPORTED_UPDATE_FORM',
    };
    return mapping[facts] ?? null;
  }
  const shape = closedObject(facts, ['kind', 'reason', 'current', 'incoming'], ['kind']);
  if (operation === 'APPLY_PEER_UPDATE' && !shape.error) {
    if (shape.values.kind === 'UNSUPPORTED_UPDATE_FORM') return 'UNSUPPORTED_UPDATE_FORM';
    if (shape.values.kind === 'UNSUPPORTED_TOPOLOGY') return 'UNSUPPORTED_COMMIT_SHAPE';
    if (shape.values.kind === 'ELIGIBLE_TWO_CANDIDATE') {
      const pair = closedObject(facts, ['kind', 'current', 'incoming']);
      if (!pair.error) {
        const current = inspectCandidate(pair.values.current);
        const incoming = inspectCandidate(pair.values.incoming);
        if (current.error === 'UNSUPPORTED_TOPOLOGY' || incoming.error === 'UNSUPPORTED_TOPOLOGY') return 'UNSUPPORTED_COMMIT_SHAPE';
        if (!current.error && !incoming.error
            && (current.candidate.ref === incoming.candidate.ref
              || compareIdentity(current.candidate.committerId, incoming.candidate.committerId) === 0)) {
          return 'UNSUPPORTED_COMMIT_SHAPE';
        }
      }
    }
  }
  return null;
}

function inspectEvent(event) {
  const shape = closedObject(event, ['operation', 'applicableErrors', 'facts', 'commitOutcome', 'operationIdentity', 'responseEmission', 'reconciliationRef'], ['operation', 'applicableErrors', 'facts']);
  const errors = [];
  if (shape.error) return { errors: [shape.error], event: null, applicable: [] };
  const value = shape.values;
  if (typeof value.operation !== 'string') errors.push('UNKNOWN_VALUE');
  const errorArray = closedArray(value.applicableErrors);
  const applicable = [];
  if (errorArray.error) {
    errors.push(errorArray.error);
  } else {
    const seen = new Set();
    for (const code of errorArray.values) {
      if (typeof code !== 'string' || !KNOWN_ERRORS.has(code)) errors.push('UNKNOWN_VALUE');
      else if (seen.has(code)) errors.push('INVALID_REQUEST');
      else { seen.add(code); applicable.push(code); }
    }
    const factCode = factRejectionCode(value.operation, value.facts);
    if (factCode !== null && seen.has(factCode)) errors.push('INVALID_REQUEST');
  }
  for (const key of ['commitOutcome', 'operationIdentity', 'responseEmission', 'reconciliationRef']) {
    if (Object.hasOwn(value, key) && typeof value[key] !== 'string') errors.push('UNKNOWN_VALUE');
  }
  if (typeof value.commitOutcome === 'string' && !['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE'].includes(value.commitOutcome)) errors.push('UNKNOWN_VALUE');
  if (typeof value.operationIdentity === 'string' && value.operationIdentity.length === 0) errors.push('UNKNOWN_VALUE');
  if (Object.hasOwn(value, 'responseEmission') && !['SUCCEEDED', 'INTERRUPTED'].includes(value.responseEmission)) errors.push('UNKNOWN_VALUE');
  if (typeof value.reconciliationRef === 'string' && value.reconciliationRef.length === 0) errors.push('UNKNOWN_VALUE');
  return { errors, event: value, applicable };
}

function exactStringFact(facts, allowed) {
  return typeof facts === 'string' && allowed.includes(facts);
}

function compareIdentity(left, right) {
  for (let index = 0; index < 32; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

function inspectCandidate(candidate) {
  const shape = closedObject(candidate, ['committerId', 'ref']);
  if (shape.error) return { error: shape.error, candidate: null };
  if (!isUint8Array(shape.values.committerId)) return { error: 'UNSUPPORTED_TOPOLOGY', candidate: null };
  let byteLength;
  try { byteLength = TYPED_ARRAY_BYTE_LENGTH.call(shape.values.committerId); } catch { return { error: 'UNSUPPORTED_TOPOLOGY', candidate: null }; }
  if (byteLength !== 32) return { error: 'UNSUPPORTED_TOPOLOGY', candidate: null };
  if (typeof shape.values.ref !== 'string' || shape.values.ref.length === 0) return { error: 'UNKNOWN_VALUE', candidate: null };
  return { error: null, candidate: shape.values };
}

function selectDecision(operation, facts) {
  switch (operation) {
    case 'CREATE':
      if (!exactStringFact(facts, ['SUPPORTED', 'UNSUPPORTED_ONBOARDING'])) return { error: 'UNKNOWN_VALUE' };
      return { scenario: facts === 'SUPPORTED' ? 'CAPI-S001' : 'CAPI-S002' };
    case 'RESTORE': {
      const mapping = { RESTORED: 'CAPI-S003', AUTHENTICATED_RECORD_INCONSISTENT: 'CAPI-S004', AUTHENTICATION_FAILED: 'CAPI-S005', NO_STORED_SESSION: 'CAPI-S025', STORED_SESSION_INCOMPATIBLE: 'CAPI-S026', MULTIPLE_OR_MIXED_NONLEGACY_CANDIDATES: 'CAPI-S029' };
      return typeof facts === 'string' && Object.hasOwn(mapping, facts) ? { scenario: mapping[facts] } : { error: 'UNKNOWN_VALUE' };
    }
    case 'JOIN_WELCOME': {
      const mapping = { SUPPORTED: 'CAPI-S006', KEY_PACKAGE_ALREADY_CONSUMED: 'CAPI-S007', UNSUPPORTED_ONBOARDING: 'CAPI-S008', WELCOME_NO_MATCHING_KEY_PACKAGE: 'CAPI-S027' };
      return typeof facts === 'string' && Object.hasOwn(mapping, facts) ? { scenario: mapping[facts] } : { error: 'UNKNOWN_VALUE' };
    }
    case 'PROTECT_APPLICATION': return facts === 'SUPPORTED' ? { scenario: 'CAPI-S009' } : { error: 'UNKNOWN_VALUE' };
    case 'OPEN_APPLICATION': {
      const mapping = { UNSEEN_IN_WINDOW: 'CAPI-S010', DUPLICATE_IN_WINDOW: 'CAPI-S011', PAST_OUTSIDE_WINDOW: 'CAPI-S012', FUTURE: 'CAPI-S013' };
      return typeof facts === 'string' && Object.hasOwn(mapping, facts) ? { scenario: mapping[facts] } : { error: 'UNKNOWN_VALUE' };
    }
    case 'SELF_UPDATE':
      if (!exactStringFact(facts, ['SUPPORTED', 'UNSUPPORTED_UPDATE_FORM'])) return { error: 'UNKNOWN_VALUE' };
      return { scenario: facts === 'SUPPORTED' ? 'CAPI-S014' : 'CAPI-S015' };
    case 'APPLY_PEER_UPDATE': {
      const outer = closedObject(facts, ['kind', 'reason', 'current', 'incoming'], ['kind']);
      if (outer.error) return { error: outer.error };
      const value = outer.values;
      if (value.kind === 'CURRENT_PARENT') return closedObject(facts, ['kind']).error ? { error: 'UNKNOWN_FIELD' } : { scenario: 'CAPI-S016' };
      if (value.kind === 'UNSUPPORTED_UPDATE_FORM') return closedObject(facts, ['kind']).error ? { error: 'UNKNOWN_FIELD' } : { scenario: 'CAPI-S018' };
      if (value.kind === 'UNSUPPORTED_TOPOLOGY') {
        const shape = closedObject(facts, ['kind', 'reason']);
        if (shape.error) return { error: shape.error };
        return typeof shape.values.reason === 'string' && shape.values.reason.length > 0 ? { scenario: 'CAPI-S019' } : { error: 'UNKNOWN_VALUE' };
      }
      if (value.kind !== 'ELIGIBLE_TWO_CANDIDATE') return { error: 'UNKNOWN_VALUE' };
      const shape = closedObject(facts, ['kind', 'current', 'incoming']);
      if (shape.error) return { error: shape.error };
      const current = inspectCandidate(shape.values.current);
      const incoming = inspectCandidate(shape.values.incoming);
      if (current.error === 'UNSUPPORTED_TOPOLOGY' || incoming.error === 'UNSUPPORTED_TOPOLOGY') return { scenario: 'CAPI-S019' };
      if (current.error || incoming.error) return { error: current.error ?? incoming.error };
      if (current.candidate.ref === incoming.candidate.ref) return { scenario: 'CAPI-S019' };
      const order = compareIdentity(current.candidate.committerId, incoming.candidate.committerId);
      if (order === 0) return { scenario: 'CAPI-S019' };
      return { scenario: 'CAPI-S017', selectedCandidateRef: order < 0 ? current.candidate.ref : incoming.candidate.ref };
    }
    default: return { error: 'UNSUPPORTED_OPERATION' };
  }
}

function selectReconciliation(snapshot, event) {
  if (event.facts !== 'RECONCILE_HELD') return { error: 'UNKNOWN_VALUE' };
  if (typeof event.reconciliationRef !== 'string') return { error: 'INVALID_REQUEST' };
  if (event.reconciliationRef !== snapshot.held.reconciliationRef) return { scenario: 'CAPI-S028' };
  if (snapshot.held.terminalEvidenceStatus === 'COMMITTED' && event.commitOutcome !== 'COMMITTED') return { error: 'FAIL_CLOSED_INTERNAL' };
  if (event.commitOutcome === 'COMMITTED') return { scenario: snapshot.held.originalStateBefore === 'EMPTY' ? 'CAPI-S020' : 'CAPI-S022' };
  if (event.commitOutcome === 'NOT_COMMITTED') return { scenario: snapshot.held.originalStateBefore === 'EMPTY' ? 'CAPI-S021' : 'CAPI-S023' };
  return { scenario: 'CAPI-S024' };
}

function conditionalEventErrors(event, selection) {
  const errors = [];
  const isReconcile = event.operation === 'RECONCILE_INDETERMINATE';
  const row = selection.scenario ? TABLES.decisionRows[selection.scenario] : null;
  const isMutation = row?.persistence === 'RS_TRI_STATE';
  if (isMutation) {
    if (typeof event.operationIdentity !== 'string' || event.operationIdentity.length === 0) errors.push('FAIL_CLOSED_INTERNAL');
    if (Object.hasOwn(event, 'responseEmission') || Object.hasOwn(event, 'reconciliationRef')) errors.push('INVALID_REQUEST');
  } else if (isReconcile) {
    if (Object.hasOwn(event, 'operationIdentity')) errors.push('INVALID_REQUEST');
    if (selection.scenario === 'CAPI-S020' || selection.scenario === 'CAPI-S022') {
      if (!['SUCCEEDED', 'INTERRUPTED'].includes(event.responseEmission)) errors.push('INVALID_REQUEST');
    } else if (selection.scenario !== 'CAPI-S028' && Object.hasOwn(event, 'responseEmission')) errors.push('INVALID_REQUEST');
  } else if (Object.hasOwn(event, 'commitOutcome') || Object.hasOwn(event, 'operationIdentity') || Object.hasOwn(event, 'responseEmission') || Object.hasOwn(event, 'reconciliationRef')) {
    errors.push('INVALID_REQUEST');
  }
  return errors;
}

function runMutation(snapshot, row, selection, event) {
  const plan = MUTATION_PLANS[row.scenario];
  if (event.commitOutcome === 'COMMITTED') {
    const result = { scenario: row.scenario, kind: 'SUCCESS', code: plan.successCode, stateBefore: snapshot.state, stateAfter: plan.stateAfterCommitted };
    if (plan.outputKind !== 'NONE') result.outputKind = plan.outputKind;
    if (selection.selectedCandidateRef !== undefined) result.selectedCandidateRef = selection.selectedCandidateRef;
    return resultEnvelope(result, plan, makeSnapshot(plan.stateAfterCommitted));
  }
  if (event.commitOutcome === 'NOT_COMMITTED') {
    return resultEnvelope({ scenario: row.scenario, kind: 'NOT_COMMITTED', code: 'NOT_COMMITTED', stateBefore: snapshot.state, stateAfter: snapshot.state }, plan, makeSnapshot(snapshot.state));
  }
  const reconciliationRef = `I-SM-HOLD:${event.operationIdentity}`;
  const held = {
    originalStateBefore: snapshot.state, scenario: row.scenario, mutationPlanIdentity: row.scenario,
    operationIdentity: event.operationIdentity, expectedSuccessCode: plan.successCode,
    expectedStateAfter: plan.stateAfterCommitted, outputKind: plan.outputKind, reconciliationRef,
    selectedCandidateRef: selection.selectedCandidateRef ?? null, terminalEvidenceStatus: 'PENDING',
  };
  return resultEnvelope({ scenario: row.scenario, kind: 'INDETERMINATE', code: 'INDETERMINATE', stateBefore: snapshot.state, stateAfter: 'RECONCILIATION_REQUIRED', originalStateBefore: snapshot.state, reconciliationRef }, plan, makeSnapshot('RECONCILIATION_REQUIRED', held));
}

function runReconciliation(snapshot, event, selection) {
  const scenario = selection.scenario;
  const row = TABLES.decisionRows[scenario];
  if (scenario === 'CAPI-S028') return resultEnvelope({ scenario, kind: row.kind, code: row.code, stateBefore: snapshot.state, stateAfter: row.stateAfter }, null, snapshot);
  if (scenario === 'CAPI-S024') return resultEnvelope({ scenario, kind: row.kind, code: row.code, stateBefore: snapshot.state, stateAfter: row.stateAfter, originalStateBefore: snapshot.held.originalStateBefore, reconciliationRef: snapshot.held.reconciliationRef }, null, snapshot);
  const committed = scenario === 'CAPI-S020' || scenario === 'CAPI-S022';
  const nextState = committed ? 'ACTIVE' : snapshot.held.originalStateBefore;
  const result = { scenario, kind: row.kind, code: row.code, stateBefore: snapshot.state, stateAfter: nextState };
  if (committed) {
    result.originalSuccessCode = snapshot.held.expectedSuccessCode;
    if (snapshot.held.outputKind !== 'NONE') result.outputKind = snapshot.held.outputKind;
    if (snapshot.held.selectedCandidateRef !== null) result.selectedCandidateRef = snapshot.held.selectedCandidateRef;
    result.responseEmission = event.responseEmission;
    if (event.responseEmission === 'INTERRUPTED') {
      const held = { ...snapshot.held, terminalEvidenceStatus: 'COMMITTED' };
      return resultEnvelope(result, null, makeSnapshot('RECONCILIATION_REQUIRED', held));
    }
  }
  return resultEnvelope(result, null, makeSnapshot(nextState));
}

function runDecision(snapshot, event, selection) {
  const row = TABLES.decisionRows[selection.scenario];
  if (event.operation === 'RECONCILE_INDETERMINATE') return runReconciliation(snapshot, event, selection);
  if (row.persistence === 'RS_TRI_STATE') return runMutation(snapshot, row, selection, event);
  return resultEnvelope({ scenario: row.scenario, kind: row.kind, code: row.code, stateBefore: snapshot.state, stateAfter: row.stateAfter }, null, makeSnapshot(row.stateAfter));
}

export function transitionAdapter(snapshotInput, eventInput) {
  const inspectedSnapshot = inspectSnapshot(snapshotInput);
  if (inspectedSnapshot.error) return invalidSnapshotResult(inspectedSnapshot.state, inspectedSnapshot.error);
  const snapshot = inspectedSnapshot.snapshot;
  const inspectedEvent = inspectEvent(eventInput);
  const candidates = inspectedEvent.errors.map((code) => candidateForError(code, 0));
  if (inspectedEvent.event === null) return errorResult(snapshot, chooseCandidate(candidates).code);
  const event = inspectedEvent.event;
  for (const code of inspectedEvent.applicable) candidates.push(candidateForError(code));

  if (!KNOWN_OPERATIONS.has(event.operation)) {
    candidates.push(candidateForError('UNSUPPORTED_OPERATION', 5));
    const winner = chooseCandidate(candidates);
    return errorResult(snapshot, winner.code);
  }

  const selection = event.operation === 'RECONCILE_INDETERMINATE'
    ? (event.facts !== 'RECONCILE_HELD'
      ? { error: 'UNKNOWN_VALUE' }
      : (typeof event.reconciliationRef !== 'string'
        ? { error: 'INVALID_REQUEST' }
        : (snapshot.state === 'RECONCILIATION_REQUIRED' ? selectReconciliation(snapshot, event) : { scenario: 'CAPI-S024' })))
    : selectDecision(event.operation, event.facts);
  if (selection.error) candidates.push(candidateForError(selection.error, 0));
  else {
    candidates.push(candidateForDecision(selection));
    for (const code of conditionalEventErrors(event, selection)) candidates.push(candidateForError(code, 0));
  }
  const gate = TABLES.stateRows[`${snapshot.state}|${event.operation}`];
  if (gate.disposition !== 'ALLOW') candidates.push(candidateForGate(gate));
  const winner = chooseCandidate(candidates);
  if (winner.type === 'error') return errorResult(snapshot, winner.code);
  if (winner.type === 'gate') return stateGateResult(snapshot, winner.row);
  return runDecision(snapshot, event, winner.selection);
}
