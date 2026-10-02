// message.test.js — I-MSG conformance tests for the M2 opaque application protect/open integration,
// the C-RET replay/retention window and the window/replay reject cases (contract Issue #411 of
// #317 G-SCOPE).
//
// The tests drive the real `invokeAdapter` / `invokeAdapterTransition` over the injected request,
// snapshot and owning-layer observation: the exact C-API decision rows CAPI-S009 to CAPI-S013 for
// `PROTECT_APPLICATION` and `OPEN_APPLICATION`, the C-RET current-plus-five-past-epoch window at its
// boundary (current, current-1, current-5 accepted; current-6 and beyond and every future epoch
// rejected), the `P06` structural epoch bound, the key-dependent authentication and replay verdicts,
// the RS tri-state and its output release, the state gates, the fail-closed request and observation
// validation, total precedence, the closed result envelope, purity and immutability, and a seeded
// property sweep. Nothing is mocked: the decision is taken by the merged I-SM core.

import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  M2_ADAPTER,
  M2AdapterError,
  invokeAdapter,
  invokeAdapterTransition,
  validateAdapterRequest,
} from '../../../src/crypto/mls/m2/adapter.js';
import { createAdapterSnapshot, transitionAdapter } from '../../../src/crypto/mls/m2/state-machine.js';

const API = M2_ADAPTER.API;
const PROFILE = M2_ADAPTER.PROFILE;
const BOUNDS = M2_ADAPTER.BOUNDS;
const RETENTION = M2_ADAPTER.RETENTION;

// The ratified O-SCEN scenario ids this card's implemented clause pointers are mapped to, by the
// clause-identity rule of M2-I-MSG-SCENARIO-MAPPING.json (see the evidence bundle): each scenario row
// whose canonical clause content is the clause pointer named by the row's action is mapped to the
// named test that implements that pointer. The whole blind set is 1821 rows; the owner reconciliation
// list stays OPEN.
const OSCEN_SCENARIOS = {
  '/codeToResultKind': [
    'OSC-10e48bd21871e3ea', 'OSC-bac934099642a48d', 'OSC-354dcdaff1f70a2e',
    'OSC-40889223667af929', 'OSC-af6b40d35ad49c9d', 'OSC-b921ef10edae9564',
    'OSC-c674b07f80aee1e4'
  ],
  '/commitOutcomeEnum': [
    'OSC-06351931f9565a4f', 'OSC-cb6c0a14b126b79d', 'OSC-b838434c7a3aca50'
  ],
  '/decisionRows': [
    'OSC-039d2541ca381eb6', 'OSC-272164b3f6ced9b4', 'OSC-f2d864ee58cc0784',
    'OSC-b92a2b9a90af255f', 'OSC-040428778da7f360'
  ],
  '/errorCodeEnum': [
    'OSC-c70e41ad3bc5c2a3', 'OSC-a085ba7e6260d7f1', 'OSC-4b12bcf17ffa24f6',
    'OSC-6844abf9cf66be2b', 'OSC-3c4f12b401aad67a', 'OSC-6b74356080755ec3',
    'OSC-f1c5d4ce4ea381e8', 'OSC-474416f91a5f4536'
  ],
  '/errorDefinitions': [
    'OSC-2952347fd5206190', 'OSC-6d899c0dd8c8c5cb', 'OSC-5a23d7268d61c6c1',
    'OSC-2defa736cbf8c637', 'OSC-41e4cc342bd76c87', 'OSC-12188dbbddee170f',
    'OSC-38aacc4880942f46'
  ],
  '/errorPrecedenceLevel': [
    'OSC-455ed401ea365633', 'OSC-610eb473f38bb1eb', 'OSC-4810f39c5bc07249',
    'OSC-5e50eb0e8aaa3039'
  ],
  '/nonClaims': [
    'OSC-005664f9d81b5036', 'OSC-09d555d3149257e2', 'OSC-0de0c697fa7865dd',
    'OSC-0f76e410275a3eb8', 'OSC-10da1e61befc2244', 'OSC-1106bf858e6a1582',
    'OSC-148301f523f7a272', 'OSC-1713e9b3c317ab0a', 'OSC-17bf2893531e1dce',
    'OSC-17d3997c635bcced', 'OSC-2122776d9a6e7135', 'OSC-2164eca684504a5e',
    'OSC-24b30e5e93b43f96', 'OSC-26772ddff4233928', 'OSC-2af57caa34f50462',
    'OSC-2c0fff37a8db2a6d', 'OSC-3d7e62a8eced0a9d', 'OSC-3f5d4a155bebb985',
    'OSC-418b250dd839768f', 'OSC-50bdaf56cb861e7f', 'OSC-520e8c834ce9f56e',
    'OSC-52c6e02fb7c8ddd9', 'OSC-59d1768a423f0b3c', 'OSC-5bb910d0ce4dcdfd',
    'OSC-5ef8fcd47dd78df2', 'OSC-60e7256805bafbf0', 'OSC-6b870d574402028d',
    'OSC-6e116cb254061107', 'OSC-78395bc6d60897ee', 'OSC-7af3b5836bd90793',
    'OSC-7bebf6b394d37f1b', 'OSC-83fe8876231d1a9f', 'OSC-863e4c5124c4eaa9',
    'OSC-8a1e339aa40bfb68', 'OSC-a137a0c4776daede', 'OSC-a61a4a6a81197c4a',
    'OSC-a9c7a57defb3f784', 'OSC-ab78a8b7e93701fc', 'OSC-abe93c1728c37102',
    'OSC-b21c83d2be10a760', 'OSC-b414808b3f6e67e4', 'OSC-ba756a36f65c9211',
    'OSC-bd3d82f73164707f', 'OSC-c0bf076fcbb78dca', 'OSC-c12a116f6de379a2',
    'OSC-c3c3c2426f6d1977', 'OSC-c983de602757bd8d', 'OSC-d2950cc5fc5419e3',
    'OSC-d625a1b980413a36', 'OSC-d645d5a8562ef599', 'OSC-d76c9a3d7ff2489f',
    'OSC-dd014c5e4190303b', 'OSC-e057ec8a85db4d4e', 'OSC-e4c3077144746801',
    'OSC-ea194e7bd00bd2f7', 'OSC-eb73a24e35ff6f02', 'OSC-ed451da81b0b81a4',
    'OSC-edc2b2318c8e3367', 'OSC-f109b4e5291ca005', 'OSC-f2b1ffadc1de1577',
    'OSC-f5718bd8a8412d01', 'OSC-f91d7b5219fb980c'
  ],
  '/operationEnum': [
    'OSC-f25e07c2cfe9ef54', 'OSC-fd1692d4b0742c06'
  ],
  '/precedenceLevels': [
    'OSC-8c9800c0135d2c39', 'OSC-53d9659868b96955'
  ],
  '/precedencePairs': [
    'OSC-0aab84c36275f501', 'OSC-1cde371be9245ff8', 'OSC-2163ae083f60c441',
    'OSC-2a86c1aa16784117', 'OSC-3ae47a4851dc2e3e', 'OSC-3b9d3951675612c3',
    'OSC-5c9f6f58dfb91b9a', 'OSC-5f4a158a65910625', 'OSC-62e85471317a3643',
    'OSC-70b4b8d534f06f06', 'OSC-9bade26fa51b61df', 'OSC-9d5176567b59994c',
    'OSC-9edd8c5c05aeaada', 'OSC-c4dc19f2ce3cecbb', 'OSC-cc63c689753a78be',
    'OSC-e9fa5890f68962d5', 'OSC-ec51ce85abe4d613'
  ],
  '/profile/pastEpochWindow': [
    'OSC-535209f7230008ff', 'OSC-6bd251aa71e602a7'
  ],
  '/request/inputByOperation': [
    'OSC-ee1310a7fcd443b8'
  ],
  '/response/byKind': [
    'OSC-c99986582316e23c'
  ],
  '/response/outputBySuccessCode': [
    'OSC-345d9f9fb61f4c7a'
  ],
  '/resultKindEnum': [
    'OSC-3d9b7da2d4b40760', 'OSC-5a12253a1b94ba5c', 'OSC-ed39d6a987385472'
  ],
  '/rules/completeLogicalMutation': [
    'OSC-3ba76ad1910efd14'
  ],
  '/rules/derivedFacts': [
    'OSC-9ebe2108b66fc218'
  ],
  '/rules/framingEpochBeforeAuthentication': [
    'OSC-7db987734dd9f139'
  ],
  '/rules/internalFailureBoundary': [
    'OSC-c614c21efa1f19d6'
  ],
  '/rules/payloadRelease': [
    'OSC-ab20fdebafb24483'
  ],
  '/rules/replayOrder': [
    'OSC-aa1cd1c3211dc823'
  ],
  '/rules/rsTriState': [
    'OSC-f4eb5de98aefe7dc'
  ],
  '/stateEnum': [
    'OSC-4fdb61c9157940c6', 'OSC-fe345e8b2cbf86a0'
  ],
  '/stateMatrix': [
    'OSC-3d08d077a759b43c', 'OSC-e1602f637d6bd551', 'OSC-813ba28ed4fa1072',
    'OSC-5879284d84662a5b', 'OSC-6a89d2539e9323e8', 'OSC-7e0a44009fea4c91'
  ],
  '/successCodeEnum': [
    'OSC-35bc709df10f1678', 'OSC-96f48e740ab1a1fb', 'OSC-f5228b30a34575bd'
  ],
  '/withinLevelErrorOrder': [
    'OSC-0522d7b7d3502cc4', 'OSC-c1ec8b0dfa28a1c4'
  ],
  '/withinLevelPrecedencePairs': [
    'OSC-a4ffb8eca560a9c8'
  ],
  'C-RET/enums': [
    'OSC-d553553a94780317', 'OSC-024084bed64ac4a1'
  ],
  'C-RET/epochRule': [
    'OSC-9ed400b7a6602e62', 'OSC-ad26b270e382b2fb', 'OSC-9a71e7db7fab3411'
  ],
  'C-RET/lifecycleMatrix/PAST_EPOCH_REPLAY_DECRYPTION_MATERIAL': [
    'OSC-099f0c355a891fde', 'OSC-1adbbcd19cc57793', 'OSC-28deb99e4ebb0a84',
    'OSC-2f53186a3d1aa529', 'OSC-34aead2413b414eb', 'OSC-3d068773f8722faf',
    'OSC-4cb98c055c86ff33', 'OSC-4eb177dcce9cc123', 'OSC-5c6c6d16384f3f8c',
    'OSC-5fbff302d019a663', 'OSC-6925e87aa37b4241', 'OSC-764253ec65afeead',
    'OSC-7800a53bc79a2b6c', 'OSC-7fdd2dbdb8a39b84', 'OSC-a235221ec15fa630',
    'OSC-c92b93d130da8893'
  ],
  'C-RET/lifecycleMatrix/REPLAY_WINDOW_STATE': [
    'OSC-02fa86253b24da1c', 'OSC-08344ad3403ea43d', 'OSC-11139a494e43d722',
    'OSC-12cbae2271e47c7e', 'OSC-32929352483bbeaa', 'OSC-4b4bc76e26695ea8',
    'OSC-566de08cfd4a29c7', 'OSC-5ada9f00d02d5c3b', 'OSC-61d0da4b15d9edcc',
    'OSC-6caf7bf3cd775b96', 'OSC-72e65cb5ff2f4ddf', 'OSC-88df51434b3128d7',
    'OSC-c8b4f00e61a1df78', 'OSC-d95b03fcd7c6ef90', 'OSC-e7ed0abcfb74d6b4',
    'OSC-e817c9b7c150c974'
  ],
  'C-RET/materialClasses/REPLAY_WINDOW_STATE': [
    'OSC-5020703f1a5ddc81'
  ],
};

const MAPPED_SCENARIO_IDS = [...new Set(Object.values(OSCEN_SCENARIOS).flat())];

const request = (operation, input, overrides = {}) => ({
  api: API,
  operation,
  requestId: 'req-1',
  profile: { ...PROFILE },
  bindingRef: new Uint8Array([0xa1, 0xa2]),
  input,
  ...overrides,
});

const empty = () => createAdapterSnapshot('EMPTY');
const active = () => createAdapterSnapshot('ACTIVE');

/** The snapshot a caller holds after an INDETERMINATE decision: taken from the real I-SM core. */
const held = () => transitionAdapter(empty(), {
  operation: 'CREATE',
  applicableErrors: [],
  facts: 'SUPPORTED',
  commitOutcome: 'INDETERMINATE',
  operationIdentity: 'held-op',
}).snapshot;

const bytes = (length, seed = 0x11) => new Uint8Array(length).fill(seed);

/** The closed `PROTECT_APPLICATION` observation: the RS tri-state, the identity and the staged bytes. */
const protectObservation = (commitOutcome = 'COMMITTED', staged = bytes(6), identity = 'op-protect-1') => ({
  commitOutcome,
  operationIdentity: identity,
  stagedOutput: staged === null ? null : { protectedApplicationBytes: staged },
});

/**
 * The closed `OPEN_APPLICATION` observation of a distance-`distance` framing message. The three
 * unreachable groups carry the exact `null` the closed rules require.
 */
const openObservation = (distance, {
  authentication = 'AUTHENTICATED', replayIdentity = 'UNSEEN',
  commitOutcome = 'COMMITTED', staged = bytes(6), identity = 'op-open-1', currentEpoch = 9,
} = {}) => ({
  currentEpoch,
  framingEpoch: currentEpoch - distance,
  authentication,
  replayIdentity,
  commitOutcome,
  operationIdentity: commitOutcome === null ? null : identity,
  stagedOutput: commitOutcome === null || staged === null ? null : { applicationBytes: staged },
});

/** The two members the framing epoch makes unreachable, set to the exact required `null`s. */
const unreachable = (currentEpoch, framingEpoch) => ({
  currentEpoch,
  framingEpoch,
  authentication: null,
  replayIdentity: null,
  commitOutcome: null,
  operationIdentity: null,
  stagedOutput: null,
});

const invoke = (req, snapshot, observation) => invokeAdapter({ request: req, snapshot, observation });
const code = (result) => (result.kind === 'REJECTED' ? result.error.code : result.successCode);

describe('I-MSG module surface (#411)', () => {
  test('the metadata is frozen and adds exactly RETENTION and OBSERVATION_KEYS', () => {
    expect(Object.isFrozen(M2_ADAPTER)).toBe(true);
    expect([...M2_ADAPTER.INTEGRATED_OPERATIONS]).toEqual([
      'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
    ]);
    expect(Object.isFrozen(M2_ADAPTER.RETENTION)).toBe(true);
    expect(Object.isFrozen(M2_ADAPTER.OBSERVATION_KEYS)).toBe(true);
    expect(Object.isFrozen(M2_ADAPTER.BOUNDS)).toBe(true);
  });

  test('the C-RET window is the C-API profile window, byte for byte', () => {
    // C-RET §12 `epochRule` / `docs/security/m2-retention-and-disposal-limits.md`
    // (sha256 eb051194620d795fc047cae367e4cd8e6c26c568fddae5a2986cdbc7549b31a2) and C-API
    // `/profile/pastEpochWindow` (sha256 b77d39fbb412b0eba3a579ebf6053408186a4c11f0de07b8727b4e1147305ad9).
    expect(RETENTION.CURRENT_EPOCHS).toBe(1);
    expect(RETENTION.MAXIMUM_PAST_EPOCHS).toBe(5);
    expect(RETENTION.PAST_EPOCHS_ONCE_AVAILABLE).toBe(5);
    expect(RETENTION.PAST_EPOCHS_ONCE_AVAILABLE).toBe(PROFILE.pastEpochWindow);
    expect(RETENTION.MAXIMUM_PAST_EPOCHS).toBe(PROFILE.pastEpochWindow);
  });

  test('the observation member sets are exactly the closed per-operation sets', () => {
    expect([...M2_ADAPTER.OBSERVATION_KEYS.PROTECT_APPLICATION])
      .toEqual(['commitOutcome', 'operationIdentity', 'stagedOutput']);
    expect([...M2_ADAPTER.OBSERVATION_KEYS.OPEN_APPLICATION]).toEqual([
      'currentEpoch', 'framingEpoch', 'authentication', 'replayIdentity', 'commitOutcome',
      'operationIdentity', 'stagedOutput',
    ]);
  });

  test('the selected bounds cover the epoch count of the framing window', () => {
    expect(BOUNDS.MAX_FRAMING_EPOCH).toBe(2147483647);
    expect(BOUNDS.MAX_FRAMING_EPOCH).toBeGreaterThan(RETENTION.PAST_EPOCHS_ONCE_AVAILABLE);
    expect(Object.isFrozen(BOUNDS)).toBe(true);
  });

  test('the two added operations are admissible requests', () => {
    expect(validateAdapterRequest(request('PROTECT_APPLICATION', { applicationBytes: bytes(4) })).code).toBeNull();
    expect(validateAdapterRequest(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(4) })).code).toBeNull();
  });

  test('the operations this card does not integrate stay unsupported', () => {
    const inputs = {
      SELF_UPDATE: {},
      APPLY_PEER_UPDATE: { protectedCommitBytes: bytes(4) },
      RECONCILE_INDETERMINATE: { reconciliationRef: 'ref-1' },
      ADD_MEMBER: {},
    };
    for (const [operation, input] of Object.entries(inputs)) {
      const result = invoke(request(operation, input), empty(), {});
      expect([operation, result.kind]).toEqual([operation, 'REJECTED']);
      expect([operation, result.error.code]).toEqual([operation, 'UNSUPPORTED_OPERATION']);
    }
  });
});

describe('I-MSG PROTECT_APPLICATION (CAPI-S009, CAPI-G004, CAPI-G012, CAPI-G020)', () => {
  test('an ACTIVE session protects the staged bytes and releases them only after COMMITTED', () => {
    const staged = bytes(6, 0x5a);
    const transition = invokeAdapterTransition({
      request: request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }),
      snapshot: active(),
      observation: protectObservation('COMMITTED', staged),
    });
    const result = transition.result;
    expect(result.kind).toBe('SUCCESS');
    expect(result.successCode).toBe('APPLICATION_PROTECTED');
    expect(result.commitOutcome).toBe('COMMITTED');
    expect(result.stateBefore).toBe('ACTIVE');
    expect(result.stateAfter).toBe('ACTIVE');
    expect([...result.output.protectedApplicationBytes]).toEqual([...staged]);
    expect(transition.snapshot.state).toBe('ACTIVE');
    expect(transition.snapshot.held).toBeNull();
  });

  test('NOT_COMMITTED releases no output and keeps the session ACTIVE', () => {
    const transition = invokeAdapterTransition({
      request: request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }),
      snapshot: active(),
      observation: protectObservation('NOT_COMMITTED'),
    });
    expect(transition.result.kind).toBe('NOT_COMMITTED');
    expect(transition.result.commitOutcome).toBe('NOT_COMMITTED');
    expect(Object.hasOwn(transition.result, 'output')).toBe(false);
    expect(Object.hasOwn(transition.result, 'successCode')).toBe(false);
    expect(transition.snapshot.state).toBe('ACTIVE');
  });

  test('INDETERMINATE retains the held mutation and releases no output', () => {
    const transition = invokeAdapterTransition({
      request: request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }),
      snapshot: active(),
      observation: protectObservation('INDETERMINATE'),
    });
    expect(transition.result.kind).toBe('INDETERMINATE');
    expect(transition.result.commitOutcome).toBe('INDETERMINATE');
    expect(transition.result.originalStateBefore).toBe('ACTIVE');
    expect(transition.result.reconciliationRef).toBe('I-SM-HOLD:op-protect-1');
    expect(Object.hasOwn(transition.result, 'output')).toBe(false);
    // The C-MUT complete logical mutation of CAPI-S009 is held, `REPLAY_RETENTION_STATE` included.
    expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(transition.snapshot.held.scenario).toBe('CAPI-S009');
    expect(transition.snapshot.held.expectedSuccessCode).toBe('APPLICATION_PROTECTED');
    expect(transition.snapshot.held.originalStateBefore).toBe('ACTIVE');
  });

  test('an absent, empty or over-bound staged output is an internal failure after the commit request', () => {
    const cases = [
      ['absent', null],
      ['empty', new Uint8Array(0)],
      ['over the bound', bytes(BOUNDS.MAX_OPAQUE_BYTES + 1)],
    ];
    for (const [label, staged] of cases) {
      for (const outcome of ['COMMITTED', 'INDETERMINATE']) {
        const transition = invokeAdapterTransition({
          request: request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }),
          snapshot: active(),
          observation: protectObservation(outcome, staged),
        });
        expect([label, outcome, transition.result.kind]).toEqual([label, outcome, 'INDETERMINATE']);
        expect(transition.result.commitOutcome).toBe('INDETERMINATE');
        expect(Object.hasOwn(transition.result, 'output')).toBe(false);
        expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
      }
      const transition = invokeAdapterTransition({
        request: request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }),
        snapshot: active(),
        observation: protectObservation('NOT_COMMITTED', staged),
      });
      expect([label, transition.result.kind]).toEqual([label, 'NOT_COMMITTED']);
    }
  });

  test('the state gate is decided before the message surface', () => {
    const inEmpty = invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }), empty(), protectObservation());
    expect(inEmpty.kind).toBe('REJECTED');
    expect(inEmpty.error.code).toBe('NO_ACTIVE_SESSION');
    expect(inEmpty.stateAfter).toBe('EMPTY');

    const inHeld = invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }), held(), protectObservation());
    expect(inHeld.kind).toBe('REJECTED');
    expect(inHeld.error.code).toBe('RECONCILIATION_REQUIRED');
    expect(inHeld.stateAfter).toBe('RECONCILIATION_REQUIRED');
  });

  test('the request input bound is P06 and never shortens the result to a rejection after a commit', () => {
    const over = invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(BOUNDS.MAX_OPAQUE_BYTES + 1) }), active(),
      protectObservation('COMMITTED'));
    // C-API `/rules/internalFailureBoundary`: the bound is found only after the RS commit request
    // answered, so the adapter holds the mutation instead of rejecting it.
    expect(over.kind).toBe('INDETERMINATE');
  });
});

describe('I-MSG OPEN_APPLICATION window: current, current-1 and current-5 (CAPI-S010, C-RET §3)', () => {
  test.each([
    ['current', 0], ['one past', 1], ['two past', 2], ['three past', 3], ['four past', 4], ['five past', 5],
  ])('%s is in the retained window and opens the plaintext', (_label, distance) => {
    const staged = bytes(7, 0x33);
    const transition = invokeAdapterTransition({
      request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
      snapshot: active(),
      observation: openObservation(distance, { staged }),
    });
    expect(transition.result.kind).toBe('SUCCESS');
    expect(transition.result.successCode).toBe('APPLICATION_OPENED');
    expect(transition.result.commitOutcome).toBe('COMMITTED');
    expect(transition.result.stateAfter).toBe('ACTIVE');
    expect([...transition.result.output.applicationBytes]).toEqual([...staged]);
    expect(transition.snapshot.state).toBe('ACTIVE');
  });

  test('the window boundary is exactly the ratified five past epochs', () => {
    const atEdge = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      openObservation(RETENTION.PAST_EPOCHS_ONCE_AVAILABLE));
    const beyondEdge = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      unreachable(9, 9 - RETENTION.PAST_EPOCHS_ONCE_AVAILABLE - 1));
    expect(atEdge.successCode).toBe('APPLICATION_OPENED');
    expect(beyondEdge.error.code).toBe('EPOCH_OUTSIDE_RETAINED_WINDOW');
  });

  test.each([6, 7, 9])('a past distance of %i rejects EPOCH_OUTSIDE_RETAINED_WINDOW at P07', (distance) => {
    const transition = invokeAdapterTransition({
      request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
      snapshot: active(),
      observation: unreachable(9, 9 - distance),
    });
    expect(transition.result.kind).toBe('REJECTED');
    expect(transition.result.error.code).toBe('EPOCH_OUTSIDE_RETAINED_WINDOW');
    expect(transition.result.stateAfter).toBe(transition.result.stateBefore);
    expect(Object.hasOwn(transition.result, 'output')).toBe(false);
    expect(Object.hasOwn(transition.result, 'commitOutcome')).toBe(false);
    expect(transition.snapshot).toBeNull();
  });

  test('a far past distance inside the epoch bound still rejects at P07', () => {
    const transition = invokeAdapterTransition({
      request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
      snapshot: active(),
      observation: unreachable(200, 100),
    });
    expect(transition.result.error.code).toBe('EPOCH_OUTSIDE_RETAINED_WINDOW');
    expect(transition.snapshot).toBeNull();
  });

  test.each([1, 2, 6])('a future epoch of +%i framing epochs rejects FUTURE_EPOCH at P07', (ahead) => {
    const transition = invokeAdapterTransition({
      request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
      snapshot: active(),
      observation: unreachable(9, 9 + ahead),
    });
    expect(transition.result.kind).toBe('REJECTED');
    expect(transition.result.error.code).toBe('FUTURE_EPOCH');
    expect(transition.result.stateAfter).toBe('ACTIVE');
    expect(transition.snapshot).toBeNull();
  });

  test('an out-of-window or future input neither extends nor shrinks the window state', () => {
    const cases = [unreachable(9, 3), unreachable(9, 12)];
    for (const observation of cases) {
      const first = invokeAdapterTransition({
        request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
        snapshot: active(), observation,
      });
      const second = invokeAdapterTransition({
        request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
        snapshot: active(), observation,
      });
      // The rejection is total and idempotent: no write, no window change, no state change at all.
      expect(first.snapshot).toBeNull();
      expect(second.result).toEqual(first.result);
    }
    // The five accepted distances keep succeeding while the sixth and the future one keep rejecting:
    // the retained window is stable, never extended by an out-of-window input.
    for (const distance of [0, 1, 2, 3, 4, 5]) {
      expect(invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
        openObservation(distance)).successCode).toBe('APPLICATION_OPENED');
    }
  });

  test('the framing epoch is classified structurally, before any key-dependent work', () => {
    // P07 preempts P08 and P09: an out-of-window framing carrying a failed authentication verdict and a
    // duplicate replay verdict is still EPOCH_OUTSIDE_RETAINED_WINDOW, and the window call makes no
    // authentication or replay lookup.
    const outOfWindowWithAuth = invoke(
      request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      { ...unreachable(9, 3), authentication: 'AUTHENTICATION_FAILED', replayIdentity: 'DUPLICATE' },
    );
    expect(outOfWindowWithAuth.error.code).toBe('INVALID_REQUEST');
    const outOfWindowClean = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(), unreachable(9, 3));
    expect(outOfWindowClean.error.code).toBe('EPOCH_OUTSIDE_RETAINED_WINDOW');
    const futureOverAuth = invoke(
      request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      unreachable(9, 40),
    );
    expect(futureOverAuth.error.code).toBe('FUTURE_EPOCH');
  });

  test('the state gate preempts the window and the bound', () => {
    const inEmpty = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), empty(),
      openObservation(0));
    expect(inEmpty.error.code).toBe('NO_ACTIVE_SESSION');
    const outOfWindowInEmpty = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), empty(),
      unreachable(9, 3));
    expect(outOfWindowInEmpty.error.code).toBe('NO_ACTIVE_SESSION');
    const boundInEmpty = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), empty(),
      unreachable(9, BOUNDS.MAX_FRAMING_EPOCH + 1));
    expect(boundInEmpty.error.code).toBe('NO_ACTIVE_SESSION');
    const inHeld = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), held(),
      openObservation(0));
    expect(inHeld.error.code).toBe('RECONCILIATION_REQUIRED');
  });
});

describe('I-MSG replay, authentication and the RS tri-state (CAPI-S011, CAPI-S012, CAPI-S013, CAPI-E017)', () => {
  test('an already accepted replay identity makes no second transition and releases no plaintext', () => {
    const duplicate = openObservation(1, { replayIdentity: 'DUPLICATE', commitOutcome: null, staged: null });
    const transition = invokeAdapterTransition({
      request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
      snapshot: active(),
      observation: duplicate,
    });
    expect(transition.result.kind).toBe('NO_CHANGE');
    expect(transition.result.successCode).toBe('DUPLICATE_IGNORED');
    expect(Object.hasOwn(transition.result, 'output')).toBe(false);
    expect(Object.hasOwn(transition.result, 'commitOutcome')).toBe(false);
    expect(transition.result.stateAfter).toBe('ACTIVE');
    // The retained replay/retention state is untouched and no held mutation appears.
    expect(transition.snapshot.state).toBe('ACTIVE');
    expect(transition.snapshot.held).toBeNull();
  });

  test('a duplicate never carries a commit outcome, a staged plaintext or an identity', () => {
    for (const extra of [
      { commitOutcome: 'COMMITTED' },
      { operationIdentity: 'op-open-1' },
      { stagedOutput: { applicationBytes: bytes(6) } },
    ]) {
      const result = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
        { ...openObservation(1, { replayIdentity: 'DUPLICATE', commitOutcome: null, staged: null }), ...extra });
      expect(result.error.code).toBe('INVALID_REQUEST');
    }
  });

  test('a failed key-dependent authentication rejects AUTHENTICATION_FAILED and opens nothing', () => {
    const result = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      openObservation(2, { authentication: 'AUTHENTICATION_FAILED', replayIdentity: null, commitOutcome: null, staged: null }));
    expect(result.kind).toBe('REJECTED');
    expect(result.error.code).toBe('AUTHENTICATION_FAILED');
    expect(Object.hasOwn(result, 'output')).toBe(false);
  });

  test('an unseen identity commits, and INDETERMINATE retains the held receiver mutation', () => {
    const indeterminate = invokeAdapterTransition({
      request: request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
      snapshot: active(),
      observation: openObservation(3, { commitOutcome: 'INDETERMINATE' }),
    });
    expect(indeterminate.result.kind).toBe('INDETERMINATE');
    expect(indeterminate.result.reconciliationRef).toBe('I-SM-HOLD:op-open-1');
    expect(Object.hasOwn(indeterminate.result, 'output')).toBe(false);
    expect(indeterminate.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(indeterminate.snapshot.held.scenario).toBe('CAPI-S010');
    expect(indeterminate.snapshot.held.expectedSuccessCode).toBe('APPLICATION_OPENED');

    const notCommitted = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      openObservation(3, { commitOutcome: 'NOT_COMMITTED' }));
    expect(notCommitted.kind).toBe('NOT_COMMITTED');
    expect(Object.hasOwn(notCommitted, 'output')).toBe(false);
  });

  test('an absent, empty or over-bound staged plaintext is an internal failure after the commit request', () => {
    for (const staged of [null, new Uint8Array(0), bytes(BOUNDS.MAX_OPAQUE_BYTES + 1)]) {
      const committed = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
        openObservation(0, { staged }));
      expect(committed.kind).toBe('INDETERMINATE');
      expect(Object.hasOwn(committed, 'output')).toBe(false);
      const notCommitted = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
        openObservation(0, { staged, commitOutcome: 'NOT_COMMITTED' }));
      expect(notCommitted.kind).toBe('NOT_COMMITTED');
      expect(Object.hasOwn(notCommitted, 'output')).toBe(false);
    }
  });

  test('no operation ever rejects after a commit request reached RS', () => {
    const outcomes = ['COMMITTED', 'INDETERMINATE'];
    const protectInputs = [bytes(6), bytes(BOUNDS.MAX_OPAQUE_BYTES + 1)];
    for (const outcome of outcomes) {
      for (const input of protectInputs) {
        for (const staged of [bytes(6), null, new Uint8Array(0)]) {
          const result = invoke(request('PROTECT_APPLICATION', { applicationBytes: input }), active(),
            protectObservation(outcome, staged));
          expect(result.kind).not.toBe('REJECTED');
        }
      }
      for (const staged of [bytes(6), null, new Uint8Array(0)]) {
        for (let distance = 0; distance <= 5; distance += 1) {
          const result = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
            openObservation(distance, { commitOutcome: outcome, staged }));
          expect(result.kind).not.toBe('REJECTED');
        }
      }
    }
  });
});

describe('I-MSG structural epoch bound and fail-closed validation (CAPI-E014, CAPI-E009, CAPI-E011)', () => {
  test('an epoch count over the selected bound is VALUE_OUT_OF_RANGE at P06', () => {
    for (const observation of [
      unreachable(9, BOUNDS.MAX_FRAMING_EPOCH + 1),
      unreachable(BOUNDS.MAX_FRAMING_EPOCH + 1, 9),
      unreachable(BOUNDS.MAX_FRAMING_EPOCH + 1, BOUNDS.MAX_FRAMING_EPOCH + 2),
    ]) {
      const result = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(), observation);
      expect(result.kind).toBe('REJECTED');
      expect(result.error.code).toBe('VALUE_OUT_OF_RANGE');
    }
  });

  test('the bound preempts the window rejection and is preempted by the state gate', () => {
    const atBound = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      openObservation(1, { currentEpoch: BOUNDS.MAX_FRAMING_EPOCH }));
    expect(atBound.successCode).toBe('APPLICATION_OPENED');
    const overBound = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      openObservation(1, { currentEpoch: BOUNDS.MAX_FRAMING_EPOCH + 1 }));
    expect(overBound.error.code).toBe('VALUE_OUT_OF_RANGE');
  });

  test('a malformed epoch is INVALID_REQUEST at P01, an out-of-set verdict UNKNOWN_VALUE', () => {
    const okProtect = request('PROTECT_APPLICATION', { applicationBytes: bytes(6) });
    const okOpen = request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) });
    const malformed = [
      ['non-integer currentEpoch', okOpen, { ...unreachable(9, 3), currentEpoch: 9.5 }, 'INVALID_REQUEST'],
      ['negative framingEpoch', okOpen, { ...unreachable(9, -1) }, 'INVALID_REQUEST'],
      ['non-number framingEpoch', okOpen, { ...unreachable(9, '3') }, 'INVALID_REQUEST'],
      ['out-of-set authentication', okOpen, openObservation(1, { authentication: 'MAYBE' }), 'UNKNOWN_VALUE'],
      ['out-of-set replayIdentity', okOpen, openObservation(1, { replayIdentity: 'MAYBE' }), 'UNKNOWN_VALUE'],
      ['out-of-set commitOutcome', okProtect, protectObservation('MAYBE'), 'UNKNOWN_VALUE'],
      ['missing observation member', okOpen, { currentEpoch: 9, framingEpoch: 9 }, 'INVALID_REQUEST'],
      ['observation member set of the other operation', okProtect, openObservation(1), 'UNKNOWN_FIELD'],
      ['unknown observation member', okProtect, { ...protectObservation(), extra: 1 }, 'UNKNOWN_FIELD'],
      ['unknown staged member', okProtect, { ...protectObservation(), stagedOutput: { other: bytes(6) } }, 'UNKNOWN_FIELD'],
      ['non-byte staged output', okProtect, { ...protectObservation(), stagedOutput: { protectedApplicationBytes: 'bytes' } }, 'INVALID_REQUEST'],
      ['empty operation identity', okProtect, protectObservation('COMMITTED', bytes(6), ''), 'INVALID_REQUEST'],
      ['reachable open without the commit trio', okOpen,
        { currentEpoch: 9, framingEpoch: 9, authentication: 'AUTHENTICATED', replayIdentity: 'UNSEEN', commitOutcome: null, operationIdentity: null, stagedOutput: null }, 'INVALID_REQUEST'],
      ['unknown request input member', request('PROTECT_APPLICATION', { protectedApplicationMessage: bytes(6) }), protectObservation(), 'UNKNOWN_FIELD'],
      ['unknown request member', request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { extra: 1 }), protectObservation(), 'UNKNOWN_FIELD'],
    ];
    for (const [label, req, observation, expected] of malformed) {
      const result = invoke(req, active(), observation);
      expect([label, result.kind, code(result)]).toEqual([label, 'REJECTED', expected]);
      expect(Object.hasOwn(result, 'output')).toBe(false);
      expect(result.stateAfter).toBe(result.stateBefore);
    }
  });

  test('a foreign profile, a drifted profile or a bad bindingRef is P02 or P03', () => {
    const cases = [
      ['foreign api constant', request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }, { api: 'styx-m2-session-adapter/v2' }), openObservation(1), 'UNSUPPORTED_API_VERSION'],
      ['drifted profile', request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { profile: { ...PROFILE, topology: 'two-member' } }), protectObservation(), 'UNSUPPORTED_PROFILE'],
      ['unknown profile member', request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { profile: { ...PROFILE, extra: 1 } }), protectObservation(), 'UNSUPPORTED_PROFILE'],
      ['empty bindingRef', request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { bindingRef: new Uint8Array(0) }), protectObservation(), 'BINDING_MISMATCH'],
      ['over-bound bindingRef', request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { bindingRef: bytes(BOUNDS.MAX_BINDING_REF_BYTES + 1) }), protectObservation(), 'BINDING_MISMATCH'],
    ];
    for (const [label, req, observation, expected] of cases) {
      const result = invoke(req, active(), observation);
      expect([label, code(result)]).toEqual([label, expected]);
    }
  });

  test('a request that is not a record shapes no result at all', () => {
    expect(() => invokeAdapter({ request: 'not-a-record', snapshot: active(), observation: protectObservation() }))
      .toThrow(M2AdapterError);
  });
});

describe('I-MSG closed result envelope, purity and immutability', () => {
  test('every result is a closed C-API record with exactly the members of its kind', () => {
    const kindRequired = {
      SUCCESS: ['successCode'],
      NO_CHANGE: ['successCode'],
      NOT_COMMITTED: ['commitOutcome'],
      INDETERMINATE: ['commitOutcome', 'reconciliationRef', 'originalStateBefore'],
      REJECTED: ['error'],
    };
    const common = ['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter'];
    const results = [
      invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }), active(), protectObservation()),
      invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }), active(), protectObservation('NOT_COMMITTED')),
      invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }), active(), protectObservation('INDETERMINATE')),
      invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(), openObservation(5)),
      invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
        openObservation(1, { replayIdentity: 'DUPLICATE', commitOutcome: null, staged: null })),
      invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(), unreachable(9, 3)),
    ];
    for (const result of results) {
      expect(Object.isFrozen(result)).toBe(true);
      const required = kindRequired[result.kind];
      const optional = result.kind === 'SUCCESS'
        ? ['output', 'commitOutcome']
        : result.kind === 'REJECTED' ? [] : [];
      const allowed = new Set([...common, ...required, ...optional]);
      for (const key of Object.keys(result)) expect([result.kind, key, allowed.has(key)]).toEqual([result.kind, key, true]);
      for (const key of [...common, ...required]) expect(Object.hasOwn(result, key)).toBe(true);
      if (result.kind === 'REJECTED') {
        expect(Object.keys(result.error)).toEqual(['code']);
      }
      if (result.kind === 'SUCCESS' && result.commitOutcome !== undefined) {
        expect(result.commitOutcome).toBe('COMMITTED');
      }
    }
  });

  test('the released output is a copy, never an alias of the injected staged bytes', () => {
    const staged = bytes(6, 0x77);
    const result = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      openObservation(0, { staged }));
    result.output.applicationBytes[0] = 0x00;
    expect(staged[0]).toBe(0x77);
    const again = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
      openObservation(0, { staged }));
    expect(again.output.applicationBytes[0]).toBe(0x77);
  });

  test('the call mutates neither the request, the snapshot nor the observation', () => {
    const req = request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) });
    const snapshot = active();
    const observation = openObservation(4);
    const before = JSON.stringify({ req, observation, snapshot });
    invokeAdapter({ request: req, snapshot, observation });
    expect(JSON.stringify({ req, observation, snapshot })).toBe(before);
    expect(Object.isFrozen(snapshot)).toBe(true);
  });

  test('a tampered observation or snapshot fails closed instead of inventing a result', () => {
    const accessor = protectObservation();
    Object.defineProperty(accessor, 'commitOutcome', { get: () => 'COMMITTED', enumerable: true });
    const fromAccessor = invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }), active(), accessor);
    expect(fromAccessor.error.code).toBe('INVALID_REQUEST');

    const badSnapshot = invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }), { state: 'ACTIVE' }, protectObservation());
    expect(badSnapshot.error.code).toBe('INVALID_REQUEST');

    // A snapshot whose `state` cannot be read at all shapes no result: the module's single error class
    // is the only outcome, exactly as `invokeAdapterTransition` documents.
    expect(() => invoke(request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }),
      { state: 'ARCHIVED', held: null }, protectObservation())).toThrow(M2AdapterError);
  });
});

describe('I-MSG total precedence over the message surface', () => {
  test('the derived code is the highest-precedence applicable one, typed independently', () => {
    // The oracle below is typed from the contract's precedence table, not from the module.
    const level = {
      UNKNOWN_FIELD: 1, INVALID_REQUEST: 1, UNKNOWN_VALUE: 1,
      UNSUPPORTED_API_VERSION: 2, UNSUPPORTED_PROFILE: 3, BINDING_MISMATCH: 3, UNSUPPORTED_OPERATION: 4,
      RECONCILIATION_REQUIRED: 5, NO_ACTIVE_SESSION: 5, NO_STORED_SESSION: 5, SESSION_ALREADY_EXISTS: 5,
      NO_RECONCILIATION_PENDING: 5, RECONCILIATION_REFERENCE_MISMATCH: 5,
      VALUE_OUT_OF_RANGE: 6, EPOCH_OUTSIDE_RETAINED_WINDOW: 7, FUTURE_EPOCH: 7,
      AUTHENTICATION_FAILED: 8, AUTHENTICATED_STATE_INCONSISTENT: 8,
      FAIL_CLOSED_INTERNAL: 10,
    };
    const cases = [
      ['window beats authentication', active(), request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
        unreachable(9, 3), 'EPOCH_OUTSIDE_RETAINED_WINDOW'],
      ['gate beats the window', empty(), request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
        unreachable(9, 3), 'NO_ACTIVE_SESSION'],
      ['gate beats the bound', empty(), request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
        unreachable(9, BOUNDS.MAX_FRAMING_EPOCH + 1), 'NO_ACTIVE_SESSION'],
      ['bound beats the window', active(), request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }),
        unreachable(9, BOUNDS.MAX_FRAMING_EPOCH + 1), 'VALUE_OUT_OF_RANGE'],
      ['shape beats everything', active(), request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { extra: 1 }),
        protectObservation(), 'UNKNOWN_FIELD'],
      ['profile beats the gate', empty(), request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { profile: { ...PROFILE, stage: 'x' } }),
        protectObservation(), 'UNSUPPORTED_PROFILE'],
      ['binding beats the gate', empty(), request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }, { bindingRef: new Uint8Array(0) }),
        protectObservation(), 'BINDING_MISMATCH'],
      ['unknown value beats the gate', empty(), request('PROTECT_APPLICATION', { applicationBytes: bytes(6) }),
        protectObservation('MAYBE'), 'UNKNOWN_VALUE'],
    ];
    for (const [label, snapshot, req, observation, expected] of cases) {
      const result = invoke(req, snapshot, observation);
      expect([label, code(result)]).toEqual([label, expected]);
      expect(level[code(result)]).toBeLessThanOrEqual(level[expected]);
    }
  });
});

describe('I-MSG seeded property sweep (C-RET window and closed envelope)', () => {
  test('every distance classifies exactly as the ratified window rule states', () => {
    fc.assert(fc.property(
      fc.integer({ min: 0, max: BOUNDS.MAX_FRAMING_EPOCH - 1 }),
      fc.integer({ min: 0, max: 12 }),
      (currentEpoch, distance) => {
        const framingEpoch = currentEpoch - distance;
        if (framingEpoch < 0) return true;
        const inWindow = distance <= RETENTION.PAST_EPOCHS_ONCE_AVAILABLE;
        const observation = inWindow
          ? openObservation(distance, { currentEpoch })
          : unreachable(currentEpoch, framingEpoch);
        const result = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(), observation);
        if (inWindow) {
          expect(result.successCode).toBe('APPLICATION_OPENED');
          expect(result.commitOutcome).toBe('COMMITTED');
        } else {
          expect(result.error.code).toBe('EPOCH_OUTSIDE_RETAINED_WINDOW');
        }
        return true;
      },
    ), { numRuns: 200, seed: 41101 });
  });

  test('every future epoch classifies as FUTURE_EPOCH', () => {
    fc.assert(fc.property(
      fc.integer({ min: 0, max: 1000 }),
      fc.integer({ min: 1, max: 1000 }),
      (currentEpoch, ahead) => {
        const framingEpoch = currentEpoch + ahead;
        if (framingEpoch > BOUNDS.MAX_FRAMING_EPOCH) return true;
        const result = invoke(request('OPEN_APPLICATION', { protectedApplicationMessage: bytes(6) }), active(),
          unreachable(currentEpoch, framingEpoch));
        expect(result.error.code).toBe('FUTURE_EPOCH');
        return true;
      },
    ), { numRuns: 200, seed: 41102 });
  });

  test('every accepted message releases exactly the staged bytes and no other member', () => {
    fc.assert(fc.property(
      fc.integer({ min: 1, max: 32 }),
      fc.integer({ min: 0, max: 5 }),
      fc.constantFrom('PROTECT_APPLICATION', 'OPEN_APPLICATION'),
      (length, distance, operation) => {
        const staged = bytes(length, 0x21);
        const observation = operation === 'PROTECT_APPLICATION'
          ? protectObservation('COMMITTED', staged)
          : openObservation(distance, { staged });
        const input = operation === 'PROTECT_APPLICATION'
          ? { applicationBytes: bytes(5) }
          : { protectedApplicationMessage: bytes(5) };
        const result = invoke(request(operation, input), active(), observation);
        expect(result.kind).toBe('SUCCESS');
        const member = operation === 'PROTECT_APPLICATION' ? 'protectedApplicationBytes' : 'applicationBytes';
        expect(Object.keys(result.output)).toEqual([member]);
        expect([...result.output[member]]).toEqual([...staged]);
        return true;
      },
    ), { numRuns: 100, seed: 41103 });
  });
});

describe('I-MSG O-SCEN mapping', () => {
  test('every mapped scenario id has the ratified O-SCEN identifier shape', () => {
    expect(MAPPED_SCENARIO_IDS.length).toBeGreaterThan(180);
    for (const id of MAPPED_SCENARIO_IDS) expect(id).toMatch(/^OSC-[0-9a-f]{16}$/);
    expect(new Set(MAPPED_SCENARIO_IDS).size).toBe(MAPPED_SCENARIO_IDS.length);
  });

  test('the clause pointers this card implements are all mapped', () => {
    for (const pointer of [
      '/decisionRows', '/stateMatrix', '/errorDefinitions', '/errorCodeEnum', '/codeToResultKind',
      '/precedenceLevels', '/precedencePairs', '/withinLevelErrorOrder', '/withinLevelPrecedencePairs',
      '/errorPrecedenceLevel', '/resultKindEnum', '/successCodeEnum', '/commitOutcomeEnum',
      '/rules/framingEpochBeforeAuthentication', '/rules/replayOrder', '/rules/rsTriState',
      '/rules/payloadRelease', '/rules/internalFailureBoundary', '/rules/completeLogicalMutation',
      '/rules/derivedFacts', '/profile/pastEpochWindow', '/request/inputByOperation',
      '/response/byKind', '/response/outputBySuccessCode',
      'C-RET/epochRule', 'C-RET/materialClasses/REPLAY_WINDOW_STATE',
      'C-RET/lifecycleMatrix/REPLAY_WINDOW_STATE',
    ]) {
      expect([pointer, OSCEN_SCENARIOS[pointer].length > 0]).toEqual([pointer, true]);
    }
  });

  test('the message rows of the window and replay surface are mapped to a named test above', () => {
    const named = {
      CAPI_S009: 'OSC-039d2541ca381eb6',
      CAPI_S010: 'OSC-272164b3f6ced9b4',
      CAPI_S011: 'OSC-f2d864ee58cc0784',
      CAPI_S012: 'OSC-b92a2b9a90af255f',
      CAPI_S013: 'OSC-040428778da7f360',
      CAPI_E009: 'OSC-2952347fd5206190',
      CAPI_E014: 'OSC-5a23d7268d61c6c1',
      CAPI_E015: 'OSC-2defa736cbf8c637',
      CAPI_E016: 'OSC-41e4cc342bd76c87',
      CAPI_E017: 'OSC-12188dbbddee170f',
      CRET_window: 'OSC-9ed400b7a6602e62',
    };
    for (const [name, id] of Object.entries(named)) {
      expect([name, MAPPED_SCENARIO_IDS.includes(id)]).toEqual([name, true]);
    }
  });
});
