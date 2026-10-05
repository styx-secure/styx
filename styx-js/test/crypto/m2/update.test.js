// update.test.js — I-UPD conformance tests for the M2 staged self-update and commit integration
// (contract Issue #415 of #317 G-SCOPE, revision R1).
//
// The tests drive the real `invokeAdapter` over the injected request, snapshot and owning-layer
// observation: the exact SELF_UPDATE staged outcomes (a staged mutation is applied only after the
// owning layer reports COMMITTED, and is never applied on a blind retry), the ambiguity reconciliation
// of RECONCILE_INDETERMINATE including the released RECONCILED_COMMITTED output, the fail-closed request
// validation, the total C-API precedence, the closed result envelope, purity and immutability, and a
// seeded property sweep. Nothing is mocked: the decision is taken by the merged I-SM decision core, and
// the hold the reconciliation resolves is produced by that same merged core.

import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  M2_ADAPTER,
  M2AdapterError,
  invokeAdapter,
  invokeAdapterTransition,
  validateAdapterRequest,
} from '../../../src/crypto/mls/m2/adapter.js';
import { createAdapterSnapshot, transitionAdapter } from '../../../src/crypto/mls/m2/state-machine.js';

// The ratified O-SCEN scenario rows that cite each clause of this card's slice, addressed exactly the
// way the ratified clause registry addresses them: an unrepeated clause by its pointer, a repeated row
// by its pointer and index.
const OSCEN_SCENARIOS = {
  '/stateEnum': [
    'OSC-4f3aee29ce90e515', 'OSC-4fdb61c9157940c6', 'OSC-fe345e8b2cbf86a0',
  ],
  '/operationEnum': [
    'OSC-0500d80b6edd43d3', 'OSC-3ebdc9b549cb083b', 'OSC-3ec84ecc3d97a9bb', 'OSC-c0044deacda4755c',
    'OSC-d091e02e83d3440f', 'OSC-e5eafaf7080ebadb', 'OSC-f25e07c2cfe9ef54', 'OSC-fd1692d4b0742c06',
  ],
  '/commitOutcomeEnum': [
    'OSC-06351931f9565a4f', 'OSC-b838434c7a3aca50', 'OSC-cb6c0a14b126b79d',
  ],
  '/resultKindEnum': [
    'OSC-075f5520e0590d5c', 'OSC-3d9b7da2d4b40760', 'OSC-5a12253a1b94ba5c', 'OSC-9328985a79604cd9',
    'OSC-ed39d6a987385472',
  ],
  '/successCodeEnum': [
    'OSC-07f623df120e3185', 'OSC-11e5567a07066948', 'OSC-2c16d4de187cc4c7', 'OSC-35bc709df10f1678',
    'OSC-468ba4c368267b67', 'OSC-66ad56eda1ee122d', 'OSC-96f48e740ab1a1fb', 'OSC-eacfdc77b80c8a9f',
    'OSC-ef7ecc2413367875', 'OSC-f5228b30a34575bd',
  ],
  '/errorCodeEnum': [
    'OSC-063fc148c5c04141', 'OSC-0a2b86a4d9a82631', 'OSC-0b9e292740aa5a4f', 'OSC-0f07564a4d760568',
    'OSC-12279c4c75df3edf', 'OSC-1645969ce33304bc', 'OSC-3b06ac58d84b16eb', 'OSC-3c4f12b401aad67a',
    'OSC-43a45fcd05c5ec34', 'OSC-474416f91a5f4536', 'OSC-4b12bcf17ffa24f6', 'OSC-586c1d231b5c8008',
    'OSC-5b90530783018a77', 'OSC-6844abf9cf66be2b', 'OSC-69d537456a74ad7f', 'OSC-6b74356080755ec3',
    'OSC-771a222317da5140', 'OSC-8659e372e5836c35', 'OSC-9069cadd07ca854e', 'OSC-a085ba7e6260d7f1',
    'OSC-a99ab800bf228ea1', 'OSC-c70e41ad3bc5c2a3', 'OSC-cac04f870e530272', 'OSC-cd489d835b771f15',
    'OSC-f1c5d4ce4ea381e8',
  ],
  '/codeToResultKind': [
    'OSC-10e48bd21871e3ea', 'OSC-1657f97e7188028a', 'OSC-1b52765282159986', 'OSC-1f2bb6258d7ce675',
    'OSC-25242934bdd6ada6', 'OSC-2e491dff10c7033c', 'OSC-354dcdaff1f70a2e', 'OSC-390aa486bbfbab3b',
    'OSC-3f680f8750f81cf1', 'OSC-40889223667af929', 'OSC-4621a77987b57dfe', 'OSC-4a35f605fe18b4a1',
    'OSC-4addb8b8ac2df912', 'OSC-5ebf1c313821391a', 'OSC-6b26bea3a03cebc8', 'OSC-6dce17d6d6be15e5',
    'OSC-7eae050b0a74a6f8', 'OSC-84f20ffa1e94f592', 'OSC-8ae8b1a3906a9f71', 'OSC-8b30af2af9cfb39d',
    'OSC-952677fd636b2000', 'OSC-9b2d58abd5977e0d', 'OSC-9cda0c51a2eed7ca', 'OSC-ab6cf35c9b941722',
    'OSC-af6b40d35ad49c9d', 'OSC-b921ef10edae9564', 'OSC-bac934099642a48d', 'OSC-bb83d3f5d456d1dd',
    'OSC-beacf30e9803e7b5', 'OSC-c674b07f80aee1e4', 'OSC-cc89198a396c9326', 'OSC-cdfca40fd472b435',
    'OSC-d7dc6a8f3979ed1d', 'OSC-dac7a67b04490d26', 'OSC-ec27a4cc334ae142', 'OSC-f159789353f61495',
    'OSC-f8ff5f7899704255',
  ],
  '/request/closedObjects': [
    'OSC-c1e032420c68d1d0',
  ],
  '/request/commonRequired': [
    'OSC-34717e0650a28b4c',
  ],
  '/request/commonOptional': [
    'OSC-fb4395910e1fdfa1',
  ],
  '/request/fieldSources': [
    'OSC-4ca49839a31c9dcf',
  ],
  '/request/inputByOperation': [
    'OSC-ee1310a7fcd443b8',
  ],
  '/request/derivedByOperation': [
    'OSC-50af871720d5f00c',
  ],
  '/response/closedObjects': [
    'OSC-3c5dcaed0207d185',
  ],
  '/response/commonRequired': [
    'OSC-b1a4b4e879fb2e12',
  ],
  '/response/byKind': [
    'OSC-c99986582316e23c',
  ],
  '/response/outputBySuccessCode': [
    'OSC-345d9f9fb61f4c7a',
  ],
  '/response/errorShape': [
    'OSC-5db832538f6984b7',
  ],
  '/response/valueDomains': [
    'OSC-5607d7e9474401de',
  ],
  '/rules/closedObjects': [
    'OSC-a9bb2f1b3a69082e',
  ],
  '/rules/derivedFacts': [
    'OSC-9ebe2108b66fc218',
  ],
  '/rules/tupleDrift': [
    'OSC-f059cf9976ae30d3',
  ],
  '/rules/payloadRelease': [
    'OSC-ab20fdebafb24483',
  ],
  '/rules/rsTriState': [
    'OSC-f4eb5de98aefe7dc',
  ],
  '/rules/internalFailureBoundary': [
    'OSC-c614c21efa1f19d6',
  ],
  '/rules/completeLogicalMutation': [
    'OSC-3ba76ad1910efd14',
  ],
  '/stateMatrix': [
    'OSC-03d9a9914b0aa6c4', 'OSC-04cc18f5934cb614', 'OSC-1a5ac71a14b6b3ea', 'OSC-2559bdde274878e9',
    'OSC-39f5831aba2cb933', 'OSC-3d08d077a759b43c', 'OSC-490c11eabc04d0b6', 'OSC-4b2bc74448d755d4',
    'OSC-5879284d84662a5b', 'OSC-5e4b4f69bf36b2e2', 'OSC-6a89d2539e9323e8', 'OSC-7aeb35e0703ace8d',
    'OSC-7e0a44009fea4c91', 'OSC-813ba28ed4fa1072', 'OSC-88ab7ef8dfc4998e', 'OSC-999ca4ee68894598',
    'OSC-a0c0ba1c1bb9dbed', 'OSC-b31a7602b8ed7c0d', 'OSC-b5dbbc218723ba6e', 'OSC-b938a01aeeeb69f8',
    'OSC-cc40e3d2750829be', 'OSC-d01172590b30f22d', 'OSC-e1602f637d6bd551', 'OSC-f89aee5d6c2a5235',
  ],
  '/errorDefinitions': [
    'OSC-075218d7cf4958d0', 'OSC-0a6573f71323f697', 'OSC-0c2d21f78631ec52', 'OSC-12188dbbddee170f',
    'OSC-1304b0262b1c5f08', 'OSC-143d5356e170e76c', 'OSC-160c3b0b1bbb8309', 'OSC-20663d6756e478a4',
    'OSC-23f4224e49ce99b3', 'OSC-2952347fd5206190', 'OSC-2a4cf6991a457a27', 'OSC-2b7cba3d479f2318',
    'OSC-2c7066d394ceec80', 'OSC-2d1e6b9cd9f1ecd4', 'OSC-2defa736cbf8c637', 'OSC-38aacc4880942f46',
    'OSC-3d62b1fb54b069e9', 'OSC-3f1d822dd29c393e', 'OSC-3f36374b8bae239d', 'OSC-41e4cc342bd76c87',
    'OSC-497c363912fc16c2', 'OSC-4cfcefe728175e37', 'OSC-576a83b2905271ce', 'OSC-5a23d7268d61c6c1',
    'OSC-5a69e9106a316e88', 'OSC-5efc889dd9d7b6a0', 'OSC-5efcc44127a81d97', 'OSC-6d899c0dd8c8c5cb',
    'OSC-6df1f2080ee597fc', 'OSC-70b7fae75b80fac5', 'OSC-73dd6c675f25d4c2', 'OSC-7fe68b37a64e9461',
    'OSC-84848d3cff7d2461', 'OSC-8c742173c8ab9e35', 'OSC-8f64d7f15a9502c0', 'OSC-90be0d82d765c004',
    'OSC-94e54b0219758a75', 'OSC-9aecbdd630e37ebd', 'OSC-9cc6537bff47ca11', 'OSC-9d3265b0d0399ef3',
    'OSC-a303d0a9a24ac5f2', 'OSC-a4ffb8eca560a9c8', 'OSC-a80635925054fad2', 'OSC-ac1baeb760fb0b1a',
    'OSC-b02cff0c70ba6515', 'OSC-b1a72075ac9b9c7a', 'OSC-b9f6a13d5b3c2234', 'OSC-c74132fb4566fea6',
    'OSC-cbfc35050b8602c5', 'OSC-d05cb2c4e3aac4e8', 'OSC-d645f4333e04879a', 'OSC-d9b31298a88d6576',
    'OSC-ddb258d94bae8c2a', 'OSC-e1287f7d943968a6', 'OSC-eb0ed4b75a40c4b3', 'OSC-ef59d18a4ce3cdb1',
    'OSC-f07a5e2af1a93cd8', 'OSC-f549863071797926', 'OSC-f71e534b1a2b9010', 'OSC-fb2d97624aa42de6',
    'OSC-fc317294a228e607',
  ],
  '/decisionRows': [
    'OSC-039d2541ca381eb6', 'OSC-040428778da7f360', 'OSC-0518d6785e092556', 'OSC-058cecc46b3d0977',
    'OSC-0d238b5685352693', 'OSC-0df5460505e0acc8', 'OSC-14d92ef35229b3d6', 'OSC-272164b3f6ced9b4',
    'OSC-275ff10dd95b8749', 'OSC-3dbc018c5e9fa76d', 'OSC-43bc2f410abce99b', 'OSC-4e6a91e8fd134c5c',
    'OSC-7298412dac6a8db3', 'OSC-826a906dac4be842', 'OSC-850b3351c75edb32', 'OSC-8c6cb835dd99eeb9',
    'OSC-9b8a5675ff85958e', 'OSC-a2300e08707a1c8e', 'OSC-af5c083231282006', 'OSC-b47a46933e3605fb',
    'OSC-b92a2b9a90af255f', 'OSC-ba40377fe5ae100a', 'OSC-bd2e673b58578db7', 'OSC-c7441026f4b0594f',
    'OSC-c90d3d132707cad8', 'OSC-cc9a837e6088df51', 'OSC-f2d864ee58cc0784', 'OSC-fad188643ebbc91a',
    'OSC-ff63831313f3870f',
  ],
  '/precedenceLevels': [
    'OSC-083a62592fa04606', 'OSC-0aab84c36275f501', 'OSC-15755d061cb96701', 'OSC-15d96acfe2d80d43',
    'OSC-164989757382dd57', 'OSC-1901a15c562e5c59', 'OSC-19e2400fbc9e2f7f', 'OSC-1cde371be9245ff8',
    'OSC-2163ae083f60c441', 'OSC-250fdf9db244f6e1', 'OSC-27678dd5154b0a6f', 'OSC-29f6b1c388b7ea01',
    'OSC-2a86c1aa16784117', 'OSC-3ae47a4851dc2e3e', 'OSC-3b9d3951675612c3', 'OSC-42b26f28b5b8c11f',
    'OSC-47b69b23744eb610', 'OSC-53d9659868b96955', 'OSC-5636bcaaf498a6bb', 'OSC-58f848756d799582',
    'OSC-597eb7a08f3f5ae8', 'OSC-5c9f6f58dfb91b9a', 'OSC-5f4a158a65910625', 'OSC-62e85471317a3643',
    'OSC-68dfd12221f1dceb', 'OSC-6b6448cdca9f01e1', 'OSC-6eed768248fb4140', 'OSC-70b4b8d534f06f06',
    'OSC-70bda9c66d781c0a', 'OSC-728237b7ef35a19f', 'OSC-7685c33ee5c32fbe', 'OSC-787d65fd1fceaab1',
    'OSC-8052bfbff121307a', 'OSC-8c9800c0135d2c39', 'OSC-966d74434e2e31da', 'OSC-9bade26fa51b61df',
    'OSC-9d5176567b59994c', 'OSC-9edd8c5c05aeaada', 'OSC-a418788aa5cd621b', 'OSC-a785e564d9ed93aa',
    'OSC-b0911ed4ac462113', 'OSC-ba0c9d77b57b06e4', 'OSC-bef062dd8bf31923', 'OSC-c4dc19f2ce3cecbb',
    'OSC-cc63c689753a78be', 'OSC-d332f411ec3df901', 'OSC-d7e9e7c61a7d4d7c', 'OSC-dbaa212f731ca3d1',
    'OSC-decf78a54b7b1e02', 'OSC-e073c1b7646d82c3', 'OSC-e63e61cc3feef036', 'OSC-e9df1e05c89ad52b',
    'OSC-e9fa5890f68962d5', 'OSC-ec51ce85abe4d613', 'OSC-ef141954680bdff6',
  ],
  '/precedencePairs': [
    'OSC-083a62592fa04606', 'OSC-0aab84c36275f501', 'OSC-15755d061cb96701', 'OSC-15d96acfe2d80d43',
    'OSC-1901a15c562e5c59', 'OSC-1cde371be9245ff8', 'OSC-2163ae083f60c441', 'OSC-250fdf9db244f6e1',
    'OSC-29f6b1c388b7ea01', 'OSC-2a86c1aa16784117', 'OSC-3ae47a4851dc2e3e', 'OSC-3b9d3951675612c3',
    'OSC-42b26f28b5b8c11f', 'OSC-47b69b23744eb610', 'OSC-597eb7a08f3f5ae8', 'OSC-5c9f6f58dfb91b9a',
    'OSC-5f4a158a65910625', 'OSC-62e85471317a3643', 'OSC-68dfd12221f1dceb', 'OSC-6b6448cdca9f01e1',
    'OSC-6eed768248fb4140', 'OSC-70b4b8d534f06f06', 'OSC-70bda9c66d781c0a', 'OSC-7685c33ee5c32fbe',
    'OSC-787d65fd1fceaab1', 'OSC-8052bfbff121307a', 'OSC-966d74434e2e31da', 'OSC-9bade26fa51b61df',
    'OSC-9d5176567b59994c', 'OSC-9edd8c5c05aeaada', 'OSC-a418788aa5cd621b', 'OSC-a785e564d9ed93aa',
    'OSC-b0911ed4ac462113', 'OSC-ba0c9d77b57b06e4', 'OSC-bef062dd8bf31923', 'OSC-c4dc19f2ce3cecbb',
    'OSC-cc63c689753a78be', 'OSC-d332f411ec3df901', 'OSC-dbaa212f731ca3d1', 'OSC-e073c1b7646d82c3',
    'OSC-e63e61cc3feef036', 'OSC-e9df1e05c89ad52b', 'OSC-e9fa5890f68962d5', 'OSC-ec51ce85abe4d613',
    'OSC-ef141954680bdff6',
  ],
  '/withinLevelPrecedencePairs': [
    'OSC-0c2d21f78631ec52', 'OSC-1304b0262b1c5f08', 'OSC-23f4224e49ce99b3', 'OSC-2a4cf6991a457a27',
    'OSC-2d1e6b9cd9f1ecd4', 'OSC-3d62b1fb54b069e9', 'OSC-3f1d822dd29c393e', 'OSC-497c363912fc16c2',
    'OSC-4cfcefe728175e37', 'OSC-576a83b2905271ce', 'OSC-5efcc44127a81d97', 'OSC-6df1f2080ee597fc',
    'OSC-7fe68b37a64e9461', 'OSC-8f64d7f15a9502c0', 'OSC-90be0d82d765c004', 'OSC-94e54b0219758a75',
    'OSC-9aecbdd630e37ebd', 'OSC-9cc6537bff47ca11', 'OSC-9d3265b0d0399ef3', 'OSC-a303d0a9a24ac5f2',
    'OSC-a4ffb8eca560a9c8', 'OSC-a80635925054fad2', 'OSC-ac1baeb760fb0b1a', 'OSC-b1a72075ac9b9c7a',
    'OSC-c74132fb4566fea6', 'OSC-cbfc35050b8602c5', 'OSC-d05cb2c4e3aac4e8', 'OSC-ddb258d94bae8c2a',
    'OSC-e1287f7d943968a6', 'OSC-eb0ed4b75a40c4b3', 'OSC-ef59d18a4ce3cdb1', 'OSC-f07a5e2af1a93cd8',
    'OSC-f549863071797926', 'OSC-f71e534b1a2b9010', 'OSC-fb2d97624aa42de6', 'OSC-fc317294a228e607',
  ],
  '/errorPrecedenceLevel': [
    'OSC-13ae3223856963a2', 'OSC-26959eb6cda340cc', 'OSC-3ffa570ffdbb3444', 'OSC-455ed401ea365633',
    'OSC-4810f39c5bc07249', 'OSC-48e236bea6b680e0', 'OSC-4da2461c2275fad7', 'OSC-52d4e213143725f1',
    'OSC-5e50eb0e8aaa3039', 'OSC-610eb473f38bb1eb', 'OSC-622fbc48a5af3c2c', 'OSC-62e6226df39afc45',
    'OSC-6be20f56334c2fdf', 'OSC-70cd0908f5a1c7c8', 'OSC-83fd0d157ad9e18b', 'OSC-84e509190eef7a3c',
    'OSC-9b4075b5f16056b9', 'OSC-9fa6fb524e13bff7', 'OSC-aa9b9cade9f142a5', 'OSC-cfc17f937b832911',
    'OSC-d89de75bd627a16d', 'OSC-e0a32a6a313b1d3e', 'OSC-e393e023695fcd07', 'OSC-e791cc282b67bb9d',
    'OSC-f3f7f0b398e81583',
  ],
  '/withinLevelErrorOrder': [
    'OSC-0522d7b7d3502cc4', 'OSC-05c0ea7a6d9c41d5', 'OSC-09a3cf2d025a6dd9', 'OSC-1859c445e4e6d986',
    'OSC-21212862d2094879', 'OSC-27ea6f777167d13f', 'OSC-785a8087bc9405af', 'OSC-a0a106063488b787',
    'OSC-c1ec8b0dfa28a1c4', 'OSC-d3ac6113a223451c',
  ],
  // per-row clauses addressed the way the ratified registry addresses them
  '/decisionRows/13': ['OSC-4e6a91e8fd134c5c'],
  '/decisionRows/14': ['OSC-ff63831313f3870f'],
  '/decisionRows/19': ['OSC-af5c083231282006'],
  '/decisionRows/20': ['OSC-cc9a837e6088df51'],
  '/decisionRows/21': ['OSC-c90d3d132707cad8'],
  '/decisionRows/22': ['OSC-c7441026f4b0594f'],
  '/decisionRows/23': ['OSC-7298412dac6a8db3'],
  '/decisionRows/27': ['OSC-b47a46933e3605fb'],
  '/stateMatrix/5': ['OSC-4b2bc74448d755d4'],
  '/stateMatrix/7': ['OSC-b31a7602b8ed7c0d'],
  '/stateMatrix/13': ['OSC-1a5ac71a14b6b3ea'],
  '/stateMatrix/15': ['OSC-999ca4ee68894598'],
  '/stateMatrix/21': ['OSC-a0c0ba1c1bb9dbed'],
  '/stateMatrix/23': ['OSC-d01172590b30f22d'],
  '/rules/rsTriState': ['OSC-f4eb5de98aefe7dc'],
  '/response/outputBySuccessCode': ['OSC-345d9f9fb61f4c7a'],
  '/response/byKind': ['OSC-c99986582316e23c'],
  '/request/derivedByOperation': ['OSC-50af871720d5f00c'],
  '/request/inputByOperation': ['OSC-ee1310a7fcd443b8'],
};

const MAPPING_SCHEMA = 'styx-m2-i-upd-scenario-mapping/v1';
const MAPPING_SHA256 = '441468618375144c479c8c7af4de60187eb28eba83620fee36e9896763cfd935';
// The pinned digest of the union of every O-SCEN id this slice cites, newline-joined and sorted.
const OSCEN_DIGEST = 'ebbb8002ac2f8ee12c96434988c2c410ca8715c7e950fad6b81785f6ccef77ac';
const sha256Of = (text) => createHash('sha256').update(text, 'utf8').digest('hex');
const MODULE_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../../../src/crypto/mls/m2/adapter.js');

const PROFILE = M2_ADAPTER.PROFILE;
const API = M2_ADAPTER.API;
const REQUEST_MEMBERS = ['api', 'operation', 'requestId', 'profile', 'bindingRef', 'input'];
const RESULT_COMMON_MEMBERS = ['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter'];

// C-BIND §4: the authoritative slot context of the session (the 32 nonzero `localContextId` bytes) the
// SS resolves for a session-bound operation, and the request `bindingRef` that names it.
const SLOT = new Uint8Array(32).fill(0xa1);
const OTHER_SLOT = new Uint8Array(32).fill(0xb2);

let counter = 0;
const request = (operation, input, overrides = {}) => ({
  api: API,
  operation,
  requestId: `req-iupd-${++counter}`,
  profile: { ...PROFILE },
  bindingRef: SLOT.slice(),
  input,
  ...overrides,
});

const bytes = (...values) => new Uint8Array(values);
const STAGED = bytes(0x11, 0x22, 0x33, 0x44);
const WELCOME = bytes(0x51, 0x52);

const empty = () => createAdapterSnapshot('EMPTY');
const active = () => createAdapterSnapshot('ACTIVE');

// The exact I-SM hold a reconciliation resolves: the hold of one held mutation, produced by the merged
// core itself and carrying the held row's original state, success code and C-MUT escrow kind.
const holdOf = (operation, snapshot, operationIdentity) => transitionAdapter(snapshot, {
  operation,
  applicableErrors: [],
  facts: 'SUPPORTED',
  commitOutcome: 'INDETERMINATE',
  operationIdentity,
}).snapshot;

const heldUpdate = (id = 'held-upd-1') => holdOf('SELF_UPDATE', active(), id);
const heldCreate = (id = 'held-create-1') => holdOf('CREATE', empty(), id);
const heldJoin = (id = 'held-join-1') => holdOf('JOIN_WELCOME', empty(), id);

const updateObservation = ({
  updateForm = 'SUPPORTED', commitOutcome = 'COMMITTED', stagedOutput = undefined, operationIdentity = undefined,
} = {}) => ({
  slotContext: SLOT.slice(),
  updateForm,
  commitOutcome,
  operationIdentity: operationIdentity === undefined ? (commitOutcome === null ? null : 'op-upd-1') : operationIdentity,
  stagedOutput: stagedOutput === undefined
    ? (commitOutcome === null ? null : { protectedCommitBytes: STAGED })
    : stagedOutput,
});

const reconcileObservation = ({ commitOutcome = 'COMMITTED', responseEmission = 'SUCCEEDED', heldOutput = undefined } = {}) => ({
  slotContext: SLOT.slice(),
  commitOutcome,
  responseEmission,
  heldOutput: heldOutput === undefined
    ? (commitOutcome === 'COMMITTED' ? { protectedCommitBytes: STAGED } : null)
    : heldOutput,
});

const code = (result) => (result.error === undefined ? undefined : result.error.code);

const assertEnvelope = (result, kind, extra) => {
  expect(Object.isFrozen(result)).toBe(true);
  const keys = Object.keys(result);
  for (const member of RESULT_COMMON_MEMBERS) expect(keys).toContain(member);
  expect(result.kind).toBe(kind);
  expect(keys.filter((key) => !RESULT_COMMON_MEMBERS.includes(key)).sort()).toEqual([...extra].sort());
};

const invoke = (operation, snapshot, observation, input = {}) => invokeAdapter({
  request: request(operation, input), snapshot, observation,
});
describe('I-UPD module surface and the widened closed sets', () => {
  test('the integrated operation set is this slice widened onto the merged base', () => {
    expect(M2_ADAPTER.API).toBe('styx-m2-session-adapter/v1');
    expect([...M2_ADAPTER.INTEGRATED_OPERATIONS]).toEqual([
      'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION', 'SELF_UPDATE',
      'RECONCILE_INDETERMINATE',
    ]);
    expect([...M2_ADAPTER.OPERATIONS]).toEqual([
      'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
      'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE',
    ]);
    expect(Object.isFrozen(M2_ADAPTER.INTEGRATED_OPERATIONS)).toBe(true);
  });

  test('the closed sets this slice adds are frozen and exact', () => {
    expect([...M2_ADAPTER.UPDATE_FORMS]).toEqual(['SUPPORTED', 'UNSUPPORTED_UPDATE_FORM']);
    expect({ ...M2_ADAPTER.STAGED_OUTPUT_BY_CODE }).toEqual({
      CREATED: 'embeddedTreeWelcome', SELF_UPDATED: 'protectedCommitBytes',
    });
    expect({ ...M2_ADAPTER.OUTPUT_MEMBER_BY_KIND }).toEqual({
      EMBEDDED_TREE_WELCOME: 'embeddedTreeWelcome',
      PROTECTED_COMMIT_BYTES: 'protectedCommitBytes',
      PROTECTED_APPLICATION_BYTES: 'protectedApplicationBytes',
      APPLICATION_BYTES: 'applicationBytes',
      SELECTED_CANDIDATE_REF: 'selectedCandidateRef',
    });
    expect(M2_ADAPTER.BOUNDS.MAX_RECONCILIATION_REF_CHARS).toBe(256);
    expect(M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES).toBe(1048576);
    expect([...M2_ADAPTER.COMMIT_OUTCOMES]).toEqual(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);
    expect([...M2_ADAPTER.SUCCESS_CODES]).toHaveLength(10);
    expect([...M2_ADAPTER.ERROR_CODES]).toHaveLength(25);
    expect(M2_ADAPTER.CODE_TO_KIND.SELF_UPDATED).toBe('SUCCESS');
    expect(M2_ADAPTER.CODE_TO_KIND.RECONCILED_COMMITTED).toBe('SUCCESS');
    expect(M2_ADAPTER.CODE_TO_KIND.RECONCILIATION_REFERENCE_MISMATCH).toBe('REJECTED');
    expect(M2_ADAPTER.CODE_TO_KIND.UNSUPPORTED_UPDATE_FORM).toBe('REJECTED');
    expect(M2_ADAPTER.CODE_TO_KIND.NOT_COMMITTED).toBe('NOT_COMMITTED');
    expect(M2_ADAPTER.CODE_TO_KIND.INDETERMINATE).toBe('INDETERMINATE');
  });

  test('the module still imports exactly the two merged modules and nothing else', () => {
    const source = readFileSync(MODULE_PATH, 'utf8');
    const specifiers = [...source.matchAll(/^\s*import\s[^;]*?from\s+'([^']+)'/gm)].map((match) => match[1]);
    expect(specifiers.sort()).toEqual([
      '../../../storage/m2/session-restore.js',
      './state-machine.js',
    ]);
    expect(/require\s*\(/.test(source)).toBe(false);
    // A static-import scan alone would miss a sneaky dynamic import, re-export or runtime require
    // factory, which is the escape hatch the closure claim actually cares about (review finding F4).
    expect(/[^\w.$]import\s*\(/.test(source)).toBe(false);
    expect(/export\s[^;]*?from\s+'/.test(source)).toBe(false);
    expect(/module\.createRequire|process\.binding|require\.resolve/.test(source)).toBe(false);
  });

  test('the ratified scenario mapping this slice cites is pinned and non-empty', () => {
    expect(MAPPING_SCHEMA).toBe('styx-m2-i-upd-scenario-mapping/v1');
    expect(MAPPING_SHA256).toBe('441468618375144c479c8c7af4de60187eb28eba83620fee36e9896763cfd935');
    const pointers = Object.keys(OSCEN_SCENARIOS);
    expect(pointers.length).toBeGreaterThan(40);
    for (const pointer of pointers) {
      expect(OSCEN_SCENARIOS[pointer].length).toBeGreaterThan(0);
      for (const id of OSCEN_SCENARIOS[pointer]) expect(id).toMatch(/^OSC-[0-9a-f]{16}$/);
    }
    const distinct = new Set(Object.values(OSCEN_SCENARIOS).flat());
    expect(distinct.size).toBe(314);
    // The union of the cited ids is pinned by digest, so the table cannot be replaced by a fabricated
    // set that merely matches the shape: the digest is the SHA-256 of the newline-joined, sorted ids of
    // every ratified O-SCEN row that cites a clause key addressed by this card's slice, derived from
    // `M2-I-UPD-SCENARIO-MAPPING.json` (sha256 above) by the generator in the card's workspace. The
    // ratified `docs/architecture/m2/scenarios/clause-scenarios.md` is not present in this tree, so the
    // mapping cannot be re-derived from the checkout alone; the generator and its inputs are named in
    // the PR that carries this file.
    expect(sha256Of([...distinct].sort().join('\n'))).toBe(OSCEN_DIGEST);
  });

  test('the exact ratified rows this slice decides are the ones the mapping cites', () => {
    expect(OSCEN_SCENARIOS['/decisionRows/13']).toEqual(['OSC-4e6a91e8fd134c5c']);
    expect(OSCEN_SCENARIOS['/decisionRows/14']).toEqual(['OSC-ff63831313f3870f']);
    expect(OSCEN_SCENARIOS['/decisionRows/19']).toEqual(['OSC-af5c083231282006']);
    expect(OSCEN_SCENARIOS['/decisionRows/20']).toEqual(['OSC-cc9a837e6088df51']);
    expect(OSCEN_SCENARIOS['/decisionRows/21']).toEqual(['OSC-c90d3d132707cad8']);
    expect(OSCEN_SCENARIOS['/decisionRows/22']).toEqual(['OSC-c7441026f4b0594f']);
    expect(OSCEN_SCENARIOS['/decisionRows/23']).toEqual(['OSC-7298412dac6a8db3']);
    expect(OSCEN_SCENARIOS['/decisionRows/27']).toEqual(['OSC-b47a46933e3605fb']);
    expect(OSCEN_SCENARIOS['/stateMatrix/5']).toEqual(['OSC-4b2bc74448d755d4']);
    expect(OSCEN_SCENARIOS['/stateMatrix/21']).toEqual(['OSC-a0c0ba1c1bb9dbed']);
    expect(OSCEN_SCENARIOS['/response/outputBySuccessCode']).toEqual(['OSC-345d9f9fb61f4c7a']);
    expect(OSCEN_SCENARIOS['/rules/rsTriState']).toEqual(['OSC-f4eb5de98aefe7dc']);
    expect(OSCEN_SCENARIOS['/request/derivedByOperation']).toEqual(['OSC-50af871720d5f00c']);
  });
});
describe('I-UPD a staged self-update is applied only after COMMITTED', () => {
  test('a supported staged update the owning layer reports COMMITTED is applied and releases the staged bytes', () => {
    const result = invoke('SELF_UPDATE', active(), updateObservation({}));
    assertEnvelope(result, 'SUCCESS', ['successCode', 'commitOutcome', 'output']);
    expect(result.api).toBe(API);
    expect(result.operation).toBe('SELF_UPDATE');
    expect(result.successCode).toBe('SELF_UPDATED');
    expect(result.commitOutcome).toBe('COMMITTED');
    expect(result.stateBefore).toBe('ACTIVE');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(Object.keys(result.output)).toEqual(['protectedCommitBytes']);
    expect(result.output.protectedCommitBytes).toEqual(STAGED);
    expect(result.output.protectedCommitBytes).not.toBe(STAGED);
    expect(Object.isFrozen(result.output)).toBe(true);
  });

  test('the entry point with the next snapshot returns the ACTIVE snapshot the caller must hold', () => {
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}), snapshot: active(), observation: updateObservation({}),
    });
    expect(Object.isFrozen(transition)).toBe(true);
    expect(Object.keys(transition).sort()).toEqual(['result', 'snapshot']);
    expect(transition.snapshot.state).toBe('ACTIVE');
    expect(transition.snapshot.held).toBe(null);
    expect(Object.isFrozen(transition.snapshot)).toBe(true);
  });

  test('a supported staged update the owning layer reports NOT_COMMITTED changes no state and releases nothing', () => {
    const result = invoke('SELF_UPDATE', active(), updateObservation({ commitOutcome: 'NOT_COMMITTED', stagedOutput: null }));
    assertEnvelope(result, 'NOT_COMMITTED', ['commitOutcome']);
    expect(code(result)).toBe(undefined);
    expect(result.commitOutcome).toBe('NOT_COMMITTED');
    expect(result.stateBefore).toBe('ACTIVE');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(result.successCode).toBe(undefined);
    expect(result.output).toBe(undefined);
  });

  test('a supported staged update the owning layer leaves INDETERMINATE is not applied and holds the mutation', () => {
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({ commitOutcome: 'INDETERMINATE', stagedOutput: null }),
    });
    assertEnvelope(transition.result, 'INDETERMINATE',
      ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(transition.result.commitOutcome).toBe('INDETERMINATE');
    expect(transition.result.stateBefore).toBe('ACTIVE');
    expect(transition.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(transition.result.originalStateBefore).toBe('ACTIVE');
    expect(transition.result.reconciliationRef).toBe('I-SM-HOLD:op-upd-1');
    expect(transition.result.successCode).toBe(undefined);
    expect(transition.result.output).toBe(undefined);
    expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(transition.snapshot.held.scenario).toBe('CAPI-S014');
    expect(transition.snapshot.held.expectedSuccessCode).toBe('SELF_UPDATED');
    expect(transition.snapshot.held.originalStateBefore).toBe('ACTIVE');
    expect(transition.snapshot.held.terminalEvidenceStatus).toBe('PENDING');
  });

  test('the held mutation is never retried blindly: a further staged update while it is held is refused', () => {
    const result = invoke('SELF_UPDATE', heldUpdate(), updateObservation({}));
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe('RECONCILIATION_REQUIRED');
    expect(result.stateBefore).toBe('RECONCILIATION_REQUIRED');
    expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
  });

  test('an unsupported update form is refused before any commit proof is consulted', () => {
    const refused = { slotContext: SLOT.slice(), updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: null, operationIdentity: null, stagedOutput: null };
    const active1 = invoke('SELF_UPDATE', active(), refused);
    assertEnvelope(active1, 'REJECTED', ['error']);
    expect(code(active1)).toBe('UNSUPPORTED_UPDATE_FORM');
    expect(active1.stateBefore).toBe('ACTIVE');
    expect(active1.stateAfter).toBe('ACTIVE');
    expect(code(invoke('SELF_UPDATE', empty(), refused))).toBe('NO_ACTIVE_SESSION');
    expect(code(invoke('SELF_UPDATE', heldUpdate(), refused))).toBe('RECONCILIATION_REQUIRED');
  });

  test('an unsupported update form with a staged output supplied still releases nothing', () => {
    const result = invoke('SELF_UPDATE', active(), {
      slotContext: SLOT.slice(),
      updateForm: 'UNSUPPORTED_UPDATE_FORM',
      commitOutcome: null,
      operationIdentity: null,
      stagedOutput: { protectedCommitBytes: STAGED },
    });
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe('UNSUPPORTED_UPDATE_FORM');
    expect(result.stateBefore).toBe('ACTIVE');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(result.output).toBe(undefined);
  });

  test('an unsupported update form with a malformed staged output is a P01 defect, not a typed outcome', () => {
    const result = invoke('SELF_UPDATE', active(), {
      slotContext: SLOT.slice(),
      updateForm: 'UNSUPPORTED_UPDATE_FORM',
      commitOutcome: null,
      operationIdentity: null,
      stagedOutput: { protectedCommitBytes: 7 },
    });
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe('INVALID_REQUEST');
  });

  test('a staged update the owning layer reports NOT_COMMITTED releases nothing even when bytes are handed over', () => {
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({ commitOutcome: 'NOT_COMMITTED' }),
    });
    assertEnvelope(transition.result, 'NOT_COMMITTED', ['commitOutcome']);
    expect(transition.result.successCode).toBe(undefined);
    expect(transition.result.output).toBe(undefined);
    expect(transition.result.stateBefore).toBe('ACTIVE');
    expect(transition.result.stateAfter).toBe('ACTIVE');
    expect(transition.snapshot.state).toBe('ACTIVE');
    expect(transition.snapshot.held).toBe(null);
  });

  test('a staged update the owning layer leaves INDETERMINATE applies nothing even when bytes are handed over', () => {
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({ commitOutcome: 'INDETERMINATE' }),
    });
    assertEnvelope(transition.result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(transition.result.successCode).toBe(undefined);
    expect(transition.result.output).toBe(undefined);
    expect(transition.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(transition.snapshot.held.expectedSuccessCode).toBe('SELF_UPDATED');
  });

  test('an escrow the owning layer cannot hand over after a commit report is held, never rejected', () => {
    for (const stagedOutput of [null, { protectedCommitBytes: 7 }, { embeddedTreeWelcome: WELCOME }]) {
      const transition = invokeAdapterTransition({
        request: request('SELF_UPDATE', {}),
        snapshot: active(),
        observation: updateObservation({ stagedOutput }),
      });
      assertEnvelope(transition.result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
      expect(transition.result.commitOutcome).toBe('INDETERMINATE');
      expect(transition.result.output).toBe(undefined);
      expect(transition.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
      expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    }
  });

  test('a staged update with no active session is refused', () => {
    const result = invoke('SELF_UPDATE', empty(), updateObservation({}));
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe('NO_ACTIVE_SESSION');
    expect(result.stateAfter).toBe('EMPTY');
  });

  test('a valid C-API operation outside this slice stays UNSUPPORTED_OPERATION', () => {
    const outside = [
      ['APPLY_PEER_UPDATE', { protectedCommitBytes: bytes(0x01) }],
      ['ADD_MEMBER', {}],
    ];
    for (const [operation, input] of outside) {
      const result = invokeAdapter({
        request: request(operation, input), snapshot: active(), observation: updateObservation({}),
      });
      expect(code(result)).toBe('UNSUPPORTED_OPERATION');
      expect(result.operation).toBe(operation);
      expect(result.stateAfter).toBe('ACTIVE');
    }
  });
});
const heldRef = (id) => `I-SM-HOLD:${id}`;
const reconcile = (snapshot, observation, reference) => invokeAdapter({
  request: request('RECONCILE_INDETERMINATE', { reconciliationRef: reference }),
  snapshot,
  observation,
});

describe('I-UPD ambiguity reconciles through RECONCILE_INDETERMINATE', () => {
  test('a committed self-update reconciles to ACTIVE and returns its held escrow under the original code', () => {
    const result = reconcile(heldUpdate(), reconcileObservation({}), heldRef('held-upd-1'));
    assertEnvelope(result, 'SUCCESS', ['successCode', 'output']);
    expect(result.successCode).toBe('RECONCILED_COMMITTED');
    expect(result.commitOutcome).toBe(undefined);
    expect(result.stateBefore).toBe('RECONCILIATION_REQUIRED');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(Object.keys(result.output)).toEqual(['originalSuccessCode', 'originalOutput']);
    expect(result.output.originalSuccessCode).toBe('SELF_UPDATED');
    expect(Object.keys(result.output.originalOutput)).toEqual(['protectedCommitBytes']);
    expect(result.output.originalOutput.protectedCommitBytes).toEqual(STAGED);
    expect(result.output.originalOutput.protectedCommitBytes).not.toBe(STAGED);
    expect(Object.isFrozen(result.output.originalOutput)).toBe(true);
  });

  test('an interrupted response emission still resolves the commit, and keeps the hold for the caller', () => {
    const transition = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }),
      snapshot: heldUpdate(),
      observation: reconcileObservation({ responseEmission: 'INTERRUPTED' }),
    });
    assertEnvelope(transition.result, 'SUCCESS', ['successCode', 'output']);
    expect(transition.result.successCode).toBe('RECONCILED_COMMITTED');
    expect(transition.result.stateAfter).toBe('ACTIVE');
    expect(transition.result.output.originalOutput.protectedCommitBytes).toEqual(STAGED);
    // The ratified C-API defines no `responseEmission` result member, so the adapter drops the merged
    // core's internal marker; the retained hold is observable through `invokeAdapterTransition`, whose
    // snapshot keeps `RECONCILIATION_REQUIRED` with the terminal evidence committed (C-MUT
    // `/reconciliation/interruptedCommittedReconciliationRepeat`).
    expect(transition.result.responseEmission).toBe(undefined);
    expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(transition.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
  });

  test('a committed create reconciles under its own original success code and escrow member', () => {
    const result = reconcile(heldCreate(),
      reconcileObservation({ heldOutput: { embeddedTreeWelcome: WELCOME } }), heldRef('held-create-1'));
    assertEnvelope(result, 'SUCCESS', ['successCode', 'output']);
    expect(result.successCode).toBe('RECONCILED_COMMITTED');
    expect(result.stateBefore).toBe('RECONCILIATION_REQUIRED');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(result.output.originalSuccessCode).toBe('CREATED');
    expect(result.output.originalOutput.embeddedTreeWelcome).toEqual(WELCOME);
  });

  test('a committed Welcome that holds no escrow reconciles with the empty closed original output', () => {
    // Owner act on #317 (2026-10-05, U1): `originalOutput` is the closed output object of the original
    // success code under C-API `/response/outputBySuccessCode`; `JOINED` lists no member, so it is `{}`.
    const result = reconcile(heldJoin(), reconcileObservation({ heldOutput: null }), heldRef('held-join-1'));
    assertEnvelope(result, 'SUCCESS', ['successCode', 'output']);
    expect(result.output.originalSuccessCode).toBe('JOINED');
    expect(result.output.originalOutput).toEqual({});
    expect(Object.getPrototypeOf(result.output.originalOutput)).toBe(Object.prototype);
    expect(Object.keys(result.output.originalOutput)).toEqual([]);
    expect(Object.isFrozen(result.output.originalOutput)).toBe(true);
  });

  test('a held mutation that can no longer commit returns to its original state and releases nothing', () => {
    const active1 = reconcile(heldUpdate(), reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), heldRef('held-upd-1'));
    assertEnvelope(active1, 'NOT_COMMITTED', ['commitOutcome']);
    expect(active1.commitOutcome).toBe('NOT_COMMITTED');
    expect(active1.stateBefore).toBe('RECONCILIATION_REQUIRED');
    expect(active1.stateAfter).toBe('ACTIVE');
    expect(active1.output).toBe(undefined);
    const empty1 = reconcile(heldCreate(), reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { embeddedTreeWelcome: WELCOME } }), heldRef('held-create-1'));
    assertEnvelope(empty1, 'NOT_COMMITTED', ['commitOutcome']);
    expect(empty1.stateAfter).toBe('EMPTY');
    expect(empty1.output).toBe(undefined);
  });

  test('a still ambiguous outcome stays held and re-emits the same reconciliation reference', () => {
    const transition = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }),
      snapshot: heldUpdate(),
      observation: reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }),
    });
    assertEnvelope(transition.result, 'INDETERMINATE',
      ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(transition.result.commitOutcome).toBe('INDETERMINATE');
    expect(transition.result.reconciliationRef).toBe(heldRef('held-upd-1'));
    expect(transition.result.originalStateBefore).toBe('ACTIVE');
    expect(transition.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(transition.result.output).toBe(undefined);
    expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(transition.snapshot.held.reconciliationRef).toBe(heldRef('held-upd-1'));
  });

  test('an unknown reconciliation reference is refused and the hold is kept', () => {
    const committed = reconcile(heldUpdate(), reconcileObservation({}), heldRef('some-other-hold'));
    assertEnvelope(committed, 'REJECTED', ['error']);
    expect(code(committed)).toBe('RECONCILIATION_REFERENCE_MISMATCH');
    expect(committed.stateBefore).toBe('RECONCILIATION_REQUIRED');
    expect(committed.stateAfter).toBe('RECONCILIATION_REQUIRED');
    const ambiguous = reconcile(heldUpdate(),
      reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }),
      heldRef('some-other-hold'));
    expect(code(ambiguous)).toBe('RECONCILIATION_REFERENCE_MISMATCH');
  });

  test('reconciliation with nothing pending is refused in ACTIVE and in EMPTY', () => {
    const nothing = reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: null });
    const act = reconcile(active(), nothing, heldRef('nothing-held'));
    assertEnvelope(act, 'REJECTED', ['error']);
    expect(code(act)).toBe('NO_RECONCILIATION_PENDING');
    expect(act.stateAfter).toBe('ACTIVE');
    const emp = reconcile(empty(), nothing, heldRef('nothing-held'));
    expect(code(emp)).toBe('NO_RECONCILIATION_PENDING');
    expect(emp.stateAfter).toBe('EMPTY');
  });

  test('the released held escrow is bounded exactly like the staged one', () => {
    const protectHold = holdOf('PROTECT_APPLICATION', active(), 'op-protect-1');
    expect(protectHold.held.outputKind).toBe('PROTECTED_APPLICATION_BYTES');
    // With no COMMITTED proof an out-of-bound held escrow is the P01 defect; with RS's COMMITTED proof it
    // is never released and the hold is retained instead (C-API `/rules/internalFailureBoundary`).
    const ambiguous = { commitOutcome: 'INDETERMINATE', responseEmission: null };
    const empty = reconcile(protectHold,
      reconcileObservation({ ...ambiguous, heldOutput: { protectedApplicationBytes: new Uint8Array(0) } }), heldRef('op-protect-1'));
    expect(code(empty)).toBe('INVALID_REQUEST');
    const overBound = reconcile(protectHold,
      reconcileObservation({ ...ambiguous, heldOutput: { protectedApplicationBytes: new Uint8Array(M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES + 1) } }),
      heldRef('op-protect-1'));
    expect(code(overBound)).toBe('INVALID_REQUEST');
    for (const bad of [new Uint8Array(0), new Uint8Array(M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES + 1)]) {
      const retained = reconcile(protectHold,
        reconcileObservation({ heldOutput: { protectedApplicationBytes: bad } }), heldRef('op-protect-1'));
      expect(retained.kind).toBe('INDETERMINATE');
      expect(retained.output).toBe(undefined);
      expect(retained.stateAfter).toBe('RECONCILIATION_REQUIRED');
    }
    const inBound = reconcile(protectHold,
      reconcileObservation({ heldOutput: { protectedApplicationBytes: bytes(0x01) } }), heldRef('op-protect-1'));
    expect(inBound.kind).toBe('SUCCESS');
    expect(inBound.output.originalSuccessCode).toBe('APPLICATION_PROTECTED');
    expect(inBound.output.originalOutput.protectedApplicationBytes).toEqual(bytes(0x01));
  });

  test('a repeat after the hold was cleared answers the ratified code even with durable RS evidence', () => {
    const durable = { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: null };
    const clearedPending = reconcile(active(), durable, heldRef('cleared-hold'));
    expect(code(clearedPending)).toBe('NO_RECONCILIATION_PENDING');
    expect(clearedPending.stateAfter).toBe('ACTIVE');
    const clearedEmpty = reconcile(empty(), durable, heldRef('cleared-hold'));
    expect(code(clearedEmpty)).toBe('NO_RECONCILIATION_PENDING');
    expect(clearedEmpty.stateAfter).toBe('EMPTY');
    const interrupted = reconcile(active(), { ...durable, responseEmission: 'INTERRUPTED' }, heldRef('cleared-hold'));
    expect(code(interrupted)).toBe('NO_RECONCILIATION_PENDING');
  });
});
const withoutMember = (record, key) => {
  const copy = { ...record };
  delete copy[key];
  return copy;
};

const withAccessor = (record, key, reads) => {
  const copy = { ...record };
  delete copy[key];
  Object.defineProperty(copy, key, {
    enumerable: true,
    get() { reads.count += 1; return typeof reads.value === 'function' ? reads.value() : reads.value; },
  });
  return copy;
};

describe('I-UPD fail-closed request validation', () => {
  const okUpdate = updateObservation({});
  const noProofReconcile = reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: null });
  // A well-formed, proof-bearing reconciliation observation: the reference check is then the defect the
  // case decides on, not the proof the no-proof observation is missing.
  const proofReconcile = reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } });

  const cases = [
    ['unknown request member', request('SELF_UPDATE', {}, { extra: 1 }), active(), okUpdate, 'UNKNOWN_FIELD'],
    ['missing request member', withoutMember(request('SELF_UPDATE', {}), 'bindingRef'), active(), okUpdate, 'INVALID_REQUEST'],
    ['non-byte bindingRef', request('SELF_UPDATE', {}, { bindingRef: 7 }), active(), okUpdate, 'INVALID_REQUEST'],
    ['empty bindingRef', request('SELF_UPDATE', {}, { bindingRef: new Uint8Array(0) }), active(), okUpdate, 'BINDING_MISMATCH'],
    ['over-bound bindingRef', request('SELF_UPDATE', {}, { bindingRef: new Uint8Array(4097) }), active(), okUpdate, 'BINDING_MISMATCH'],
    ['foreign api', request('SELF_UPDATE', {}, { api: 'styx-m2-session-adapter/v2' }), active(), okUpdate, 'UNSUPPORTED_API_VERSION'],
    ['drifted profile member', request('SELF_UPDATE', {}, { profile: { ...PROFILE, pastEpochWindow: PROFILE.pastEpochWindow + 1 } }), active(), okUpdate, 'UNSUPPORTED_PROFILE'],
    ['missing profile member', request('SELF_UPDATE', {}, { profile: withoutMember({ ...PROFILE }, 'adapterApi') }), active(), okUpdate, 'UNSUPPORTED_PROFILE'],
    ['unknown operation', request('ADD_MEMBER', {}), active(), okUpdate, 'UNSUPPORTED_OPERATION'],
    ['operation outside the slice', request('APPLY_PEER_UPDATE', { protectedCommitBytes: bytes(0x01) }), active(), okUpdate, 'UNSUPPORTED_OPERATION'],
    ['malformed input of an outside operation', request('APPLY_PEER_UPDATE', {}), active(), okUpdate, 'INVALID_REQUEST'],
    ['unknown input member', request('SELF_UPDATE', { extra: 1 }), active(), okUpdate, 'UNKNOWN_FIELD'],
    ['missing reconcile reference', request('RECONCILE_INDETERMINATE', {}), heldUpdate(), proofReconcile, 'INVALID_REQUEST'],
    ['empty reconcile reference', request('RECONCILE_INDETERMINATE', { reconciliationRef: '' }), heldUpdate(), proofReconcile, 'INVALID_REQUEST'],
    ['non-string reconcile reference', request('RECONCILE_INDETERMINATE', { reconciliationRef: 7 }), heldUpdate(), proofReconcile, 'INVALID_REQUEST'],
    ['non-closed observation', request('SELF_UPDATE', {}), active(), { ...okUpdate, extra: 1 }, 'UNKNOWN_FIELD'],
    ['reconciliation with no hold and no proof at all', request('RECONCILE_INDETERMINATE', { reconciliationRef: 'I-SM-HOLD:none' }), active(), noProofReconcile, 'NO_RECONCILIATION_PENDING'],
    ['missing observation member', request('SELF_UPDATE', {}), active(), withoutMember(okUpdate, 'operationIdentity'), 'INVALID_REQUEST'],
    ['out-of-set update form', request('SELF_UPDATE', {}), active(), { slotContext: SLOT.slice(), updateForm: 'PROPOSAL_FREE', commitOutcome: null, operationIdentity: null, stagedOutput: null }, 'UNKNOWN_VALUE'],
    ['out-of-set update form with a commit proof supplied', request('SELF_UPDATE', {}), active(), { ...okUpdate, updateForm: 'PROPOSAL_FREE' }, 'INVALID_REQUEST'],
    ['malformed staged output with an unsupported form', request('SELF_UPDATE', {}), active(), { slotContext: SLOT.slice(), updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: null, operationIdentity: null, stagedOutput: { protectedCommitBytes: 'x' } }, 'INVALID_REQUEST'],
    ['non-closed reconciliation observation', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), { ...reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }), extra: 1 }, 'UNKNOWN_FIELD'],
    ['missing reconciliation observation member', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-other') }), heldUpdate(), withoutMember(reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }), 'responseEmission'), 'INVALID_REQUEST'],
    ['accessor reconciliation observation member', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-other') }), heldUpdate(), withAccessor(reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }), 'heldOutput'), 'INVALID_REQUEST'],
    ['held escrow withheld from a reconciliation with no proof', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: null }), 'INVALID_REQUEST'],
    ['supported form without a commit proof', request('SELF_UPDATE', {}), active(), { slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: null, operationIdentity: null, stagedOutput: null }, 'INVALID_REQUEST'],
    ['staged output without a commit proof', request('SELF_UPDATE', {}), active(), { slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: null, operationIdentity: null, stagedOutput: { protectedCommitBytes: STAGED } }, 'INVALID_REQUEST'],
    ['commit proof without a supported form', request('SELF_UPDATE', {}), active(), { slotContext: SLOT.slice(), updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: 'COMMITTED', operationIdentity: 'op-upd-1', stagedOutput: null }, 'INVALID_REQUEST'],
    ['staged output of the wrong member without a commit proof', request('SELF_UPDATE', {}), active(), updateObservation({ commitOutcome: null, stagedOutput: { embeddedTreeWelcome: WELCOME } }), 'UNKNOWN_FIELD'],
    ['staged output of the wrong type without a commit proof', request('SELF_UPDATE', {}), active(), updateObservation({ commitOutcome: null, stagedOutput: { protectedCommitBytes: 7 } }), 'INVALID_REQUEST'],
    ['out-of-set commit outcome with no request issued', request('SELF_UPDATE', {}), active(), { ...okUpdate, commitOutcome: 'MAYBE', operationIdentity: null }, 'INVALID_REQUEST'],
    ['missing operation identity after a commit proof', request('SELF_UPDATE', {}), active(), { ...okUpdate, operationIdentity: null }, 'INVALID_REQUEST'],
    ['empty operation identity after a commit proof', request('SELF_UPDATE', {}), active(), { ...okUpdate, operationIdentity: '' }, 'INVALID_REQUEST'],
    ['out-of-set response emission', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-other') }), heldUpdate(), reconcileObservation({ responseEmission: 'DELIVERED' }), 'UNKNOWN_VALUE'],
    ['response emission for an outcome that cannot have one', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: 'SUCCEEDED', heldOutput: null }), 'INVALID_REQUEST'],
    ['missing response emission for a committed outcome', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-other') }), heldUpdate(), reconcileObservation({ responseEmission: null }), 'INVALID_REQUEST'],
    ['held escrow of two members', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED, embeddedTreeWelcome: WELCOME } }), 'UNKNOWN_FIELD'],
    ['held escrow that is not the held mutation\'s escrow', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { embeddedTreeWelcome: WELCOME } }), 'INVALID_REQUEST'],
    ['held escrow offered while nothing is held', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), active(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), 'INVALID_REQUEST'],
    ['held escrow withheld while the held kind names one', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: null }), 'INVALID_REQUEST'],
  ];

  test.each(cases)('%s rejects fail-closed', (_name, req, snapshot, observation, expected) => {
    const result = invokeAdapter({ request: req, snapshot, observation });
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe(expected);
    expect(Object.keys(result.error)).toEqual(['code']);
    expect(Object.isFrozen(result.error)).toBe(true);
  });

  test('an over-bound request bound is refused without a commit request', () => {
    const longId = 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_REQUEST_ID_CHARS + 1);
    const longRef = 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_RECONCILIATION_REF_CHARS + 1);
    expect(validateAdapterRequest(request('SELF_UPDATE', {}, { requestId: longId })))
      .toEqual({ ok: false, code: 'VALUE_OUT_OF_RANGE' });
    expect(validateAdapterRequest(request('RECONCILE_INDETERMINATE', { reconciliationRef: longRef })))
      .toEqual({ ok: false, code: 'VALUE_OUT_OF_RANGE' });
    expect(validateAdapterRequest(request('SELF_UPDATE', {}))).toEqual({ ok: true, code: null });
    // The bound itself is exactly the contract bound: 256 characters are admissible, 257 are not.
    expect(validateAdapterRequest(request('RECONCILE_INDETERMINATE', {
      reconciliationRef: 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_RECONCILIATION_REF_CHARS),
    }))).toEqual({ ok: true, code: null });
    expect(M2_ADAPTER.BOUNDS.MAX_RECONCILIATION_REF_CHARS).toBe(256);
    expect(M2_ADAPTER.BOUNDS.MAX_OPERATION_IDENTITY_CHARS).toBe(246);
    expect(Object.isFrozen(validateAdapterRequest(request('SELF_UPDATE', {})))).toBe(true);
  });

  test('an operation identity past its bound is rejected at P06 before any commit request (probe p06)', () => {
    const identity = 'i'.repeat(M2_ADAPTER.BOUNDS.MAX_OPERATION_IDENTITY_CHARS);
    const accepted = invokeAdapter({
      request: request('SELF_UPDATE', {}), snapshot: active(), observation: updateObservation({ operationIdentity: identity }),
    });
    expect(accepted.kind).toBe('SUCCESS');
    expect(accepted.successCode).toBe('SELF_UPDATED');
    // The longest accepted identity mints a reference that fits the reconciliation bound exactly, and that
    // reference reconciles.
    const fits = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}), snapshot: active(),
      observation: updateObservation({ commitOutcome: 'INDETERMINATE', operationIdentity: identity }),
    });
    expect(fits.result.kind).toBe('INDETERMINATE');
    expect(fits.result.reconciliationRef.length).toBe(M2_ADAPTER.BOUNDS.MAX_RECONCILIATION_REF_CHARS);
    const resolved = invokeAdapter({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: fits.result.reconciliationRef }),
      snapshot: fits.snapshot, observation: reconcileObservation({}),
    });
    expect(resolved.successCode).toBe('RECONCILED_COMMITTED');
    // C-API `CAPI-E014` (P06, REJECTED, UNCHANGED, persistence NONE) and C-MUT §3: one character more is
    // a structural bound exceeded before any commit request, whatever outcome is reported — nothing is
    // applied, nothing is held, and no reference this module would refuse is ever minted.
    for (const commitOutcome of ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']) {
      const over = invokeAdapterTransition({
        request: request('SELF_UPDATE', {}), snapshot: active(),
        observation: updateObservation({ commitOutcome, operationIdentity: `${identity}i` }),
      });
      assertEnvelope(over.result, 'REJECTED', ['error']);
      expect(code(over.result)).toBe('VALUE_OUT_OF_RANGE');
      expect(over.result.stateAfter).toBe('ACTIVE');
      expect(over.snapshot).toBe(null);
    }
    // The P05 state gates still outrank the P06 bound.
    const gated = invokeAdapter({
      request: request('SELF_UPDATE', {}), snapshot: heldUpdate(),
      observation: updateObservation({ operationIdentity: `${identity}i` }),
    });
    expect(code(gated)).toBe('RECONCILIATION_REQUIRED');
  });

  test('the identity bound leaves the I-MSG operations unchanged (contract R2 step 5, final review)', () => {
    // R2 scopes the P06 identity bound to CREATE, JOIN_WELCOME and SELF_UPDATE. A PROTECT_APPLICATION
    // whose RS identity is one character past it keeps its integrated tri-state answer and its hold.
    const longIdentity = 'i'.repeat(M2_ADAPTER.BOUNDS.MAX_OPERATION_IDENTITY_CHARS + 1);
    const protect = (commitOutcome) => invokeAdapterTransition({
      request: request('PROTECT_APPLICATION', { applicationBytes: bytes(0x01) }),
      snapshot: active(),
      observation: {
        commitOutcome, operationIdentity: longIdentity,
        stagedOutput: { protectedApplicationBytes: bytes(0x02) },
      },
    });
    const committed = protect('COMMITTED');
    expect(committed.result.kind).toBe('SUCCESS');
    expect(committed.result.successCode).toBe('APPLICATION_PROTECTED');
    expect(protect('NOT_COMMITTED').result.kind).toBe('NOT_COMMITTED');
    const held = protect('INDETERMINATE');
    expect(held.result.kind).toBe('INDETERMINATE');
    expect(held.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(held.result.reconciliationRef).toBe(`I-SM-HOLD:${longIdentity}`);
  });

  test('no accessor of any injected record is ever invoked', () => {
    const reads = { count: 0 };
    const result = invokeAdapter({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: withAccessor(okUpdate, 'operationIdentity', reads),
    });
    expect(code(result)).toBe('INVALID_REQUEST');
    expect(reads.count).toBe(0);
    // An accessor evidence member is read as absent, never invoked: the issued update is held.
    const evidenceReads = { count: 0 };
    const held = invokeAdapter({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: withAccessor(okUpdate, 'commitOutcome', evidenceReads),
    });
    expect(held.kind).toBe('INDETERMINATE');
    expect(evidenceReads.count).toBe(0);
    const requestReads = { count: 0 };
    let thrown = null;
    try {
      invokeAdapter({
        request: withAccessor(request('SELF_UPDATE', {}), 'requestId', requestReads),
        snapshot: active(),
        observation: okUpdate,
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(M2AdapterError);
    expect(thrown.code).toBe('INVALID_REQUEST');
    expect(requestReads.count).toBe(0);
  });

  test('an accessor input is never invoked: it is a P01 defect, and an unknown member still preempts it (cycle 5d review)', () => {
    for (const value of [() => ({}), () => { throw new Error('caller code'); }]) {
      const inputReads = { count: 0, value };
      const withInput = withAccessor(request('SELF_UPDATE', {}), 'input', inputReads);
      const malformed = invokeAdapter({ request: withInput, snapshot: active(), observation: okUpdate });
      expect(code(malformed)).toBe('INVALID_REQUEST');
      const unknownFirst = { extra: 1 };
      for (const key of Reflect.ownKeys(withInput)) {
        Object.defineProperty(unknownFirst, key, Object.getOwnPropertyDescriptor(withInput, key));
      }
      const unknownLast = withAccessor(request('SELF_UPDATE', {}, { extra: 1 }), 'input', inputReads);
      for (const record of [unknownFirst, unknownLast]) {
        expect(code(invokeAdapter({ request: record, snapshot: active(), observation: okUpdate }))).toBe('UNKNOWN_FIELD');
      }
      expect(inputReads.count).toBe(0);
    }
  });
});
describe('I-UPD total precedence and the internal failure boundary', () => {
  test('the lowest precedence level present decides, whatever its order in the request', () => {
    const several = request('ADD_MEMBER', {}, { extra: 1, api: 'styx-m2-session-adapter/v2' });
    expect(code(invokeAdapter({ request: several, snapshot: active(), observation: updateObservation({}) })))
      .toBe('UNKNOWN_FIELD');
    const apiThenOperation = request('APPLY_PEER_UPDATE', { protectedCommitBytes: bytes(0x01) },
      { api: 'styx-m2-session-adapter/v2' });
    expect(code(invokeAdapter({ request: apiThenOperation, snapshot: active(), observation: updateObservation({}) })))
      .toBe('UNSUPPORTED_API_VERSION');
    const profileThenBinding = request('SELF_UPDATE', {},
      { profile: { ...PROFILE, pastEpochWindow: 1 }, bindingRef: new Uint8Array(0) });
    expect(code(invokeAdapter({ request: profileThenBinding, snapshot: active(), observation: updateObservation({}) })))
      .toBe('UNSUPPORTED_PROFILE');
  });

  test('the P05 state gate is decided after the earlier P01-P04 errors and before the later P06-P10 ones', () => {
    const malformed = invokeAdapter({
      request: request('SELF_UPDATE', {}), snapshot: empty(), observation: { ...updateObservation({}), extra: 1 },
    });
    expect(code(malformed)).toBe('UNKNOWN_FIELD');
    const overBound = invokeAdapter({
      request: request('SELF_UPDATE', {}, { requestId: 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_REQUEST_ID_CHARS + 1) }),
      snapshot: empty(),
      observation: updateObservation({}),
    });
    expect(code(overBound)).toBe('NO_ACTIVE_SESSION');
  });

  test('a durable committed proof with no pending hold reaches the ratified gate code, not a P01 defect', () => {
    const result = invokeAdapter({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }),
      snapshot: active(),
      observation: reconcileObservation({ heldOutput: null }),
    });
    expect(code(result)).toBe('NO_RECONCILIATION_PENDING');
    expect(result.stateBefore).toBe('ACTIVE');
    expect(result.stateAfter).toBe('ACTIVE');
  });
  test('a request-level error preempts an otherwise valid operation', () => {
    const drifted = request('SELF_UPDATE', {}, { profile: { ...PROFILE, stage: 'other-profile' } });
    const result = invokeAdapter({
      request: drifted, snapshot: empty(), observation: updateObservation({}),
    });
    expect(code(result)).toBe('UNSUPPORTED_PROFILE');
    expect(result.stateBefore).toBe('EMPTY');
  });

  test('a request bound preempts a P09 decision but never a gate that is already past it', () => {
    const longId = 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_REQUEST_ID_CHARS + 1);
    const refused = invokeAdapter({
      request: request('SELF_UPDATE', {}, { requestId: longId }),
      snapshot: active(),
      observation: { slotContext: SLOT.slice(), updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: null, operationIdentity: null, stagedOutput: null },
    });
    expect(code(refused)).toBe('VALUE_OUT_OF_RANGE');
  });

  test('after a commit request no rejection is ever emitted: a late defect holds the mutation', () => {
    const longId = 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_REQUEST_ID_CHARS + 1);
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}, { requestId: longId }),
      snapshot: active(),
      observation: updateObservation({}),
    });
    assertEnvelope(transition.result, 'INDETERMINATE',
      ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(transition.result.commitOutcome).toBe('INDETERMINATE');
    expect(transition.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(transition.result.output).toBe(undefined);
    expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    const absent = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({ stagedOutput: null }),
    });
    expect(absent.result.kind).toBe('INDETERMINATE');
    expect(absent.snapshot.held.scenario).toBe('CAPI-S014');
    expect(absent.snapshot.held.outputKind).toBe('PROTECTED_COMMIT_BYTES');
    const notCommitted = invokeAdapter({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({ commitOutcome: 'NOT_COMMITTED', stagedOutput: null }),
    });
    expect(notCommitted.kind).toBe('NOT_COMMITTED');
  });
});

describe('I-UPD purity, immutability and the closed envelope', () => {
  const matrix = [
    ['SELF_UPDATE', active(), updateObservation({})],
    ['SELF_UPDATE', active(), updateObservation({ commitOutcome: 'NOT_COMMITTED', stagedOutput: null })],
    ['SELF_UPDATE', active(), updateObservation({ commitOutcome: 'INDETERMINATE', stagedOutput: null })],
    ['SELF_UPDATE', empty(), updateObservation({})],
    ['RECONCILE_INDETERMINATE', heldUpdate(), reconcileObservation({})],
    ['RECONCILE_INDETERMINATE', heldUpdate(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } })],
  ];

  test('the result of every outcome shape is frozen, closed and free of undefined members', () => {
    const extras = {
      SUCCESS: ['successCode', 'commitOutcome', 'output'],
      NOT_COMMITTED: ['commitOutcome'],
      INDETERMINATE: ['commitOutcome', 'reconciliationRef', 'originalStateBefore'],
      REJECTED: ['error'],
    };
    for (const [operation, snapshot, observation] of matrix) {
      const reference = operation === 'RECONCILE_INDETERMINATE' ? { reconciliationRef: heldRef('held-upd-1') } : {};
      const result = invoke(operation, snapshot, observation, reference);
      const extra = result.kind === 'SUCCESS' && operation === 'RECONCILE_INDETERMINATE'
        ? ['successCode', 'output'] : extras[result.kind];
      assertEnvelope(result, result.kind, extra);
      for (const value of Object.values(result)) expect(value).not.toBe(undefined);
    }
  });

  test('the same input yields the same result and the input is never mutated', () => {
    for (const [operation, snapshot, observation] of matrix) {
      const reference = operation === 'RECONCILE_INDETERMINATE' ? { reconciliationRef: heldRef('held-upd-1') } : {};
      const input = { request: request(operation, reference), snapshot, observation: structuredClone(observation) };
      const before = structuredClone(observation);
      const snapshotBefore = structuredClone(snapshot);
      const first = invokeAdapter(input);
      const second = invokeAdapter(input);
      expect(first).toEqual(second);
      expect(Object.isFrozen(first)).toBe(true);
      expect(observation).toEqual(before);
      expect(input.observation).toEqual(before);
      // The injected snapshot is read, never written: reconciliation moves state by returning a new
      // snapshot, so the caller's own record must come back byte-for-byte unchanged.
      expect(snapshot).toEqual(snapshotBefore);
      expect(input.request.bindingRef).toEqual(SLOT);
    }
  });

  test('a released member is a copy: neither side can reach the other through it', () => {
    const observation = updateObservation({});
    const result = invokeAdapter({ request: request('SELF_UPDATE', {}), snapshot: active(), observation });
    result.output.protectedCommitBytes[0] = 0xff;
    expect(observation.stagedOutput.protectedCommitBytes[0]).toBe(0x11);
    observation.stagedOutput.protectedCommitBytes[1] = 0xff;
    expect(result.output.protectedCommitBytes[1]).toBe(0x22);
  });
});
describe('I-UPD seeded property sweep', () => {
  const SEED = 20261002;
  const RUNS = 300;

  const memberArbitrary = fc.oneof(
    fc.constant(undefined),
    fc.constant(null),
    fc.integer(),
    fc.string(),
    fc.boolean(),
    fc.uint8Array({ maxLength: 4 }),
    fc.constant('SUPPORTED'),
    fc.constant('UNSUPPORTED_UPDATE_FORM'),
    fc.constant('COMMITTED'),
    fc.constant('NOT_COMMITTED'),
    fc.constant('INDETERMINATE'),
    fc.constant('SUCCEEDED'),
    fc.constant('INTERRUPTED'),
    fc.constant('op-upd-1'),
  );

  const snapshotArbitrary = fc.oneof(
    fc.constant(empty()),
    fc.constant(active()),
    fc.constant(holdOf('SELF_UPDATE', active(), 'op-upd-1')),
    fc.constant(holdOf('CREATE', empty(), 'op-create-1')),
    fc.constant(holdOf('JOIN_WELCOME', empty(), 'op-join-1')),
  );

  test('no randomly shaped staged observation escapes the closed outcome space', () => {
    const observationArbitrary = fc.record({
      updateForm: memberArbitrary,
      commitOutcome: memberArbitrary,
      operationIdentity: memberArbitrary,
      stagedOutput: fc.oneof(
        fc.constant(null),
        fc.record({ protectedCommitBytes: memberArbitrary }),
        fc.record({ embeddedTreeWelcome: memberArbitrary }),
        // A well-formed, bounded escrow with a commit report: without it every generated observation
        // would be refused before the success path and the assertions below could not fail.
        fc.constant({ protectedCommitBytes: new Uint8Array([1, 2, 3]) }),
      ),
    });
    const seen = { success: 0, released: 0, rejected: 0, held: 0 };
    fc.assert(fc.property(snapshotArbitrary, fc.oneof(
      observationArbitrary,
      fc.constant({ slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: 'COMMITTED', operationIdentity: 'op-upd-1', stagedOutput: { protectedCommitBytes: new Uint8Array([7]) } }),
      fc.constant({ slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: 'INDETERMINATE', operationIdentity: 'op-upd-1', stagedOutput: { protectedCommitBytes: new Uint8Array([8]) } }),
    ), (snapshot, observation) => {
      let result;
      try {
        result = invokeAdapter({ request: request('SELF_UPDATE', {}), snapshot, observation });
      } catch (error) {
        expect(error).toBeInstanceOf(M2AdapterError);
        return;
      }
      expect(M2_ADAPTER.RESULT_KINDS).toContain(result.kind);
      expect(M2_ADAPTER.STATES).toContain(result.stateAfter);
      expect(result.stateBefore).toBe(snapshot.state);
      expect(result.operation).toBe('SELF_UPDATE');
      expect(result.requestId).toMatch(/^req-iupd-/);
      if (result.kind === 'SUCCESS') {
        expect(observation.updateForm).toBe('SUPPORTED');
        expect(observation.commitOutcome).toBe('COMMITTED');
        expect(result.commitOutcome).toBe('COMMITTED');
        expect(result.successCode).toBe('SELF_UPDATED');
      }
      if (result.kind === 'INDETERMINATE') expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
      if (result.kind === 'NOT_COMMITTED') expect(result.stateAfter).toBe(result.stateBefore);
      if (result.kind === 'REJECTED') {
        expect(M2_ADAPTER.ERROR_CODES).toContain(result.error.code);
        expect(result.stateAfter).toBe(snapshot.state);
        seen.rejected += 1;
      }
      if (result.kind === 'INDETERMINATE') seen.held += 1;
      if (result.kind === 'SUCCESS') {
        seen.success += 1;
        // A success always carries its released member and only ever reports the commit it required.
        expect(Object.keys(result.output)).toEqual(['protectedCommitBytes']);
        seen.released += 1;
      }
    }), { seed: SEED, numRuns: RUNS });
    // The sweep is only evidence if it actually reaches every outcome it asserts on.
    expect(seen.success).toBeGreaterThan(0);
    expect(seen.rejected).toBeGreaterThan(0);
    expect(seen.held).toBeGreaterThan(0);
  });

  test('no randomised reconciliation ever releases a member the hold does not fix', () => {
    const seen = { success: 0, held: 0, refused: 0 };
    const reconcileObservationArbitrary = fc.record({
      commitOutcome: memberArbitrary,
      responseEmission: memberArbitrary,
      heldOutput: fc.oneof(
        fc.constant(null),
        fc.record({ protectedCommitBytes: memberArbitrary }),
        fc.record({ embeddedTreeWelcome: memberArbitrary }),
        fc.record({ protectedCommitBytes: memberArbitrary, embeddedTreeWelcome: memberArbitrary }),
        fc.constant({ protectedCommitBytes: new Uint8Array([1, 2, 3]) }),
        fc.constant({ embeddedTreeWelcome: new Uint8Array([4, 5, 6]) }),
      ),
    });
    fc.assert(fc.property(
      fc.oneof(
        // Correlated pairs: each hold with the exact escrow and proof that resolves it, so the release path
        // is genuinely reachable, plus the free product of every other shape.
        fc.constant([heldUpdate(), { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: { protectedCommitBytes: STAGED } }]),
        fc.constant([heldCreate(), { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: { embeddedTreeWelcome: WELCOME } }]),
        fc.constant([heldJoin(), { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: null }]),
        fc.constant([heldUpdate(), { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'INTERRUPTED', heldOutput: { protectedCommitBytes: STAGED } }]),
        fc.tuple(snapshotArbitrary, reconcileObservationArbitrary),
      ),
      (pair) => {
        const [snapshot, observation] = pair;
        const { heldOutput, commitOutcome, responseEmission } = observation;
        const held = snapshot.held;
        const reference = held === null ? 'I-SM-HOLD:none' : held.reconciliationRef;
        let result;
        try {
          result = invokeAdapter({
            request: request('RECONCILE_INDETERMINATE', { reconciliationRef: reference }),
            snapshot,
            observation: { slotContext: SLOT.slice(), commitOutcome, responseEmission, heldOutput },
          });
        } catch (error) {
          expect(error).toBeInstanceOf(M2AdapterError);
          return;
        }
        expect(M2_ADAPTER.RESULT_KINDS).toContain(result.kind);
        expect(result.stateBefore).toBe(snapshot.state);
        if (result.kind === 'SUCCESS') {
          seen.success += 1;
          expect(commitOutcome).toBe('COMMITTED');
          expect(result.successCode).toBe('RECONCILED_COMMITTED');
          expect(held).not.toBe(null);
          expect(result.output.originalSuccessCode).toBe(held.expectedSuccessCode);
          if (held.outputKind === 'NONE') expect(Object.keys(result.output.originalOutput)).toEqual([]);
          else {
            expect(result.output.originalOutput).not.toBe(null);
            expect(Object.keys(result.output.originalOutput)).toEqual([M2_ADAPTER.OUTPUT_MEMBER_BY_KIND[held.outputKind]]);
          }
        }
        if (result.kind === 'INDETERMINATE') {
          seen.held += 1;
          expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
          if (held !== null) expect(result.reconciliationRef).toBe(held.reconciliationRef);
        }
        if (result.kind === 'REJECTED') seen.refused += 1;
      }), { seed: SEED + 1, numRuns: RUNS });
    // Both the release and the refusal paths must actually be reached by the generated corpus.
    expect(seen.success).toBeGreaterThan(0);
    expect(seen.refused).toBeGreaterThan(0);
  });

  test('a replayed corpus is bit-identical, so the sweep is evidence and not a coin toss', () => {
    const sampler = (seed) => {
      const trace = [];
      fc.assert(fc.property(snapshotArbitrary, fc.oneof(
        fc.constant({ slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: 'COMMITTED', operationIdentity: 'op-upd-1', stagedOutput: { protectedCommitBytes: new Uint8Array([1]) } }),
        fc.constant({ slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: 'NOT_COMMITTED', operationIdentity: 'op-upd-1', stagedOutput: null }),
        fc.constant({ slotContext: SLOT.slice(), updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: null, operationIdentity: null, stagedOutput: null }),
      ), (snapshot, observation) => {
        const result = invokeAdapter({ request: request('SELF_UPDATE', {}), snapshot, observation });
        trace.push(`${snapshot.state}|${observation.commitOutcome}|${result.kind}|${result.stateAfter}|${result.error === undefined ? result.successCode ?? '' : result.error.code}`);
      }), { seed, numRuns: 40 });
      return trace;
    };
    const first = sampler(SEED + 7);
    const second = sampler(SEED + 7);
    expect(first).toEqual(second);
    expect(first.length).toBe(40);
  });
});

// The release path closes the escrow twice: once when the observation is read, and once when the copy
// leaves this module. A resizable backing buffer resized from a snapshot trap was how a caller could make
// those two reads disagree. The snapshot is now copied once before the observation is read, so the trap
// never fires between them; these tests drive that through the public entry point only.
const resizable = (values, maxByteLength) => {
  if (typeof ArrayBuffer.prototype.resize !== 'function') return null;
  const buffer = new ArrayBuffer(values.length, { maxByteLength: Math.max(values.length, maxByteLength) });
  const view = new Uint8Array(buffer);
  view.set(values);
  return { view, resize: (bytes) => buffer.resize(bytes) };
};

// The escrow is grown only once the observation record has already been read: the staged-output proxy
// flips `escrowRead` while the module decodes it, and the snapshot proxy then resizes the buffer on the
// next own-keys read, which is the merged core reading the snapshot inside the decision. The two reads
// of the same buffer therefore disagree by construction, not by a call count that happens to line up.
const growEscrowDuringDecision = (values, grownBytes) => {
  const located = resizable(values, grownBytes);
  if (located === null) return null;
  const state = { escrowRead: false, grown: false };
  const stagedOutput = new Proxy({ protectedCommitBytes: located.view }, {
    getOwnPropertyDescriptor(target, key) {
      const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
      if (key === 'protectedCommitBytes') state.escrowRead = true;
      return descriptor;
    },
  });
  const snapshot = new Proxy({ state: 'ACTIVE', held: null }, {
    ownKeys(target) {
      if (state.escrowRead && !state.grown) {
        located.resize(grownBytes);
        state.grown = true;
      }
      return Reflect.ownKeys(target);
    },
  });
  return { stagedOutput, snapshot, state, view: located.view };
};

const heldRefOf = (id) => heldRef(id);

describe('I-UPD the release path re-checks the escrow it hands over', () => {
  test('the runtime under test provides the resizable buffers these probes drive', () => {
    expect(typeof ArrayBuffer.prototype.resize).toBe('function');
  });

  test('a snapshot trap that would grow the escrow after it is measured never runs: the measured escrow is released', () => {
    const grown = growEscrowDuringDecision([0x11, 0x22, 0x33, 0x44], 2 * M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES);
    expect(grown).not.toBe(null);
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: grown.snapshot,
      observation: updateObservation({ stagedOutput: grown.stagedOutput }),
    });
    // The trap never fires after the escrow read: the caller's snapshot is copied once, before the
    // observation is read, so nothing the caller controls runs between the measurement and the release.
    expect(grown.state.grown).toBe(false);
    expect(grown.view.length).toBe(4);
    // ... and the adapter answers exactly what the measured escrow supports.
    expect(transition.result.kind).toBe('SUCCESS');
    expect(transition.result.successCode).toBe('SELF_UPDATED');
    expect(Array.from(transition.result.output.protectedCommitBytes)).toEqual([0x11, 0x22, 0x33, 0x44]);
    expect(transition.snapshot.state).toBe('ACTIVE');
  });

  test('a snapshot trap that would shrink the escrow after it is measured never runs either', () => {
    const shrunk = growEscrowDuringDecision([0x11, 0x22, 0x33, 0x44], 2);
    expect(shrunk).not.toBe(null);
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: shrunk.snapshot,
      observation: updateObservation({ stagedOutput: shrunk.stagedOutput }),
    });
    expect(shrunk.state.grown).toBe(false);
    expect(shrunk.view.length).toBe(4);
    expect(transition.result.kind).toBe('SUCCESS');
    expect(Array.from(transition.result.output.protectedCommitBytes)).toEqual([0x11, 0x22, 0x33, 0x44]);
    expect(transition.snapshot.state).toBe('ACTIVE');
  });

  test('a held escrow cannot be resized by a snapshot trap between its measurement and its release', () => {
    const located = resizable([0x51, 0x52, 0x53, 0x54], 2 * M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES);
    expect(located).not.toBe(null);
    const hold = heldUpdate('held-upd-toctou');
    const reference = heldRefOf('held-upd-toctou');
    const state = { escrowRead: false, grown: false };
    const heldOutput = new Proxy({ protectedCommitBytes: located.view }, {
      getOwnPropertyDescriptor(target, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
        if (key === 'protectedCommitBytes') state.escrowRead = true;
        return descriptor;
      },
    });
    // The growth is driven by the merged core reading the snapshot, exactly as in the staged case above.
    const snapshot = new Proxy(hold, {
      ownKeys(target) {
        if (state.escrowRead && !state.grown) {
          located.resize(2 * M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES);
          state.grown = true;
        }
        return Reflect.ownKeys(target);
      },
    });
    const truthful = reconcile(hold, reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }), reference);
    expect(truthful.kind).toBe('SUCCESS');
    const result = reconcile(snapshot, {
      slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput,
    }, reference);
    expect(state.grown).toBe(false);
    // The held escrow is measured after the one snapshot read, so it cannot change before release: the
    // answer is the truthful one, releasing exactly the four bytes that were measured.
    expect(result.kind).toBe('SUCCESS');
    expect(result.successCode).toBe(truthful.successCode);
    expect(Array.from(result.output.originalOutput.protectedCommitBytes)).toEqual([0x51, 0x52, 0x53, 0x54]);
  });

  test('a snapshot that answers `held` to a property read differently than to a descriptor read cannot pick the escrow', () => {
    const hold = heldUpdate('held-upd-lying');
    const reference = heldRefOf('held-upd-lying');
    const other = holdOf('JOIN_WELCOME', empty(), 'held-upd-lying');
    // The lie the merged core's own descriptor-based inspection never sees: a plain `snapshot.held` that
    // hands back a hold of a different escrow kind (here the escrow-less Welcome hold).
    const lying = new Proxy({ state: 'RECONCILIATION_REQUIRED', held: hold.held }, {
      get(target, key) { return key === 'held' ? other.held : Reflect.get(target, key); },
    });
    const observation = reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } });
    const truthful = reconcile(hold, observation, reference);
    const throughLie = reconcile(lying, observation, reference);
    expect(truthful.kind).toBe('SUCCESS');
    expect(truthful.successCode).toBe('RECONCILED_COMMITTED');
    expect(truthful.output.originalSuccessCode).toBe('SELF_UPDATED');
    // The hold the code reads is the one the descriptor read decoded, so the lie changes nothing.
    expect(throughLie.kind).toBe('SUCCESS');
    expect(throughLie.successCode).toBe(truthful.successCode);
    expect(throughLie.output.originalSuccessCode).toBe(truthful.output.originalSuccessCode);
    expect([...throughLie.output.originalOutput.protectedCommitBytes]).toEqual([...STAGED]);
    expect(throughLie.stateAfter).toBe(truthful.stateAfter);
    // And the escrow the hold fixes is still required: with no escrow supplied and no COMMITTED proof the
    // same snapshot refuses.
    expect(code(reconcile(lying, reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: null }), reference))).toBe('INVALID_REQUEST');
  });

  test('a released escrow is the bounded copy of exactly the bytes the observation validated', () => {
    const source = bytes(0x0a, 0x0b, 0x0c, 0x0d);
    const transition = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({ stagedOutput: { protectedCommitBytes: source } }),
    });
    expect(transition.result.kind).toBe('SUCCESS');
    expect(transition.result.successCode).toBe('SELF_UPDATED');
    expect([...transition.result.output.protectedCommitBytes]).toEqual([...source]);
    expect(transition.result.output.protectedCommitBytes).not.toBe(source);
    expect(Object.isFrozen(transition.result.output)).toBe(true);
  });

  test('an over-bound escrow is released by nothing on either path', () => {
    const over = new Uint8Array(M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES + 1);
    // After a commit report an escrow the owning layer cannot hand over is held, never released: an
    // over-bound one is a handover failure, not a rejection of the mutation RS already committed.
    const staged = invokeAdapterTransition({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({ stagedOutput: { protectedCommitBytes: over } }),
    });
    assertEnvelope(staged.result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(staged.result.output).toBe(undefined);
    expect(staged.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    // A held escrow past the bound with no COMMITTED proof is a P01 observation defect, and the hold
    // survives the refusal; with RS's COMMITTED proof it retains the hold instead, releasing nothing.
    const held = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRefOf('held-upd-over') }),
      snapshot: heldUpdate('held-upd-over'),
      observation: reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: over } }),
    });
    assertEnvelope(held.result, 'REJECTED', ['error']);
    expect(code(held.result)).toBe('INVALID_REQUEST');
    expect(held.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    const proved = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRefOf('held-upd-over') }),
      snapshot: heldUpdate('held-upd-over'),
      observation: reconcileObservation({ heldOutput: { protectedCommitBytes: over } }),
    });
    assertEnvelope(proved.result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(proved.result.output).toBe(undefined);
    expect(proved.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
  });
});

describe('I-UPD hostile inputs never widen the closed vocabulary', () => {
  const forged = () => {
    const error = new M2AdapterError('UNKNOWN_FIELD');
    error.code = 'NOT_A_CAPI_CODE';
    error.message = 'text chosen by the input';
    throw error;
  };

  test('an M2AdapterError a hostile record throws never escapes with a code outside the closed set', () => {
    const hostile = new Proxy({ protectedCommitBytes: bytes(0x11) }, { getOwnPropertyDescriptor: forged });
    const reference = heldRefOf('held-upd-hostile');
    let thrown = null;
    let result = null;
    try {
      result = reconcile(heldUpdate('held-upd-hostile'), {
        slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: hostile,
      }, reference);
    } catch (error) {
      thrown = error;
    }
    if (thrown !== null) {
      expect(thrown).toBeInstanceOf(M2AdapterError);
      expect(M2_ADAPTER.ERROR_CODES).toContain(thrown.code);
      expect(thrown.message).toBe(thrown.code);
    } else {
      // RS reported COMMITTED for this hold: an escrow the SS cannot hand over retains the hold with the
      // proof recorded (C-API `/rules/internalFailureBoundary`, cycle 5g review); nothing is released.
      assertEnvelope(result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
      expect(result.output).toBe(undefined);
      expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    }
  });

  test('the same hostile throw on the outer input record stays a closed code as well', () => {
    const hostileInput = new Proxy({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: updateObservation({}),
    }, { getOwnPropertyDescriptor: forged });
    let thrown = null;
    try {
      invokeAdapterTransition(hostileInput);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(M2AdapterError);
    expect(M2_ADAPTER.ERROR_CODES).toContain(thrown.code);
    expect(thrown.message).toBe(thrown.code);
    expect(thrown.code).not.toBe('NOT_A_CAPI_CODE');
  });

  test('every thrown error the public surface can raise carries exactly one closed C-API code', () => {
    const cases = [
      new Proxy({}, { getOwnPropertyDescriptor: forged }),
      new Proxy({ state: 'ACTIVE', held: null }, { ownKeys: forged }),
      new Proxy({ state: 'ACTIVE', held: null }, { getOwnPropertyDescriptor: forged }),
    ];
    for (const snapshot of cases) {
      for (const probe of [
        () => invokeAdapterTransition({
          request: request('SELF_UPDATE', {}), snapshot, observation: updateObservation({}),
        }).result,
        () => invokeAdapterTransition({
          request: request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRefOf('held-upd-x') }),
          snapshot,
          observation: reconcileObservation({}),
        }).result,
        () => invokeAdapter({ request: request('SELF_UPDATE', {}), snapshot, observation: updateObservation({}) }),
      ]) {
        let result = null;
        let thrown = null;
        try {
          result = probe();
        } catch (error) {
          thrown = error;
        }
        if (thrown === null) {
          expect(M2_ADAPTER.RESULT_KINDS).toContain(result.kind);
          if (result.kind === 'REJECTED') expect(M2_ADAPTER.ERROR_CODES).toContain(code(result));
        } else {
          expect(thrown).toBeInstanceOf(M2AdapterError);
          expect(M2_ADAPTER.ERROR_CODES).toContain(thrown.code);
          expect(thrown.message).toBe(thrown.code);
        }
      }
    }
  });
});

// Fifth correction cycle: one regression per finding fixed, all through the public entry points.
describe('I-UPD fifth-cycle regressions (probes p06, p08, p12, p14, p16)', () => {
  const selfUpdate = (bindingRef, observation, snapshot = active()) => invokeAdapterTransition({
    request: request('SELF_UPDATE', {}, { bindingRef }), snapshot, observation,
  });
  const reconcileWith = (bindingRef, snapshot, observation, reference) => invokeAdapterTransition({
    request: request('RECONCILE_INDETERMINATE', { reconciliationRef: reference }, { bindingRef }), snapshot, observation,
  });

  test('p12: SELF_UPDATE compares bindingRef byte-for-byte with the authoritative slot at P03', () => {
    // C-BIND `/comparisonRules/active` and §4, C-API `CAPI-E006`: wrong length, unknown reference and
    // byte mismatch are all BINDING_MISMATCH at P03, REJECTED, state unchanged, nothing persisted.
    expect(selfUpdate(SLOT.slice(), updateObservation({})).result.successCode).toBe('SELF_UPDATED');
    const lastByte = SLOT.slice();
    lastByte[31] ^= 0x01;
    for (const bindingRef of [OTHER_SLOT.slice(), lastByte, SLOT.slice(0, 31), bytes(1, 2, 3), new Uint8Array(4096).fill(7)]) {
      const transition = selfUpdate(bindingRef, updateObservation({}));
      assertEnvelope(transition.result, 'REJECTED', ['error']);
      expect(code(transition.result)).toBe('BINDING_MISMATCH');
      expect(transition.result.stateAfter).toBe('ACTIVE');
      expect(transition.snapshot).toBe(null);
    }
    // P03 outranks the P05 state gate and every decision row.
    expect(code(selfUpdate(OTHER_SLOT.slice(), updateObservation({}), heldUpdate()).result)).toBe('BINDING_MISMATCH');
    expect(code(selfUpdate(OTHER_SLOT.slice(), updateObservation({}), empty()).result)).toBe('BINDING_MISMATCH');
    // ...and P01/P02 outrank P03.
    expect(code(invokeAdapter({
      request: request('SELF_UPDATE', {}, { bindingRef: OTHER_SLOT.slice(), api: 'other' }), snapshot: active(), observation: updateObservation({}),
    }))).toBe('UNSUPPORTED_API_VERSION');
  });

  test('p12: RECONCILE_INDETERMINATE compares bindingRef with the original slot of the hold', () => {
    // C-BIND `/comparisonRules/reconciliationRequired`: a hold created in context A cannot be resolved
    // through context B; the mismatch is CAPI-E006 and the hold survives unchanged.
    const held = selfUpdate(SLOT.slice(), updateObservation({ commitOutcome: 'INDETERMINATE' }));
    expect(held.result.kind).toBe('INDETERMINATE');
    const cross = reconcileWith(OTHER_SLOT.slice(), held.snapshot, reconcileObservation({}), held.result.reconciliationRef);
    assertEnvelope(cross.result, 'REJECTED', ['error']);
    expect(code(cross.result)).toBe('BINDING_MISMATCH');
    expect(cross.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(cross.snapshot).toBe(null);
    const same = reconcileWith(SLOT.slice(), held.snapshot, reconcileObservation({}), held.result.reconciliationRef);
    expect(same.result.successCode).toBe('RECONCILED_COMMITTED');
  });

  test('p12: the authoritative slot context is a closed, mandatory SS fact of exactly 32 nonzero bytes', () => {
    for (const slotContext of [undefined, null, bytes(1, 2, 3), new Uint8Array(32), 'a'.repeat(32), [...SLOT]]) {
      const observation = { ...updateObservation({}), slotContext };
      if (slotContext === undefined) delete observation.slotContext;
      expect(code(selfUpdate(SLOT.slice(), observation).result)).toBe('INVALID_REQUEST');
    }
    // A slot fact is refused on the operations that do not carry one.
    const created = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: bytes(1) }), snapshot: empty(),
      observation: { onboarding: 'SUPPORTED', commitOutcome: 'COMMITTED', operationIdentity: 'op-c', stagedOutput: { embeddedTreeWelcome: WELCOME }, slotContext: SLOT.slice() },
    });
    expect(code(created)).toBe('UNKNOWN_FIELD');
  });

  test('p14: a reconciliation with no RS readback is the still-pending CAPI-S024 answer, never INVALID_REQUEST', () => {
    const hold = heldUpdate('held-upd-p14');
    const reference = heldRef('held-upd-p14');
    const pending = reconcileWith(SLOT.slice(), hold, reconcileObservation({ commitOutcome: null, responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
    assertEnvelope(pending.result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(pending.result.reconciliationRef).toBe(reference);
    expect(pending.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    // With nothing held the same request reaches the ratified CAPI-G016 gate.
    const nothing = reconcileWith(SLOT.slice(), active(), reconcileObservation({ commitOutcome: null, responseEmission: null, heldOutput: null }), reference);
    expect(code(nothing.result)).toBe('NO_RECONCILIATION_PENDING');
  });

  test('p14: a supported SELF_UPDATE whose issued request has no RS outcome is held, not rejected', () => {
    // C-API `/rules/rsTriState` INDETERMINATE "includes every absent, failed or unknown RS outcome after a
    // commit request"; the SS_RS operation identity is the evidence that the request was issued.
    const transition = selfUpdate(SLOT.slice(), updateObservation({ commitOutcome: null, operationIdentity: 'op-upd-p14', stagedOutput: { protectedCommitBytes: STAGED } }));
    assertEnvelope(transition.result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(transition.result.output).toBe(undefined);
    expect(transition.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    // With no identity either, no request was issued: that stays the P01 defect.
    expect(code(selfUpdate(SLOT.slice(), updateObservation({ commitOutcome: null })).result)).toBe('INVALID_REQUEST');
  });

  test('p16: after RS proved COMMITTED, a later readback never answers REJECTED and keeps the committed hold', () => {
    const hold = heldUpdate('held-upd-p16');
    const reference = heldRef('held-upd-p16');
    const interrupted = reconcileWith(SLOT.slice(), hold, reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference);
    expect(interrupted.result.successCode).toBe('RECONCILED_COMMITTED');
    expect(interrupted.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
    for (const commitOutcome of ['INDETERMINATE', 'NOT_COMMITTED', null]) {
      const later = reconcileWith(SLOT.slice(), interrupted.snapshot,
        reconcileObservation({ commitOutcome, responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
      assertEnvelope(later.result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
      expect(later.result.output).toBe(undefined);
      expect(later.snapshot).toEqual(interrupted.snapshot);
    }
    // The repeat with the committed proof still releases the same escrow (C-MUT
    // `/reconciliation/interruptedCommittedReconciliationRepeat`), and a wrong reference keeps CAPI-S028.
    const repeat = reconcileWith(SLOT.slice(), interrupted.snapshot, reconcileObservation({}), reference);
    expect(repeat.result.successCode).toBe('RECONCILED_COMMITTED');
    expect(repeat.snapshot.state).toBe('ACTIVE');
    const wrong = reconcileWith(SLOT.slice(), interrupted.snapshot,
      reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), heldRef('other'));
    expect(code(wrong.result)).toBe('RECONCILIATION_REFERENCE_MISMATCH');
  });

  test('p16: a snapshot that answers a different hold on a second read cannot swap the committed hold', () => {
    const hold = heldUpdate('held-upd-swap');
    const reference = heldRef('held-upd-swap');
    const interrupted = reconcileWith(SLOT.slice(), hold, reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference);
    const genuine = interrupted.snapshot.held;
    // Same reference and evidence status, a different decoded mutation (a JOIN_WELCOME hold of the same
    // operation identity): valid on its own, but never the mutation RS proved committed.
    const swapped = { ...heldJoin('held-upd-swap').held, terminalEvidenceStatus: 'COMMITTED' };
    expect(swapped.reconciliationRef).toBe(genuine.reconciliationRef);
    expect(swapped.scenario).not.toBe(genuine.scenario);
    // The swap is tried from every read position on, because the adapter reads `held` more than once
    // before this path; whichever read is the one that decides, the answer must be a rejection or the
    // genuine committed hold returned exactly as it was.
    for (let swapFrom = 1; swapFrom <= 8; swapFrom += 1) {
      let reads = 0;
      const hostile = new Proxy({ ...interrupted.snapshot }, {
        getOwnPropertyDescriptor(target, key) {
          if (key === 'held') {
            reads += 1;
            return { value: reads >= swapFrom ? swapped : genuine, writable: true, enumerable: true, configurable: true };
          }
          return Reflect.getOwnPropertyDescriptor(target, key);
        },
      });
      const later = reconcileWith(SLOT.slice(), hostile,
        reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
      if (later.result.kind === 'INDETERMINATE') {
        // The snapshot is read exactly once: the hold returned is the one that single read gave, never a
        // mixture of the genuine and the swapped hold.
        const asRead = swapFrom === 1 ? { ...interrupted.snapshot, held: swapped } : interrupted.snapshot;
        expect(later.snapshot).toEqual(asRead);
      } else {
        expect(later.result.kind).toBe('REJECTED');
        expect(later.snapshot).toBe(null);
      }
    }
  });

  test('p08: two P01 defects in one observation follow the ratified order whatever the member order', () => {
    const withAccessor = (first) => {
      const value = first === 'unknown' ? { extra: 1 } : {};
      Object.defineProperty(value, 'updateForm', { enumerable: true, get() { return 'SUPPORTED'; } });
      Object.assign(value, { slotContext: SLOT.slice(), commitOutcome: null, operationIdentity: null, stagedOutput: null });
      if (first !== 'unknown') value.extra = 1;
      return value;
    };
    for (const first of ['accessor', 'unknown']) {
      const result = selfUpdate(SLOT.slice(), withAccessor(first));
      expect(code(result.result)).toBe('UNKNOWN_FIELD');
      expect(result.snapshot).toBe(null);
    }
    // A descriptor read that throws is an INVALID_REQUEST defect; the unknown member still preempts it.
    const throwing = new Proxy({ extra: 1, slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: null, operationIdentity: null, stagedOutput: null }, {
      getOwnPropertyDescriptor(target, key) {
        if (key === 'updateForm') throw new Error('hostile descriptor');
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    const thrown = selfUpdate(SLOT.slice(), throwing);
    expect(code(thrown.result)).toBe('UNKNOWN_FIELD');
    expect(thrown.snapshot).toBe(null);
  });

  test('a snapshot that swaps its hold between reads never reports or clears another mutation', () => {
    // Review finding (cycle 5b): the hold is decoded once from the caller's snapshot, and that one copy
    // is what is validated, decided and succeeded, so later descriptor reads cannot substitute a valid
    // hold of another mutation with the same reference (C-MUT §5, §6).
    const id = 'held-swap-normal';
    const pending = heldUpdate(id);
    const reference = heldRef(id);
    const committed = reconcileWith(SLOT.slice(), pending, reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference).snapshot;
    expect(committed.held.terminalEvidenceStatus).toBe('COMMITTED');
    const replacement = heldJoin(id).held;
    expect(replacement.reconciliationRef).toBe(committed.held.reconciliationRef);
    for (let swapFrom = 1; swapFrom <= 8; swapFrom += 1) {
      let reads = 0;
      const hostile = () => {
        reads = 0;
        return new Proxy({ ...committed }, {
          getOwnPropertyDescriptor(target, key) {
            if (key !== 'held') return Reflect.getOwnPropertyDescriptor(target, key);
            reads += 1;
            return { value: reads >= swapFrom ? replacement : committed.held, writable: true, enumerable: true, configurable: true };
          },
        });
      };
      // Whatever the snapshot answers on its first read of `held` is the one snapshot the call sees: the
      // answer equals the answer for that plain snapshot, and `held` is read exactly once.
      const seen = swapFrom === 1 ? { ...committed, held: replacement } : committed;
      for (const observation of [
        reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }),
        reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }),
        reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: null }),
        reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }),
      ]) {
        const throughProxy = reconcileWith(SLOT.slice(), hostile(), observation, reference);
        expect(reads).toBe(1);
        const plain = reconcileWith(SLOT.slice(), seen, observation, reference);
        expect({ ...throughProxy.result, requestId: null }).toEqual({ ...plain.result, requestId: null });
        expect(throughProxy.snapshot).toEqual(plain.snapshot);
      }
    }
    // The committed SELF_UPDATE itself is never reported as another mutation nor cleared as NOT_COMMITTED.
    const success = reconcileWith(SLOT.slice(), committed, reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }), reference);
    expect(success.result.output.originalSuccessCode).toBe('SELF_UPDATED');
    const cleared = reconcileWith(SLOT.slice(), committed,
      reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
    expect(cleared.result.kind).toBe('INDETERMINATE');
    expect(cleared.snapshot).toEqual(committed);
  });

  test('a snapshot copy that fails part-way fails closed and never falls back to the caller object', () => {
    // Review finding (cycle 5c): when reading the caller's snapshot or its hold throws, the adapter must
    // not complete the copy from the live object, which could then answer a different hold.
    const id = 'held-copy-fail';
    const reference = heldRef(id);
    const committed = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference).snapshot;
    const replacement = heldCreate(id).held;
    expect(replacement.reconciliationRef).toBe(committed.held.reconciliationRef);
    const observations = [
      reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }),
      reconcileObservation({ heldOutput: { embeddedTreeWelcome: STAGED } }),
      reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }),
      reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: null }),
    ];
    const failOuter = () => {
      let reads = 0;
      return new Proxy({ ...committed }, {
        getOwnPropertyDescriptor(target, key) {
          if (key !== 'held') return Reflect.getOwnPropertyDescriptor(target, key);
          reads += 1;
          if (reads === 1) throw new Error('first read fails');
          return { value: reads === 2 ? committed.held : replacement, writable: true, enumerable: true, configurable: true };
        },
      });
    };
    const failInner = () => {
      let reads = 0;
      const held = new Proxy({ ...committed.held }, {
        getOwnPropertyDescriptor(target, key) {
          reads += 1;
          if (reads === 1) throw new Error('first member read fails');
          return Reflect.getOwnPropertyDescriptor(reads > 20 ? replacement : target, key);
        },
      });
      return { state: committed.state, held };
    };
    for (const make of [failOuter, failInner]) {
      for (const observation of observations) {
        const result = reconcileWith(SLOT.slice(), make(), observation, reference);
        expect(result.result.kind).toBe('REJECTED');
        expect(code(result.result)).toBe('FAIL_CLOSED_INTERNAL');
        expect(result.snapshot).toBe(null);
      }
    }
  });

  test('an own __proto__ member of the snapshot or of its hold is still an unknown field', () => {
    // Review finding (cycle 5c): copying the snapshot must keep every own key, including `__proto__`.
    const outer = { state: 'ACTIVE', held: null };
    Object.defineProperty(outer, '__proto__', { value: 'unknown', enumerable: true, writable: true, configurable: true });
    const direct = transitionAdapter(outer, { operation: 'RESTORE', applicableErrors: [], facts: 'NO_STORED_SESSION' });
    expect(direct.result.code).toBe('UNKNOWN_FIELD');
    const update = selfUpdate(SLOT.slice(), updateObservation({ stagedOutput: { protectedCommitBytes: STAGED } }), outer);
    expect(code(update.result)).toBe('UNKNOWN_FIELD');
    expect(update.snapshot).toBe(null);
    const id = 'held-proto';
    const pending = heldUpdate(id);
    const held = { ...pending.held };
    Object.defineProperty(held, '__proto__', { value: 'unknown', enumerable: true, writable: true, configurable: true });
    const reconciled = reconcileWith(SLOT.slice(), { state: pending.state, held },
      reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }), heldRef(id));
    expect(code(reconciled.result)).toBe('UNKNOWN_FIELD');
    expect(reconciled.snapshot).toBe(null);
  });

  test('an unknown snapshot or hold member preempts a malformed one whatever the member order (cycle 5d review)', () => {
    const data = (value) => ({ value, enumerable: true, writable: true, configurable: true });
    const accessor = { enumerable: true, configurable: true, get() { throw new Error('never invoked'); } };
    const build = (entries) => {
      const value = {};
      for (const [key, descriptor] of entries) Object.defineProperty(value, key, descriptor);
      return value;
    };
    for (const entries of [
      [['state', data('ACTIVE')], ['held', accessor], ['extra', data(1)]],
      [['extra', data(1)], ['state', data('ACTIVE')], ['held', accessor]],
    ]) {
      const result = selfUpdate(SLOT.slice(), updateObservation({ stagedOutput: { protectedCommitBytes: STAGED } }), build(entries));
      expect(code(result.result)).toBe('UNKNOWN_FIELD');
      expect(result.snapshot).toBe(null);
    }
    const id = 'held-order';
    const pending = heldUpdate(id);
    const members = Object.entries(pending.held).filter(([key]) => key !== 'scenario').map(([key, value]) => [key, data(value)]);
    const observation = reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } });
    for (const entries of [
      [...members, ['scenario', accessor], ['extra', data(1)]],
      [['extra', data(1)], ['scenario', accessor], ...members],
    ]) {
      const snapshot = build([['state', data(pending.state)], ['held', data(build(entries))]]);
      const result = reconcileWith(SLOT.slice(), snapshot, observation, heldRef(id));
      expect(code(result.result)).toBe('UNKNOWN_FIELD');
      expect(result.snapshot).toBe(null);
    }
  });

  test('the public validator uses one decoded request: two invalid presentations never combine into a valid one (cycle 5e review)', () => {
    const first = request('SELF_UPDATE', {}, { api: 'styx-m2-session-adapter/v2' });
    const second = request('SELF_UPDATE', { extra: 1 });
    expect(validateAdapterRequest(first).ok).toBe(false);
    expect(validateAdapterRequest(second).ok).toBe(false);
    let reads = 0;
    const proxy = new Proxy({ ...first }, {
      ownKeys(target) { return Reflect.ownKeys(target); },
      getOwnPropertyDescriptor(target, key) {
        if (key === 'api') reads += 1;
        const source = reads > 1 ? second : first;
        return Reflect.getOwnPropertyDescriptor(source, key);
      },
    });
    const verdict = validateAdapterRequest(proxy);
    expect(verdict.ok).toBe(false);
    expect(verdict.code).toBe('UNSUPPORTED_API_VERSION');
    expect(reads).toBe(1);
  });

  test('a readable nested input defect competes with a malformed request member at P01 (cycle 5e review)', () => {
    const accessor = { enumerable: true, configurable: true, get() { throw new Error('never invoked'); } };
    const malformedApi = request('SELF_UPDATE', { extra: 1 });
    Object.defineProperty(malformedApi, 'api', accessor);
    expect(validateAdapterRequest(malformedApi).code).toBe('UNKNOWN_FIELD');
    expect(code(invokeAdapter({ request: malformedApi, snapshot: active(), observation: updateObservation({}) }))).toBe('UNKNOWN_FIELD');
    const malformedOnly = request('SELF_UPDATE', {});
    Object.defineProperty(malformedOnly, 'api', accessor);
    expect(validateAdapterRequest(malformedOnly).code).toBe('INVALID_REQUEST');
  });

  test('a malformed hold value preempts an out-of-set one (cycle 5e review)', () => {
    const id = 'held-values';
    const pending = heldUpdate(id);
    const observation = reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } });
    const both = { state: pending.state, held: { ...pending.held, originalStateBefore: 'unknown', operationIdentity: 42 } };
    expect(code(reconcileWith(SLOT.slice(), both, observation, heldRef(id)).result)).toBe('INVALID_REQUEST');
    const outOfSetOnly = { state: pending.state, held: { ...pending.held, originalStateBefore: 'unknown' } };
    expect(code(reconcileWith(SLOT.slice(), outOfSetOnly, observation, heldRef(id)).result)).toBe('UNKNOWN_VALUE');
    const badStatus = { state: pending.state, held: { ...pending.held, scenario: 'CAPI-S999', terminalEvidenceStatus: 'LATER' } };
    expect(code(reconcileWith(SLOT.slice(), badStatus, observation, heldRef(id)).result)).toBe('INVALID_REQUEST');
  });

  test('an unknown RS outcome after the commit request is INDETERMINATE, and a committed hold is kept (cycle 5e review)', () => {
    const id = 'held-unknown';
    const reference = heldRef(id);
    const committed = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference).snapshot;
    expect(committed.held.terminalEvidenceStatus).toBe('COMMITTED');
    for (const outcome of ['unknown', 42, true, { kind: 'COMMITTED' }]) {
      // The held escrow is a required SS fact; for a hold RS has proved COMMITTED, withholding it retains the
      // hold too (C-API `/rules/internalFailureBoundary`), so both readbacks are exercised.
      for (const heldOutput of [{ protectedCommitBytes: STAGED }, null]) {
        const kept = reconcileWith(SLOT.slice(), committed, reconcileObservation({ commitOutcome: outcome, responseEmission: null, heldOutput }), reference);
        expect(kept.result.kind).toBe('INDETERMINATE');
        expect(kept.snapshot).toEqual(committed);
      }
      const pending = heldUpdate(id);
      const still = reconcileWith(SLOT.slice(), pending, reconcileObservation({ commitOutcome: outcome, responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
      expect(still.result.kind).toBe('INDETERMINATE');
      expect(still.snapshot).toEqual(pending);
      const issued = selfUpdate(SLOT.slice(), updateObservation({ commitOutcome: outcome, stagedOutput: { protectedCommitBytes: STAGED } }));
      expect(issued.result.kind).toBe('INDETERMINATE');
      expect(issued.snapshot.state).toBe('RECONCILIATION_REQUIRED');
      expect(issued.result.output).toBe(undefined);
    }
  });

  test('a COMMITTED self-update retained for a late escrow failure keeps its COMMITTED proof (cycle 5f review)', () => {
    for (const stagedOutput of [null, { protectedCommitBytes: new Uint8Array(0) }]) {
      const first = selfUpdate(SLOT.slice(), updateObservation({ operationIdentity: 'late-escrow', stagedOutput }));
      expect(first.result.kind).toBe('INDETERMINATE');
      expect(first.result.output).toBe(undefined);
      expect(first.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
      const reference = first.result.reconciliationRef;
      for (const later of [
        { commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } },
        { commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } },
      ]) {
        const second = reconcileWith(SLOT.slice(), first.snapshot, reconcileObservation(later), reference);
        expect(second.result.kind).toBe('INDETERMINATE');
        expect(second.snapshot).toEqual(first.snapshot);
      }
      const released = reconcileWith(SLOT.slice(), first.snapshot, reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } }), reference);
      expect(released.result.kind).toBe('SUCCESS');
      expect(Array.from(released.result.output.originalOutput.protectedCommitBytes)).toEqual(Array.from(STAGED));
    }
    // An INDETERMINATE self-update with a late escrow failure keeps the PENDING hold the core builds.
    const ambiguous = selfUpdate(SLOT.slice(), updateObservation({ commitOutcome: 'INDETERMINATE', operationIdentity: 'late-pending', stagedOutput: null }));
    expect(ambiguous.snapshot.held.terminalEvidenceStatus).toBe('PENDING');
  });

  test('a matching readback never rejects a COMMITTED hold for an escrow it cannot hand over (cycle 5f review)', () => {
    const id = 'held-escrow-missing';
    const reference = heldRef(id);
    const committed = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference).snapshot;
    for (const later of [
      { commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: null },
      { commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: null },
      { commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: { protectedCommitBytes: new Uint8Array(0) } },
      { commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: { embeddedTreeWelcome: WELCOME } },
      { commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: { protectedCommitBytes: STAGED, extra: 1 } },
    ]) {
      const result = reconcileWith(SLOT.slice(), committed, reconcileObservation(later), reference);
      expect(result.result.kind).toBe('INDETERMINATE');
      expect(result.result.output).toBe(undefined);
      expect(result.snapshot).toEqual(committed);
    }
    // A PENDING hold that this readback proves COMMITTED is retained the same way, with the proof recorded;
    // a later NOT_COMMITTED readback then cannot clear it (cycle 5g review).
    for (const heldOutput of [null, { protectedCommitBytes: STAGED, extra: 1 }]) {
      const first = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ heldOutput }), reference);
      expect(first.result.kind).toBe('INDETERMINATE');
      expect(first.result.output).toBe(undefined);
      expect(first.snapshot).toEqual(committed);
      const second = reconcileWith(SLOT.slice(), first.snapshot, reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
      expect(second.result.kind).toBe('INDETERMINATE');
      expect(second.snapshot).toEqual(committed);
    }
    // An escrow defect with no COMMITTED proof, recorded or reported, stays the P01 rejection.
    expect(code(reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED, extra: 1 } }), reference).result)).toBe('UNKNOWN_FIELD');
    // The base table's escrow defects, carried by a COMMITTED readback, retain the hold with the proof.
    for (const heldOutput of [{ protectedCommitBytes: STAGED, embeddedTreeWelcome: WELCOME }, { embeddedTreeWelcome: WELCOME }, null]) {
      const retained = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ heldOutput }), reference);
      expect(retained.result.kind).toBe('INDETERMINATE');
      expect(retained.snapshot).toEqual(committed);
    }
    // A non-matching reference keeps its own CAPI-S028 answer; its escrow defect stays a P01 defect.
    const mismatch = reconcileWith(SLOT.slice(), committed, reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), heldRef('other'));
    expect(mismatch.result.kind).toBe('REJECTED');
    expect(code(mismatch.result)).toBe('RECONCILIATION_REFERENCE_MISMATCH');
    expect(code(reconcileWith(SLOT.slice(), committed, reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: null }), heldRef('other')).result)).toBe('INVALID_REQUEST');
  });

  test('a COMMITTED readback whose emission fact fails keeps its proof (cycle 5h review)', () => {
    const id = 'held-emission';
    const reference = heldRef(id);
    const committed = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference).snapshot;
    for (const responseEmission of [null, 7, 'DELIVERED']) {
      const first = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ responseEmission }), reference);
      expect(first.result.kind).toBe('INDETERMINATE');
      expect(first.result.output).toBe(undefined);
      expect(first.snapshot).toEqual(committed);
      const later = reconcileWith(SLOT.slice(), first.snapshot, reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
      expect(later.result.kind).toBe('INDETERMINATE');
      expect(later.snapshot).toEqual(committed);
      // A reference that does not name the hold keeps the emission defect at P01.
      expect(code(reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ responseEmission }), heldRef('other')).result))
        .toBe(responseEmission === 'DELIVERED' ? 'UNKNOWN_VALUE' : 'INVALID_REQUEST');
    }
    // An emission fact on a non-COMMITTED readback stays a P01 defect even with the matching reference.
    expect(code(reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: 'SUCCEEDED', heldOutput: null }), reference).result)).toBe('INVALID_REQUEST');
    // An omitted emission member on a later non-COMMITTED readback retains a hold RS already proved
    // COMMITTED, and stays the P01 rejection for a PENDING hold (cycle 5k review).
    const omittedEmission = withoutMember(reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), 'responseEmission');
    const retainedLater = reconcileWith(SLOT.slice(), committed, omittedEmission, reference);
    expect(retainedLater.result.kind).toBe('INDETERMINATE');
    expect(retainedLater.snapshot).toEqual(committed);
    expect(code(reconcileWith(SLOT.slice(), heldUpdate(id), omittedEmission, reference).result)).toBe('INVALID_REQUEST');
  });

  test('a COMMITTED proof survives an omitted, accessor or unreadable evidence member (cycle 5i review)', () => {
    const id = 'held-evidence';
    const reference = heldRef(id);
    const committed = reconcileWith(SLOT.slice(), heldUpdate(id), reconcileObservation({ responseEmission: 'INTERRUPTED' }), reference).snapshot;
    const throwing = (record, key) => new Proxy(record, {
      getOwnPropertyDescriptor(object, member) {
        if (member === key) throw new Error('unreadable');
        return Reflect.getOwnPropertyDescriptor(object, member);
      },
    });
    const nonEnumerable = (record, key) => {
      const copy = { ...record };
      Object.defineProperty(copy, key, { enumerable: false });
      return copy;
    };
    const base = reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } });
    const variants = [];
    for (const key of ['responseEmission', 'heldOutput']) {
      variants.push(withoutMember(base, key), withAccessor(base, key, { count: 0, value: null }), throwing(base, key), nonEnumerable(base, key));
    }
    for (const observation of variants) {
      const first = reconcileWith(SLOT.slice(), heldUpdate(id), observation, reference);
      expect(first.result.kind).toBe('INDETERMINATE');
      expect(first.result.output).toBe(undefined);
      expect(first.snapshot).toEqual(committed);
      const later = reconcileWith(SLOT.slice(), first.snapshot, reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), reference);
      expect(later.result.kind).toBe('INDETERMINATE');
      expect(later.snapshot).toEqual(committed);
      // With a reference that does not name the hold the shape defect stays the P01 rejection.
      expect(code(reconcileWith(SLOT.slice(), heldUpdate(id), observation, heldRef('other')).result)).toBe('INVALID_REQUEST');
    }
    // An omitted RS outcome is the still-ambiguous readback: the PENDING hold is kept unchanged.
    const pending = heldUpdate(id);
    const omitted = reconcileWith(SLOT.slice(), pending, withoutMember(reconcileObservation({ responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), 'commitOutcome'), reference);
    expect(omitted.result.kind).toBe('INDETERMINATE');
    expect(omitted.snapshot).toEqual(pending);
    // An emission fact beside an omitted outcome is an emission on a non-COMMITTED readback: P01.
    expect(code(reconcileWith(SLOT.slice(), pending, withoutMember(base, 'commitOutcome'), reference).result)).toBe('INVALID_REQUEST');
    // A non-evidence member keeps its P01 rejection whatever the outcome.
    expect(code(reconcileWith(SLOT.slice(), heldUpdate(id), withoutMember(base, 'slotContext'), reference).result)).toBe('INVALID_REQUEST');
    // Without a COMMITTED proof an omitted escrow stays the P01 rejection.
    expect(code(reconcileWith(SLOT.slice(), heldUpdate(id), withoutMember(reconcileObservation({ commitOutcome: 'NOT_COMMITTED', responseEmission: null }), 'heldOutput'), reference).result)).toBe('INVALID_REQUEST');
  });

  test('an issued SELF_UPDATE with an omitted RS outcome or escrow is held, never rejected (cycle 5i review)', () => {
    const issued = { slotContext: SLOT.slice(), updateForm: 'SUPPORTED', operationIdentity: 'issued', commitOutcome: 'INDETERMINATE', stagedOutput: { protectedCommitBytes: STAGED } };
    const reference = invokeAdapterTransition({ request: request('SELF_UPDATE', {}), snapshot: active(), observation: issued });
    for (const observation of [withoutMember(issued, 'commitOutcome'), withAccessor(issued, 'commitOutcome', { count: 0, value: 'COMMITTED' })]) {
      const answer = invokeAdapterTransition({ request: request('SELF_UPDATE', {}), snapshot: active(), observation });
      expect(answer.result.kind).toBe('INDETERMINATE');
      expect(answer.snapshot).toEqual(reference.snapshot);
    }
    const committedNoEscrow = invokeAdapterTransition({ request: request('SELF_UPDATE', {}), snapshot: active(), observation: withoutMember({ ...issued, commitOutcome: 'COMMITTED' }, 'stagedOutput') });
    expect(committedNoEscrow.result.kind).toBe('INDETERMINATE');
    expect(committedNoEscrow.result.output).toBe(undefined);
    expect(committedNoEscrow.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
    // An issued, not-committed update whose escrow member fails is held (INDETERMINATE) or closed
    // (NOT_COMMITTED) exactly as with an absent escrow, releasing nothing (cycle 5j review).
    for (const [outcome, kind] of [['INDETERMINATE', 'INDETERMINATE'], ['NOT_COMMITTED', 'NOT_COMMITTED']]) {
      const failedEscrow = invokeAdapterTransition({ request: request('SELF_UPDATE', {}), snapshot: active(), observation: withoutMember({ ...issued, commitOutcome: outcome }, 'stagedOutput') });
      expect(failedEscrow.result.kind).toBe(kind);
      expect(failedEscrow.result.output).toBe(undefined);
      if (kind === 'INDETERMINATE') expect(failedEscrow.snapshot.held.terminalEvidenceStatus).toBe('PENDING');
    }
    // A readable non-enumerable escrow's nested unknown member still preempts at P01.
    const hidden = { ...issued, operationIdentity: null, commitOutcome: null, stagedOutput: { protectedCommitBytes: STAGED, extra: true } };
    Object.defineProperty(hidden, 'stagedOutput', { enumerable: false });
    expect(code(invokeAdapterTransition({ request: request('SELF_UPDATE', {}), snapshot: active(), observation: hidden }).result)).toBe('UNKNOWN_FIELD');
    // A readable non-enumerable escrow is decided by its value exactly as an enumerable one (cycle 5k review).
    for (const outcome of ['INDETERMINATE', 'COMMITTED']) {
      const plain = { ...issued, commitOutcome: outcome, stagedOutput: { protectedCommitBytes: 'invalid' } };
      const hiddenBad = { ...plain };
      Object.defineProperty(hiddenBad, 'stagedOutput', { enumerable: false });
      const sameRequest = request('SELF_UPDATE', {});
      const expected = invokeAdapterTransition({ request: sameRequest, snapshot: active(), observation: plain });
      const answer = invokeAdapterTransition({ request: sameRequest, snapshot: active(), observation: hiddenBad });
      expect(answer).toEqual(expected);
    }
    // With no operation identity no request was issued: the omitted outcome stays the P01 defect.
    const unissued = invokeAdapterTransition({ request: request('SELF_UPDATE', {}), snapshot: active(), observation: withoutMember({ ...issued, operationIdentity: null }, 'commitOutcome') });
    expect(code(unissued.result)).toBe('INVALID_REQUEST');
    // An unknown member still preempts at P01.
    const unknown = invokeAdapterTransition({ request: request('SELF_UPDATE', {}), snapshot: active(), observation: { ...withoutMember(issued, 'commitOutcome'), extra: 1 } });
    expect(code(unknown.result)).toBe('UNKNOWN_FIELD');
  });

  test('a readable non-enumerable data member still lets its nested P01 defect compete (cycle 5i review)', () => {
    const value = request('SELF_UPDATE', { extra: 1 });
    Object.defineProperty(value, 'input', { enumerable: false });
    expect(validateAdapterRequest(value).code).toBe('UNKNOWN_FIELD');
  });

  test('integration decides on one decoded request: a Proxy cannot validate one operation and dispatch another (cycle 5f review)', () => {
    const target = request('SELF_UPDATE', { peerFramedKeyPackage: bytes(0x01) });
    let reads = 0;
    const proxy = new Proxy(target, {
      getOwnPropertyDescriptor(object, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(object, key);
        if (key !== 'operation') return descriptor;
        reads += 1;
        return { ...descriptor, value: reads === 1 ? 'CREATE' : 'SELF_UPDATE' };
      },
    });
    const answer = invokeAdapterTransition({
      request: proxy,
      snapshot: empty(),
      observation: { onboarding: 'SUPPORTED', commitOutcome: 'COMMITTED', operationIdentity: 'probe', stagedOutput: { embeddedTreeWelcome: WELCOME } },
    });
    expect(reads).toBe(1);
    // The one read said CREATE, so the call is a CREATE throughout: validated, dispatched and released as
    // CREATED with its Welcome, never a SELF_UPDATE validation with a CREATE dispatch.
    expect(answer.result.kind).toBe('SUCCESS');
    expect(answer.result.successCode).toBe('CREATED');
    expect(answer.result.requestId).toBe(target.requestId);
    expect(answer.snapshot.state).toBe('ACTIVE');
  });

  test('nested P01 defects compete with the outer record whatever the member order (cycle 5f review)', () => {
    const accessor = { enumerable: true, configurable: true, get() { throw new Error('never invoked'); } };
    // A descriptor read that throws on one request member does not hide a readable input's unknown member.
    const target = request('SELF_UPDATE', { extra: 1 });
    const throwing = new Proxy(target, {
      getOwnPropertyDescriptor(object, key) {
        if (key === 'api') throw new Error('descriptor read');
        return Reflect.getOwnPropertyDescriptor(object, key);
      },
    });
    expect(validateAdapterRequest(throwing).code).toBe('UNKNOWN_FIELD');
    // An accessor observation member does not hide a readable staged escrow's unknown member.
    const observation = updateObservation({ stagedOutput: { protectedCommitBytes: STAGED, extra: 1 } });
    Object.defineProperty(observation, 'updateForm', accessor);
    expect(code(selfUpdate(SLOT.slice(), observation).result)).toBe('UNKNOWN_FIELD');
    // Nor a held escrow carrying two recognised output members (cycle 5g review).
    const twoMembers = reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED, embeddedTreeWelcome: WELCOME } });
    expect(code(reconcileWith(SLOT.slice(), empty(), twoMembers, heldRef('x')).result)).toBe('UNKNOWN_FIELD');
    Object.defineProperty(twoMembers, 'responseEmission', accessor);
    expect(code(reconcileWith(SLOT.slice(), empty(), twoMembers, heldRef('x')).result)).toBe('UNKNOWN_FIELD');
    // A plan-identity inconsistency is INVALID_REQUEST and outranks an out-of-set original state.
    const id = 'held-plan';
    const pending = heldUpdate(id);
    const both = { state: pending.state, held: { ...pending.held, originalStateBefore: 'UNKNOWN', mutationPlanIdentity: 'WRONG' } };
    const reconcile = reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED } });
    expect(code(reconcileWith(SLOT.slice(), both, reconcile, heldRef(id)).result)).toBe('INVALID_REQUEST');
    const planFixed = { state: pending.state, held: { ...pending.held, originalStateBefore: 'UNKNOWN', outputKind: 'NONE' } };
    expect(code(reconcileWith(SLOT.slice(), planFixed, reconcile, heldRef(id)).result)).toBe('INVALID_REQUEST');
    const outOfSetOnly = { state: pending.state, held: { ...pending.held, originalStateBefore: 'UNKNOWN' } };
    expect(code(reconcileWith(SLOT.slice(), outOfSetOnly, reconcile, heldRef(id)).result)).toBe('UNKNOWN_VALUE');
  });
});
