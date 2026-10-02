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

let counter = 0;
const request = (operation, input, overrides = {}) => ({
  api: API,
  operation,
  requestId: `req-iupd-${++counter}`,
  profile: { ...PROFILE },
  bindingRef: new Uint8Array([0x01, 0x02, 0x03]),
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

const updateObservation = ({ updateForm = 'SUPPORTED', commitOutcome = 'COMMITTED', stagedOutput = undefined } = {}) => ({
  updateForm,
  commitOutcome,
  operationIdentity: commitOutcome === null ? null : 'op-upd-1',
  stagedOutput: stagedOutput === undefined
    ? (commitOutcome === null ? null : { protectedCommitBytes: STAGED })
    : stagedOutput,
});

const reconcileObservation = ({ commitOutcome = 'COMMITTED', responseEmission = 'SUCCEEDED', heldOutput = undefined } = {}) => ({
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
      'CREATE', 'RESTORE', 'JOIN_WELCOME', 'SELF_UPDATE', 'RECONCILE_INDETERMINATE',
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
    const refused = { updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: null, operationIdentity: null, stagedOutput: null };
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
      updateForm: 'UNSUPPORTED_UPDATE_FORM',
      commitOutcome: null,
      operationIdentity: null,
      stagedOutput: { protectedCommitBytes: 7 },
    });
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe('INVALID_REQUEST');
  });

  test('a staged update with no active session is refused', () => {
    const result = invoke('SELF_UPDATE', empty(), updateObservation({}));
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe('NO_ACTIVE_SESSION');
    expect(result.stateAfter).toBe('EMPTY');
  });

  test('a valid C-API operation outside this slice stays UNSUPPORTED_OPERATION', () => {
    const outside = [
      ['PROTECT_APPLICATION', { applicationBytes: bytes(0x01) }],
      ['OPEN_APPLICATION', { protectedApplicationMessage: bytes(0x01) }],
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

  test('a committed Welcome that holds no escrow reconciles with a null original output', () => {
    const result = reconcile(heldJoin(), reconcileObservation({ heldOutput: null }), heldRef('held-join-1'));
    assertEnvelope(result, 'SUCCESS', ['successCode', 'output']);
    expect(result.output.originalSuccessCode).toBe('JOINED');
    expect(result.output.originalOutput).toBe(null);
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
  const noProofReconcile = reconcileObservation({ commitOutcome: null, responseEmission: null, heldOutput: null });

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
    ['malformed input of an outside operation', request('PROTECT_APPLICATION', {}), active(), okUpdate, 'INVALID_REQUEST'],
    ['unknown input member', request('SELF_UPDATE', { extra: 1 }), active(), okUpdate, 'UNKNOWN_FIELD'],
    ['missing reconcile reference', request('RECONCILE_INDETERMINATE', {}), active(), noProofReconcile, 'INVALID_REQUEST'],
    ['empty reconcile reference', request('RECONCILE_INDETERMINATE', { reconciliationRef: '' }), active(), noProofReconcile, 'INVALID_REQUEST'],
    ['non-string reconcile reference', request('RECONCILE_INDETERMINATE', { reconciliationRef: 7 }), active(), noProofReconcile, 'INVALID_REQUEST'],
    ['non-closed observation', request('SELF_UPDATE', {}), active(), { ...okUpdate, extra: 1 }, 'UNKNOWN_FIELD'],
    ['missing observation member', request('SELF_UPDATE', {}), active(), withoutMember(okUpdate, 'stagedOutput'), 'INVALID_REQUEST'],
    ['out-of-set update form', request('SELF_UPDATE', {}), active(), { ...okUpdate, updateForm: 'PROPOSAL_FREE' }, 'UNKNOWN_VALUE'],
    ['malformed staged output with an unsupported form', request('SELF_UPDATE', {}), active(), { updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: null, operationIdentity: null, stagedOutput: { protectedCommitBytes: 'x' } }, 'INVALID_REQUEST'],
    ['supported form without a commit proof', request('SELF_UPDATE', {}), active(), { updateForm: 'SUPPORTED', commitOutcome: null, operationIdentity: null, stagedOutput: null }, 'INVALID_REQUEST'],
    ['staged output without a commit proof', request('SELF_UPDATE', {}), active(), { updateForm: 'SUPPORTED', commitOutcome: null, operationIdentity: null, stagedOutput: { protectedCommitBytes: STAGED } }, 'INVALID_REQUEST'],
    ['commit proof without a supported form', request('SELF_UPDATE', {}), active(), { updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: 'COMMITTED', operationIdentity: 'op-upd-1', stagedOutput: null }, 'INVALID_REQUEST'],
    ['staged output of the wrong member', request('SELF_UPDATE', {}), active(), updateObservation({ stagedOutput: { embeddedTreeWelcome: WELCOME } }), 'UNKNOWN_FIELD'],
    ['staged output of the wrong type', request('SELF_UPDATE', {}), active(), updateObservation({ stagedOutput: { protectedCommitBytes: 7 } }), 'INVALID_REQUEST'],
    ['out-of-set commit outcome', request('SELF_UPDATE', {}), active(), { ...okUpdate, commitOutcome: 'MAYBE' }, 'UNKNOWN_VALUE'],
    ['missing operation identity after a commit proof', request('SELF_UPDATE', {}), active(), { ...okUpdate, operationIdentity: null }, 'INVALID_REQUEST'],
    ['empty operation identity after a commit proof', request('SELF_UPDATE', {}), active(), { ...okUpdate, operationIdentity: '' }, 'INVALID_REQUEST'],
    ['out-of-set response emission', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ responseEmission: 'DELIVERED' }), 'UNKNOWN_VALUE'],
    ['response emission for an outcome that cannot have one', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: 'SUCCEEDED', heldOutput: null }), 'INVALID_REQUEST'],
    ['missing response emission for a committed outcome', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ responseEmission: null }), 'INVALID_REQUEST'],
    ['held escrow of two members', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ heldOutput: { protectedCommitBytes: STAGED, embeddedTreeWelcome: WELCOME } }), 'UNKNOWN_FIELD'],
    ['held escrow that is not the held mutation\'s escrow', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ heldOutput: { embeddedTreeWelcome: WELCOME } }), 'INVALID_REQUEST'],
    ['held escrow offered while nothing is held', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), active(), reconcileObservation({ commitOutcome: 'INDETERMINATE', responseEmission: null, heldOutput: { protectedCommitBytes: STAGED } }), 'INVALID_REQUEST'],
    ['held escrow withheld while the held kind names one', request('RECONCILE_INDETERMINATE', { reconciliationRef: heldRef('held-upd-1') }), heldUpdate(), reconcileObservation({ heldOutput: null }), 'INVALID_REQUEST'],
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
    expect(Object.isFrozen(validateAdapterRequest(request('SELF_UPDATE', {})))).toBe(true);
  });

  test('no accessor of any injected record is ever invoked', () => {
    const reads = { count: 0 };
    const result = invokeAdapter({
      request: request('SELF_UPDATE', {}),
      snapshot: active(),
      observation: withAccessor(okUpdate, 'commitOutcome', reads),
    });
    expect(code(result)).toBe('INVALID_REQUEST');
    expect(reads.count).toBe(0);
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
});
describe('I-UPD total precedence and the internal failure boundary', () => {
  test('the lowest precedence level present decides, whatever its order in the request', () => {
    const several = request('ADD_MEMBER', {}, { extra: 1, api: 'styx-m2-session-adapter/v2' });
    expect(code(invokeAdapter({ request: several, snapshot: active(), observation: updateObservation({}) })))
      .toBe('UNKNOWN_FIELD');
    const apiThenOperation = request('PROTECT_APPLICATION', { applicationBytes: bytes(0x01) },
      { api: 'styx-m2-session-adapter/v2' });
    expect(code(invokeAdapter({ request: apiThenOperation, snapshot: active(), observation: updateObservation({}) })))
      .toBe('UNSUPPORTED_API_VERSION');
    const profileThenBinding = request('SELF_UPDATE', {},
      { profile: { ...PROFILE, pastEpochWindow: 1 }, bindingRef: new Uint8Array(0) });
    expect(code(invokeAdapter({ request: profileThenBinding, snapshot: active(), observation: updateObservation({}) })))
      .toBe('UNSUPPORTED_PROFILE');
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
      observation: { updateForm: 'UNSUPPORTED_UPDATE_FORM', commitOutcome: null, operationIdentity: null, stagedOutput: null },
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
      const first = invokeAdapter(input);
      const second = invokeAdapter(input);
      expect(first).toEqual(second);
      expect(Object.isFrozen(first.result)).toBe(true);
      expect(observation).toEqual(before);
      expect(input.observation).toEqual(before);
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
      ),
    });
    fc.assert(fc.property(snapshotArbitrary, observationArbitrary, (snapshot, observation) => {
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
        expect(M2_ADAPTER.COMMIT_OUTCOMES).toContain(observation.commitOutcome);
        expect(result.commitOutcome).toBe('COMMITTED');
        expect(result.successCode).toBe('SELF_UPDATED');
      }
      if (result.kind === 'INDETERMINATE') expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
      if (result.kind === 'NOT_COMMITTED') expect(result.stateAfter).toBe(result.stateBefore);
      if (result.kind === 'REJECTED') {
        expect(M2_ADAPTER.ERROR_CODES).toContain(result.error.code);
        expect(result.stateAfter).toBe(snapshot.state);
      }
    }), { seed: SEED, numRuns: RUNS });
  });

  test('no randomised reconciliation ever releases a member the hold does not fix', () => {
    fc.assert(fc.property(
      snapshotArbitrary,
      fc.oneof(
        fc.constant(null),
        fc.record({ protectedCommitBytes: memberArbitrary }),
        fc.record({ embeddedTreeWelcome: memberArbitrary }),
        fc.record({ protectedCommitBytes: memberArbitrary, embeddedTreeWelcome: memberArbitrary }),
      ),
      memberArbitrary,
      memberArbitrary,
      (snapshot, heldOutput, commitOutcome, responseEmission) => {
        const held = snapshot.held;
        const reference = held === null ? 'I-SM-HOLD:none' : held.reconciliationRef;
        let result;
        try {
          result = invokeAdapter({
            request: request('RECONCILE_INDETERMINATE', { reconciliationRef: reference }),
            snapshot,
            observation: { commitOutcome, responseEmission, heldOutput },
          });
        } catch (error) {
          expect(error).toBeInstanceOf(M2AdapterError);
          return;
        }
        expect(M2_ADAPTER.RESULT_KINDS).toContain(result.kind);
        expect(result.stateBefore).toBe(snapshot.state);
        if (result.kind === 'SUCCESS') {
          expect(result.successCode).toBe('RECONCILED_COMMITTED');
          expect(held).not.toBe(null);
          expect(result.output.originalSuccessCode).toBe(held.expectedSuccessCode);
          if (held.outputKind === 'NONE') expect(result.output.originalOutput).toBe(null);
          else {
            expect(result.output.originalOutput).not.toBe(null);
            expect(Object.keys(result.output.originalOutput)).toEqual([M2_ADAPTER.OUTPUT_MEMBER_BY_KIND[held.outputKind]]);
          }
        }
        if (result.kind === 'INDETERMINATE') {
          expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
          if (held !== null) expect(result.reconciliationRef).toBe(held.reconciliationRef);
        }
      }), { seed: SEED + 1, numRuns: RUNS });
  });
});
