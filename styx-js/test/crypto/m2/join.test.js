// join.test.js — I-JOIN conformance tests for the M2 create / restore / Welcome integration
// adapter (contract Issue #402 of #317 G-SCOPE).
//
// The tests drive the real `invokeAdapter` over the injected request, snapshot and owning-layer
// observation: the seven exact C-REST positive fixtures, all sixty-five C-REST negative fixtures, the
// exact create and Welcome outcomes, the fail-closed request validation, total precedence, the closed
// result envelope, purity and immutability, and a seeded property sweep. Nothing is mocked: the
// decision is taken by the merged I-SM core and, for restore, by the merged I-REST classifier.

import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  M2_ADAPTER,
  M2AdapterError,
  invokeAdapter,
  validateAdapterRequest,
} from '../../../src/crypto/mls/m2/adapter.js';
import { createAdapterSnapshot, transitionAdapter } from '../../../src/crypto/mls/m2/state-machine.js';
import { FRESH_WORKER_FIXTURES, classifyRestore } from '../../../src/storage/m2/session-restore.js';

// The ratified O-SCEN scenario ids this card's implemented clause pointers are mapped to, by the
// clause-identity rule of M2-I-JOIN-SCENARIO-MAPPING.json (see the evidence bundle). The whole blind
// set is 1821 rows; the owner reconciliation list stays OPEN.
const OSCEN_SCENARIOS = {
  '/profile': [
    'OSC-1cd3173a8d0d52bf', 'OSC-3d0ab107f2d76c19', 'OSC-3d3155950c9e5dce', 'OSC-4cf85dd6b70ef6d6',
    'OSC-535209f7230008ff', 'OSC-6ba7acf8b1c1f6ee', 'OSC-7ef76030cc0e9961', 'OSC-902c5a1f4709f544',
    'OSC-b1e08cba48935d8a', 'OSC-b28c0db8ec839cee', 'OSC-d42169b5c40b576a', 'OSC-dec7fa64138c6422',
    'OSC-eb6174b618c6b6cb',
  ],
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
  '/rules/tupleDrift': [
    'OSC-f059cf9976ae30d3',
  ],
  '/rules/bindingMismatch': [
    'OSC-afc7b4725bb5f62d',
  ],
  '/rules/derivedFacts': [
    'OSC-9ebe2108b66fc218',
  ],
  '/rules/rsTriState': [
    'OSC-f4eb5de98aefe7dc',
  ],
  '/rules/internalFailureBoundary': [
    'OSC-c614c21efa1f19d6',
  ],
  '/rules/payloadRelease': [
    'OSC-ab20fdebafb24483',
  ],
  '/rules/restore': [
    'OSC-167372283b0e10d1',
  ],
  '/rules/keyPackageProvisioning': [
    'OSC-fe63306db5665204',
  ],
  '/rules/coarseAnchorRegression': [
    'OSC-567c2503898b28a6',
  ],
  '/rules/legacy': [
    'OSC-108f963d85bcd8fc',
  ],
  '/rules/singleWriter': [
    'OSC-7e009f23be2707b5',
  ],
  '/rules/replayOrder': [
    'OSC-aa1cd1c3211dc823',
  ],
  '/rules/framingEpochBeforeAuthentication': [
    'OSC-7db987734dd9f139',
  ],
  '/rules/completeLogicalMutation': [
    'OSC-3ba76ad1910efd14',
  ],
  '/rules/candidateSelector': [
    'OSC-0885ca4fd15bf91b',
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
  '/nonClaims': [
    'OSC-1713e9b3c317ab0a', 'OSC-2164eca684504a5e', 'OSC-24b30e5e93b43f96', 'OSC-ab78a8b7e93701fc',
    'OSC-eb73a24e35ff6f02', 'OSC-f109b4e5291ca005', 'OSC-f91d7b5219fb980c',
  ],
};

const MAPPING_SHA256 = 'b650f0f6cf755a0d0eadb2a86f39f5824215ff45151c23c42108c91cc22a4a48';
const MAPPING_SCHEMA = 'styx-m2-i-join-scenario-mapping/v1';

const MODULE_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../../../src/crypto/mls/m2/adapter.js');

const PROFILE = M2_ADAPTER.PROFILE;
const API = M2_ADAPTER.API;
const REQUEST_MEMBERS = ['api', 'operation', 'requestId', 'profile', 'bindingRef', 'input'];
const RESULT_COMMON_MEMBERS = ['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter'];
const KIND_MEMBERS = {
  SUCCESS: ['successCode', 'output', 'commitOutcome'],
  NO_CHANGE: ['successCode'],
  NOT_COMMITTED: ['commitOutcome'],
  INDETERMINATE: ['commitOutcome', 'reconciliationRef', 'originalStateBefore'],
  REJECTED: ['error'],
};

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

const createObservation = (onboarding, commitOutcome, stagedOutput) => ({
  onboarding,
  commitOutcome,
  operationIdentity: commitOutcome === null ? null : 'op-create-1',
  stagedOutput: stagedOutput === undefined
    ? (commitOutcome === null ? null : { embeddedTreeWelcome: new Uint8Array([0x11, 0x22]) })
    : stagedOutput,
});

const joinObservation = (keyPackage, commitOutcome) => ({
  keyPackage,
  commitOutcome,
  operationIdentity: commitOutcome === null ? null : 'op-join-1',
});

const restoreObservation = (members) => ({
  restoreObservation: {
    faults: [], inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE',
    ...members,
  },
});

const code = (result) => (result.kind === 'REJECTED' ? result.error.code : result.successCode);

/**
 * The closed observation of one ratified C-REST fixture row, derived from the row's own store members
 * and never from the row's expected result. The selector state is the state of the row's store vector;
 * a row without a vector is exercised under the ACTIVE context C-REST fixes for `gates`-only rows.
 */
const VECTOR_STATE = {
  'FMT-KAT-EMPTY': 'EMPTY',
  'FMT-KAT-ACTIVE': 'ACTIVE',
  'FMT-KAT-HOLD': 'RECONCILIATION_REQUIRED',
  'FMT-KAT-EMPTY-HOLD': 'RECONCILIATION_REQUIRED',
};

function observationOfFixture(row) {
  const inventory = Object.hasOwn(row, 'inventory') ? row.inventory : 'M2';
  const vector = Object.hasOwn(row, 'vector') ? row.vector : 'FMT-KAT-ACTIVE';
  const legacy = Object.hasOwn(row, 'legacy') ? row.legacy : false;
  const faults = Object.hasOwn(row, 'faults') ? row.faults : [];
  const selectorState = vector === null ? 'ACTIVE' : VECTOR_STATE[vector];
  return { restoreObservation: { faults: [...faults], inventory, legacy, vector, selectorState } };
}

const positive = (id) => FRESH_WORKER_FIXTURES.positive.find((row) => row.id === id);
const negatives = FRESH_WORKER_FIXTURES.negative;
const invokeRestore = (observation, snapshot = empty()) => invokeAdapter({
  request: request('RESTORE', {}),
  snapshot,
  observation,
});

const FAIL_CLOSED_POSITIVES = ['POS-EMPTY', 'POS-HOLD', 'POS-EMPTY-HOLD'];

describe('I-JOIN module surface and closure', () => {
  test('the closed metadata is frozen and carries the ratified vocabularies', () => {
    expect(Object.isFrozen(M2_ADAPTER)).toBe(true);
    expect(M2_ADAPTER.API).toBe('styx-m2-session-adapter/v1');
    expect([...M2_ADAPTER.OPERATIONS]).toEqual([
      'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
      'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE',
    ]);
    expect([...M2_ADAPTER.INTEGRATED_OPERATIONS]).toEqual(['CREATE', 'RESTORE', 'JOIN_WELCOME']);
    expect([...M2_ADAPTER.STATES]).toEqual(['EMPTY', 'ACTIVE', 'RECONCILIATION_REQUIRED']);
    expect([...M2_ADAPTER.RESULT_KINDS]).toEqual([
      'SUCCESS', 'NO_CHANGE', 'NOT_COMMITTED', 'INDETERMINATE', 'REJECTED',
    ]);
    expect(M2_ADAPTER.ERROR_CODES).toHaveLength(25);
    expect(M2_ADAPTER.SUCCESS_CODES).toHaveLength(10);
    expect(Object.keys(M2_ADAPTER.PROFILE)).toHaveLength(13);
    expect(M2_ADAPTER.CODE_TO_KIND.CREATED).toBe('SUCCESS');
    expect(M2_ADAPTER.CODE_TO_KIND.FAIL_CLOSED_INTERNAL).toBe('REJECTED');
    expect(Object.isFrozen(M2_ADAPTER.PROFILE)).toBe(true);
    expect(Object.isFrozen(M2_ADAPTER.RESTORE_DISPOSITIONS)).toBe(true);
  });

  test('the C-REST outcome mapping is total over the ratified result sets', () => {
    const outcomes = [
      'NO_M2_STATE', 'LEGACY_ONLY', 'RESTORED_EMPTY', 'RESTORED_ACTIVE',
      'RESTORED_RECONCILIATION_REQUIRED', 'LOCKED_ELSEWHERE', 'WRAPPER_AUTH_FAILED',
      'INCOMPATIBLE_BUILD', 'INCOMPATIBLE_FORMAT', 'UNSUPPORTED_VERSION', 'SELECTOR_INVALID',
      'AUTHENTICATION_FAILED', 'MANIFEST_INVALID', 'RECORD_SET_INCOMPLETE', 'RECORD_INVALID',
      'REFERENCE_INCONSISTENT', 'PARTIAL_GENERATION', 'INTERNAL_VALIDATION_FAILED',
    ];
    expect(Object.keys(M2_ADAPTER.RESTORE_DISPOSITIONS).sort()).toEqual([...outcomes].sort());
    for (const [outcome, disposition] of Object.entries(M2_ADAPTER.RESTORE_DISPOSITIONS)) {
      expect(M2_ADAPTER.CODE_TO_KIND[disposition]).toBeDefined();
      expect(`${outcome}:${disposition}`).toBeTruthy();
    }
  });

  test('the module imports exactly the two merged modules and nothing else', () => {
    const source = readFileSync(MODULE_PATH, 'utf8');
    const specifiers = [...source.matchAll(/^import\s+(?:[^'"]*?from\s+)?'([^']+)';$/gm)]
      .map((match) => match[1]);
    expect(specifiers).toEqual([
      './state-machine.js',
      '../../../storage/m2/session-restore.js',
    ]);
    expect(source).not.toMatch(/require\(/);
    expect(source).not.toMatch(/\bimport\(/);
  });
});

describe('I-JOIN exact positive fixtures restore through adapter', () => {
  test('POS-NO-M2 rejects NO_STORED_SESSION with the state unchanged', () => {
    const row = positive('POS-NO-M2');
    const observation = observationOfFixture(row);
    expect(classifyRestore(observation.restoreObservation).result).toBe(row.result);
    const snapshot = empty();
    const result = invokeRestore(observation, snapshot);
    expect(result.kind).toBe('REJECTED');
    expect(result.error.code).toBe('NO_STORED_SESSION');
    expect(result.stateBefore).toBe('EMPTY');
    expect(result.stateAfter).toBe('EMPTY');
    expect(Object.hasOwn(result, 'output')).toBe(false);
    expect(snapshot.state).toBe('EMPTY');
  });

  test('POS-LEGACY-ONLY rejects STORED_SESSION_INCOMPATIBLE with the state unchanged', () => {
    const row = positive('POS-LEGACY-ONLY');
    const observation = observationOfFixture(row);
    expect(classifyRestore(observation.restoreObservation).result).toBe(row.result);
    const result = invokeRestore(observation);
    expect(result.kind).toBe('REJECTED');
    expect(result.error.code).toBe('STORED_SESSION_INCOMPATIBLE');
    expect(result.stateBefore).toBe('EMPTY');
    expect(result.stateAfter).toBe('EMPTY');
  });

  test('POS-ACTIVE restores through the adapter as SUCCESS RESTORED with ACTIVE and no output', () => {
    const row = positive('POS-ACTIVE');
    const observation = observationOfFixture(row);
    expect(classifyRestore(observation.restoreObservation).result).toBe('RESTORED_ACTIVE');
    const snapshot = empty();
    const result = invokeRestore(observation, snapshot);
    expect(result.kind).toBe('SUCCESS');
    expect(result.successCode).toBe('RESTORED');
    expect(result.stateBefore).toBe('EMPTY');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(Object.hasOwn(result, 'output')).toBe(false);
    expect(Object.hasOwn(result, 'commitOutcome')).toBe(false);
    expect(snapshot.state).toBe('EMPTY');
  });

  test('POS-M2-LEGACY-PRESENT restores and the LEGACY_PRESENT condition changes nothing', () => {
    const row = positive('POS-M2-LEGACY-PRESENT');
    const observation = observationOfFixture(row);
    const outcome = classifyRestore(observation.restoreObservation);
    expect(outcome.result).toBe('RESTORED_ACTIVE');
    expect(outcome.condition).toBe('LEGACY_PRESENT');
    const result = invokeRestore(observation);
    expect(result.kind).toBe('SUCCESS');
    expect(result.successCode).toBe('RESTORED');
    expect(result.stateAfter).toBe('ACTIVE');
  });

  test('POS-EMPTY, POS-HOLD and POS-EMPTY-HOLD fail closed as AUTHENTICATED_STATE_INCONSISTENT', () => {
    const expectations = {
      'POS-EMPTY': 'RESTORED_EMPTY',
      'POS-HOLD': 'RESTORED_RECONCILIATION_REQUIRED',
      'POS-EMPTY-HOLD': 'RESTORED_RECONCILIATION_REQUIRED',
    };
    for (const [id, outcome] of Object.entries(expectations)) {
      const row = positive(id);
      const observation = observationOfFixture(row);
      expect(classifyRestore(observation.restoreObservation).result).toBe(outcome);
      const result = invokeRestore(observation);
      expect(`${id}:${result.kind}:${code(result)}`)
        .toBe(`${id}:REJECTED:AUTHENTICATED_STATE_INCONSISTENT`);
      expect(result.stateBefore).toBe('EMPTY');
      expect(result.stateAfter).toBe('EMPTY');
      expect(Object.hasOwn(result, 'output')).toBe(false);
    }
  });

  test('the fail-closed positives are exactly the three named cases and no other positive fails closed', () => {
    const failedClosed = [];
    for (const row of FRESH_WORKER_FIXTURES.positive) {
      const observation = observationOfFixture(row);
      const result = invokeRestore(observation);
      if (result.kind === 'REJECTED' && result.error.code === 'AUTHENTICATED_STATE_INCONSISTENT') {
        failedClosed.push(row.id);
      }
    }
    expect(failedClosed.sort()).toEqual([...FAIL_CLOSED_POSITIVES].sort());
    expect(FRESH_WORKER_FIXTURES.positive).toHaveLength(7);
  });
});

describe('I-JOIN all sixty-five negative fixtures', () => {
  test('every negative fixture returns its exact mapped rejected code and never a success', () => {
    expect(negatives).toHaveLength(65);
    const seen = new Set();
    for (const row of negatives) {
      const observation = observationOfFixture(row);
      const classified = classifyRestore(observation.restoreObservation);
      // The observation built from the row must classify as the row says, so the mapping below is not
      // tautological: a wrong observation would change the C-REST outcome and fail here first.
      expect(`${row.id}:${classified.result}:${classified.stage}`)
        .toBe(`${row.id}:${row.result}:${row.firstPhase}`);
      const expected = M2_ADAPTER.RESTORE_DISPOSITIONS[row.result];
      const result = invokeRestore(observation);
      expect(`${row.id}:${result.kind}:${code(result)}`).toBe(`${row.id}:REJECTED:${expected}`);
      expect(M2_ADAPTER.ERROR_CODES).toContain(result.error.code);
      expect(result.stateBefore).toBe('EMPTY');
      expect(result.stateAfter).toBe('EMPTY');
      expect(Object.hasOwn(result, 'output')).toBe(false);
      expect(Object.hasOwn(result, 'commitOutcome')).toBe(false);
      seen.add(result.error.code);
    }
    expect([...seen].sort()).toEqual(
      ['AUTHENTICATION_FAILED', 'AUTHENTICATED_STATE_INCONSISTENT', 'FAIL_CLOSED_INTERNAL',
        'STORED_SESSION_INCOMPATIBLE'].sort(),
    );
  });

  test('the lock and internal outcomes have no ratified decision row and fail closed at P10', () => {
    const locked = invokeRestore(restoreObservation({ faults: ['lockUnavailable'] }));
    expect(locked.error.code).toBe('FAIL_CLOSED_INTERNAL');
    const internal = invokeRestore({
      restoreObservation: { faults: ['inventoryAmbiguous'], inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE' },
    });
    expect(internal.error.code).toBe('FAIL_CLOSED_INTERNAL');
  });
});

describe('I-JOIN create and Welcome', () => {
  test('CREATE with COMMITTED returns CREATED, ACTIVE and exactly the staged Welcome bytes', () => {
    const result = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation: createObservation('SUPPORTED', 'COMMITTED', { embeddedTreeWelcome: new Uint8Array([0x77, 0x78]) }),
    });
    expect(result.kind).toBe('SUCCESS');
    expect(result.successCode).toBe('CREATED');
    expect(result.stateBefore).toBe('EMPTY');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(result.commitOutcome).toBe('COMMITTED');
    expect([...result.output.embeddedTreeWelcome]).toEqual([0x77, 0x78]);
    expect(Object.keys(result.output)).toEqual(['embeddedTreeWelcome']);
  });

  test('CREATE with NOT_COMMITTED returns NOT_COMMITTED, the state unchanged and no output', () => {
    const result = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation: createObservation('SUPPORTED', 'NOT_COMMITTED'),
    });
    expect(result.kind).toBe('NOT_COMMITTED');
    expect(result.commitOutcome).toBe('NOT_COMMITTED');
    expect(result.stateBefore).toBe('EMPTY');
    expect(result.stateAfter).toBe('EMPTY');
    expect(Object.hasOwn(result, 'output')).toBe(false);
    expect(Object.hasOwn(result, 'successCode')).toBe(false);
  });

  test('CREATE with INDETERMINATE returns the held reference, the original state and no output', () => {
    const result = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation: createObservation('SUPPORTED', 'INDETERMINATE'),
    });
    expect(result.kind).toBe('INDETERMINATE');
    expect(result.commitOutcome).toBe('INDETERMINATE');
    expect(typeof result.reconciliationRef).toBe('string');
    expect(result.reconciliationRef.length).toBeGreaterThan(0);
    expect(result.originalStateBefore).toBe('EMPTY');
    expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(Object.hasOwn(result, 'output')).toBe(false);
  });

  test('CREATE with UNSUPPORTED_ONBOARDING rejects before mutation', () => {
    const snapshot = empty();
    const result = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot,
      observation: createObservation('UNSUPPORTED_ONBOARDING', null),
    });
    expect(result.kind).toBe('REJECTED');
    expect(result.error.code).toBe('UNSUPPORTED_ONBOARDING');
    expect(result.stateAfter).toBe('EMPTY');
    expect(snapshot.state).toBe('EMPTY');
  });

  test('CREATE and JOIN_WELCOME in an ACTIVE state cannot mutate', () => {
    const create = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: active(),
      observation: createObservation('SUPPORTED', 'COMMITTED'),
    });
    const join = invokeAdapter({
      request: request('JOIN_WELCOME', { embeddedTreeWelcome: new Uint8Array([0x01]) }),
      snapshot: active(),
      observation: joinObservation('MATCHED', 'COMMITTED'),
    });
    expect(code(create)).toBe('SESSION_ALREADY_EXISTS');
    expect(code(join)).toBe('SESSION_ALREADY_EXISTS');
  });

  test('RESTORE while reconciliation is required cannot restore', () => {
    const result = invokeRestore(restoreObservation({}), held());
    expect(code(result)).toBe('RECONCILIATION_REQUIRED');
    expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
  });

  test('JOIN_WELCOME returns its four closed outcomes with no output', () => {
    const cases = [
      ['MATCHED', 'COMMITTED', 'SUCCESS', 'JOINED'],
      ['MATCHED', 'NOT_COMMITTED', 'NOT_COMMITTED', 'NOT_COMMITTED'],
      ['KEY_PACKAGE_ALREADY_CONSUMED', null, 'REJECTED', 'KEY_PACKAGE_ALREADY_CONSUMED'],
      ['WELCOME_NO_MATCHING_KEY_PACKAGE', null, 'REJECTED', 'WELCOME_NO_MATCHING_KEY_PACKAGE'],
      ['UNSUPPORTED_ONBOARDING', null, 'REJECTED', 'UNSUPPORTED_ONBOARDING'],
    ];
    for (const [keyPackage, commitOutcome, kind, expected] of cases) {
      const result = invokeAdapter({
        request: request('JOIN_WELCOME', { embeddedTreeWelcome: new Uint8Array([0x02]) }),
        snapshot: empty(),
        observation: joinObservation(keyPackage, commitOutcome),
      });
      expect(`${keyPackage}:${result.kind}:${code(result)}`).toBe(`${keyPackage}:${kind}:${expected}`);
      expect(Object.hasOwn(result, 'output')).toBe(false);
    }
  });

  test('JOIN_WELCOME with INDETERMINATE keeps the KeyPackage decision without blind retry', () => {
    const result = invokeAdapter({
      request: request('JOIN_WELCOME', { embeddedTreeWelcome: new Uint8Array([0x02]) }),
      snapshot: empty(),
      observation: joinObservation('MATCHED', 'INDETERMINATE'),
    });
    expect(result.kind).toBe('INDETERMINATE');
    expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(Object.hasOwn(result, 'output')).toBe(false);
  });
});

describe('I-JOIN fail-closed request validation', () => {
  const cases = [
    ['unknown request member', request('RESTORE', {}, { extra: 1 }), {}, 'UNKNOWN_FIELD'],
    ['missing request member', { api: API, operation: 'RESTORE', requestId: 'r', profile: { ...PROFILE }, bindingRef: new Uint8Array([0x01]) }, {}, 'INVALID_REQUEST'],
    ['non-plain request', 'not-a-record', {}, 'INVALID_REQUEST'],
    ['foreign api constant', request('RESTORE', {}, { api: 'styx-m2-session-adapter/v2' }), {}, 'UNSUPPORTED_API_VERSION'],
    ['profile member drifted by one character', request('RESTORE', {}, { profile: { ...PROFILE, topology: 'three-member-direct' } }), {}, 'UNSUPPORTED_PROFILE'],
    ['missing profile member', request('RESTORE', {}, { profile: { adapterApi: API } }), {}, 'UNSUPPORTED_PROFILE'],
    ['unknown profile member', request('RESTORE', {}, { profile: { ...PROFILE, extra: 1 } }), {}, 'UNSUPPORTED_PROFILE'],
    ['empty bindingRef', request('RESTORE', {}, { bindingRef: new Uint8Array(0) }), {}, 'BINDING_MISMATCH'],
    ['non-byte bindingRef', request('RESTORE', {}, { bindingRef: 7 }), {}, 'BINDING_MISMATCH'],
    ['unknown operation', request('ADD_MEMBER', {}), {}, 'UNSUPPORTED_OPERATION'],
    ['operation outside the integrated three', request('PROTECT_APPLICATION', { applicationBytes: new Uint8Array([0x01]) }), {}, 'UNSUPPORTED_OPERATION'],
    ['unknown request input member', request('RESTORE', { extra: 1 }), {}, 'UNKNOWN_FIELD'],
    ['non-closed observation', request('RESTORE', {}), { restoreObservation: null, extra: 1 }, 'UNKNOWN_FIELD'],
    ['unknown observation member', request('RESTORE', {}), { restoreObservation: { faults: [], inventory: 'NONE', legacy: false, vector: null, selectorState: 'ACTIVE' }, extra: 1 }, 'UNKNOWN_FIELD'],
    ['out-of-set onboarding', request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }), { onboarding: 'MAYBE', commitOutcome: null, operationIdentity: null, stagedOutput: null }, 'UNKNOWN_VALUE'],
    ['out-of-set keyPackage', request('JOIN_WELCOME', { embeddedTreeWelcome: new Uint8Array([0x01]) }), { keyPackage: 'MAYBE', commitOutcome: null, operationIdentity: null }, 'UNKNOWN_VALUE'],
    ['out-of-set commit outcome', request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }), { onboarding: 'SUPPORTED', commitOutcome: 'MAYBE', operationIdentity: 'x', stagedOutput: { embeddedTreeWelcome: new Uint8Array([0x01]) } }, 'UNKNOWN_VALUE'],
    ['non-byte peer KeyPackage', request('CREATE', { peerFramedKeyPackage: 'bytes' }), {}, 'INVALID_REQUEST'],
    ['unreachable create carries a commit outcome', request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }), { onboarding: 'UNSUPPORTED_ONBOARDING', commitOutcome: 'COMMITTED', operationIdentity: 'x', stagedOutput: null }, 'INVALID_REQUEST'],
    ['staged output outside its closed shape', request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }), { onboarding: 'SUPPORTED', commitOutcome: 'COMMITTED', operationIdentity: 'x', stagedOutput: { other: new Uint8Array([0x01]) } }, 'UNKNOWN_FIELD'],
  ];

  test.each(cases)('%s rejects with its exact code', (_label, req, observation, expected) => {
    const result = invokeAdapter({ request: req, snapshot: empty(), observation });
    expect(result.kind).toBe('REJECTED');
    expect(result.error.code).toBe(expected);
    expect(result.stateAfter).toBe(result.stateBefore);
    expect(Object.hasOwn(result, 'output')).toBe(false);
  });

  test('an accessor request member is rejected without invoking it', () => {
    let reads = 0;
    const req = request('RESTORE', {});
    Object.defineProperty(req, 'bindingRef', {
      enumerable: true,
      get() {
        reads += 1;
        return new Uint8Array([0x01]);
      },
    });
    const result = invokeAdapter({ request: req, snapshot: empty(), observation: restoreObservation({}) });
    expect(code(result)).toBe('UNKNOWN_FIELD');
    expect(reads).toBe(0);
  });

  test('a request-level error preempts an otherwise valid operation', () => {
    const result = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }, { operation: 'ADD_MEMBER' }),
      snapshot: empty(),
      observation: createObservation('SUPPORTED', 'COMMITTED'),
    });
    expect(code(result)).toBe('UNSUPPORTED_OPERATION');
  });

  test('unreadable framing throws the single closed error class and nothing else', () => {
    const unreadable = [
      { snapshot: empty(), observation: {} },
      { request: request('RESTORE', {}), observation: {} },
      { request: { api: API, operation: 'RESTORE', profile: { ...PROFILE }, bindingRef: new Uint8Array([0x01]), input: {} }, snapshot: empty(), observation: {} },
      { request: request('RESTORE', {}), snapshot: { state: 'BROKEN' }, observation: {} },
      { request: request('RESTORE', {}), snapshot: null, observation: {} },
    ];
    for (const input of unreadable) {
      let caught = null;
      try {
        invokeAdapter(input);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(M2AdapterError);
      expect(['INVALID_REQUEST', 'FAIL_CLOSED_INTERNAL']).toContain(caught.code);
    }
    expect(() => invokeAdapter({ request: request('RESTORE', {}), snapshot: empty(), observation: {}, extra: 1 }))
      .toThrow(M2AdapterError);
  });

  test('validateAdapterRequest decides only the request-level levels', () => {
    expect(validateAdapterRequest(request('RESTORE', {}))).toEqual({ ok: true, code: null });
    expect(validateAdapterRequest(request('RESTORE', {}, { extra: 1 })).code).toBe('UNKNOWN_FIELD');
    expect(validateAdapterRequest(request('PROTECT_APPLICATION', { applicationBytes: new Uint8Array([0x01]) })).code)
      .toBe('UNSUPPORTED_OPERATION');
    expect(validateAdapterRequest(request('RESTORE', {})).ok).toBe(true);
    expect(Object.isFrozen(validateAdapterRequest(request('RESTORE', {})))).toBe(true);
  });
});

describe('I-JOIN total precedence', () => {
  test('the P01 order is enforced when several request-level defects are present at once', () => {
    const both = invokeAdapter({
      request: request('RESTORE', {}, { api: 'styx-m2-session-adapter/v2', extra: 1 }),
      snapshot: empty(),
      observation: restoreObservation({}),
    });
    expect(code(both)).toBe('UNKNOWN_FIELD');
    const profileAndOperation = invokeAdapter({
      request: request('ADD_MEMBER', {}, { profile: { ...PROFILE, topology: 'x' } }),
      snapshot: empty(),
      observation: restoreObservation({}),
    });
    expect(code(profileAndOperation)).toBe('UNSUPPORTED_PROFILE');
    const apiAndProfile = invokeAdapter({
      request: request('RESTORE', {}, { api: 'v2', profile: { ...PROFILE, topology: 'x' } }),
      snapshot: empty(),
      observation: restoreObservation({}),
    });
    expect(code(apiAndProfile)).toBe('UNSUPPORTED_API_VERSION');
  });

  test('the state gate at P05 preempts a bound failure at P06 and a decision row at P09 to P10', () => {
    const overLong = 'x'.repeat(M2_ADAPTER.BOUNDS.MAX_REQUEST_ID_CHARS + 1);
    const bounded = invokeAdapter({
      request: request('RESTORE', {}, { requestId: overLong }),
      snapshot: empty(),
      observation: restoreObservation({}),
    });
    expect(code(bounded)).toBe('VALUE_OUT_OF_RANGE');
    const gated = invokeAdapter({
      request: request('RESTORE', {}, { requestId: overLong }),
      snapshot: active(),
      observation: restoreObservation({}),
    });
    expect(code(gated)).toBe('SESSION_ALREADY_EXISTS');
    const noStored = invokeAdapter({
      request: request('RESTORE', {}, { requestId: overLong }),
      snapshot: empty(),
      observation: restoreObservation({ inventory: 'NONE', vector: null }),
    });
    expect(code(noStored)).toBe('NO_STORED_SESSION');
  });

  test('an owning-layer rejection at P08 preempts a P09 outcome', () => {
    const result = invokeRestore(restoreObservation({
      faults: ['manifestOrRootMismatch', 'authenticatedVersionUnknownOrMixed'],
    }));
    const classification = classifyRestore({
      faults: ['manifestOrRootMismatch', 'authenticatedVersionUnknownOrMixed'],
      inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE',
    });
    expect(classification.result).toBe('MANIFEST_INVALID');
    expect(code(result)).toBe('AUTHENTICATED_STATE_INCONSISTENT');
  });

  test('an over-limit requestId at P06 preempts a P10 success', () => {
    const result = invokeAdapter({
      request: request('RESTORE', {}, { requestId: 'x'.repeat(1000) }),
      snapshot: empty(),
      observation: restoreObservation({}),
    });
    expect(code(result)).toBe('VALUE_OUT_OF_RANGE');
  });
});

describe('I-JOIN result envelope shape', () => {
  const samples = [
    () => invokeAdapter({ request: request('RESTORE', {}), snapshot: empty(), observation: restoreObservation({}) }),
    () => invokeAdapter({ request: request('RESTORE', {}), snapshot: empty(), observation: restoreObservation({ inventory: 'NONE', vector: null }) }),
    () => invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation: createObservation('SUPPORTED', 'COMMITTED'),
    }),
    () => invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation: createObservation('SUPPORTED', 'NOT_COMMITTED'),
    }),
    () => invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation: createObservation('SUPPORTED', 'INDETERMINATE'),
    }),
    () => invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation: createObservation('UNSUPPORTED_ONBOARDING', null),
    }),
  ];

  test('every result carries exactly the common members plus the members its kind permits', () => {
    const kinds = new Set();
    for (const sample of samples) {
      const result = sample();
      kinds.add(result.kind);
      const allowed = [...RESULT_COMMON_MEMBERS, ...KIND_MEMBERS[result.kind]];
      expect(Object.keys(result).sort()).toEqual([...new Set(allowed)].sort());
      expect(result.api).toBe(API);
      expect(result.operation).toBeTruthy();
      expect(M2_ADAPTER.RESULT_KINDS).toContain(result.kind);
      expect(M2_ADAPTER.STATES).toContain(result.stateBefore);
      expect(M2_ADAPTER.STATES).toContain(result.stateAfter);
      expect(Object.isFrozen(result)).toBe(true);
      if (result.kind === 'REJECTED') {
        expect(Object.keys(result.error)).toEqual(['code']);
        expect(M2_ADAPTER.ERROR_CODES).toContain(result.error.code);
        expect(M2_ADAPTER.CODE_TO_KIND[result.error.code]).toBe('REJECTED');
      }
      if (result.kind === 'SUCCESS') {
        expect(M2_ADAPTER.SUCCESS_CODES).toContain(result.successCode);
        expect(M2_ADAPTER.CODE_TO_KIND[result.successCode]).toBe('SUCCESS');
        expect(M2_ADAPTER.OUTPUT_BY_SUCCESS_CODE[result.successCode].length === 0)
          .toBe(Object.hasOwn(result, 'output') === false);
      }
    }
    expect([...kinds].sort()).toEqual(['INDETERMINATE', 'NOT_COMMITTED', 'REJECTED', 'SUCCESS']);
  });

  test('request-id and operation are echoed exactly and no member carries free text', () => {
    const result = invokeAdapter({
      request: request('RESTORE', {}, { requestId: 'abc-123' }),
      snapshot: empty(),
      observation: restoreObservation({}),
    });
    expect(result.requestId).toBe('abc-123');
    expect(result.operation).toBe('RESTORE');
    expect(JSON.stringify(result)).not.toMatch(/\/home\/|Error:|stack/);
  });
});

describe('I-JOIN immutability and purity', () => {
  test('the request, the snapshot and the observation are not mutated', () => {
    const req = request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01, 0x02]) });
    const snapshot = empty();
    const observation = createObservation('SUPPORTED', 'COMMITTED');
    const before = JSON.stringify({
      req: { ...req, profile: { ...req.profile }, bindingRef: [...req.bindingRef], input: { peerFramedKeyPackage: [...req.input.peerFramedKeyPackage] } },
      snapshot: { ...snapshot },
      observation: { ...observation, stagedOutput: { embeddedTreeWelcome: [...observation.stagedOutput.embeddedTreeWelcome] } },
    });
    const first = invokeAdapter({ request: req, snapshot, observation });
    const second = invokeAdapter({ request: req, snapshot, observation });
    const after = JSON.stringify({
      req: { ...req, profile: { ...req.profile }, bindingRef: [...req.bindingRef], input: { peerFramedKeyPackage: [...req.input.peerFramedKeyPackage] } },
      snapshot: { ...snapshot },
      observation: { ...observation, stagedOutput: { embeddedTreeWelcome: [...observation.stagedOutput.embeddedTreeWelcome] } },
    });
    expect(after).toBe(before);
    expect(second).toEqual(first);
    expect(second).not.toBe(first);
  });

  test('the released bytes are a copy and later mutation of the observation cannot change them', () => {
    const observation = createObservation('SUPPORTED', 'COMMITTED', { embeddedTreeWelcome: new Uint8Array([0x05, 0x06]) });
    const result = invokeAdapter({
      request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
      snapshot: empty(),
      observation,
    });
    expect(result.output.embeddedTreeWelcome).not.toBe(observation.stagedOutput.embeddedTreeWelcome);
    observation.stagedOutput.embeddedTreeWelcome[0] = 0xff;
    expect([...result.output.embeddedTreeWelcome]).toEqual([0x05, 0x06]);
  });

  test('the module exposes exactly its four documented names', async () => {
    const namespace = await import('../../../src/crypto/mls/m2/adapter.js');
    expect(Object.keys(namespace).sort()).toEqual([
      'M2AdapterError', 'M2_ADAPTER', 'invokeAdapter', 'validateAdapterRequest',
    ]);
  });
});

describe('I-JOIN O-SCEN clause mapping', () => {
  test('the mapping covers every implemented pointer with ratified scenario ids', () => {
    const pointers = Object.keys(OSCEN_SCENARIOS);
    expect(pointers.length).toBeGreaterThan(40);
    const ids = new Set();
    for (const [pointer, scenarios] of Object.entries(OSCEN_SCENARIOS)) {
      expect(pointer.startsWith('/')).toBe(true);
      expect(Array.isArray(scenarios)).toBe(true);
      expect(scenarios.length).toBeGreaterThan(0);
      for (const id of scenarios) {
        expect(id).toMatch(/^OSC-[0-9a-f]{16}$/);
        ids.add(id);
      }
    }
    expect(ids.size).toBe(343);
    expect(MAPPING_SCHEMA).toBe('styx-m2-i-join-scenario-mapping/v1');
    expect(MAPPING_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });

  test('the mapping names no I-JOIN identifier and does not close the reconciliation list', () => {
    for (const [pointer, scenarios] of Object.entries(OSCEN_SCENARIOS)) {
      for (const id of scenarios) {
        expect(id).not.toMatch(/I-JOIN|IJN-/);
      }
      expect(`${pointer}:${scenarios.length}`).toBeTruthy();
    }
  });

  test('the create, restore and Welcome pointers are all mapped', () => {
    for (const pointer of ['/decisionRows', '/stateMatrix', '/errorDefinitions', '/rules/restore',
      '/request/inputByOperation', '/response/byKind', '/response/outputBySuccessCode']) {
      expect(OSCEN_SCENARIOS[pointer].length).toBeGreaterThan(0);
    }
  });
});

describe('I-JOIN seeded property sweep', () => {
  const SEED = 20261002;
  const RUNS = 300;

  const memberArbitrary = fc.oneof(
    fc.constant(undefined),
    fc.constant(null),
    fc.integer(),
    fc.string(),
    fc.boolean(),
    fc.uint8Array({ maxLength: 4 }),
    fc.constant('EMPTY'),
    fc.constant('ACTIVE'),
    fc.constant('SUPPORTED'),
    fc.constant('MATCHED'),
    fc.constant('COMMITTED'),
    fc.constant('INDETERMINATE'),
    fc.constant('RESTORE'),
    fc.constant('CREATE'),
    fc.constant('JOIN_WELCOME'),
  );

  const requestArbitrary = fc.record({
    api: fc.oneof(fc.constant(API), fc.string()),
    operation: fc.oneof(fc.constantFrom('CREATE', 'RESTORE', 'JOIN_WELCOME'), fc.string()),
    requestId: fc.oneof(fc.constant('req'), fc.string({ maxLength: 3 }), fc.integer()),
    profile: fc.oneof(fc.constant({ ...PROFILE }), fc.constant({ adapterApi: API }), fc.constant({ ...PROFILE, topology: 'x' }), fc.string()),
    bindingRef: fc.oneof(fc.uint8Array({ minLength: 1, maxLength: 4 }), fc.constant(new Uint8Array(0)), fc.integer()),
    input: fc.oneof(fc.constant({}), fc.record({ peerFramedKeyPackage: fc.uint8Array({ maxLength: 3 }) }, { requiredKeys: [] }), fc.string()),
  }, { requiredKeys: [] });

  const observationArbitrary = fc.record({
    onboarding: memberArbitrary,
    commitOutcome: memberArbitrary,
    operationIdentity: memberArbitrary,
    stagedOutput: fc.oneof(fc.constant(null), fc.record({ embeddedTreeWelcome: fc.uint8Array({ maxLength: 3 }) })),
    keyPackage: memberArbitrary,
    restoreObservation: fc.oneof(
      fc.constant(null),
      fc.record({
        faults: fc.array(fc.constantFrom('lockUnavailable', 'manifestOrRootMismatch', 'recordAuthenticationFailed'), { maxLength: 2 }),
        inventory: fc.constantFrom('NONE', 'LEGACY_ONLY', 'M2'),
        legacy: fc.boolean(),
        vector: fc.oneof(fc.constant(null), fc.constantFrom('FMT-KAT-EMPTY', 'FMT-KAT-ACTIVE', 'FMT-KAT-HOLD')),
        selectorState: fc.constantFrom('EMPTY', 'ACTIVE', 'RECONCILIATION_REQUIRED'),
      }),
    ),
  }, { requiredKeys: [] });

  const snapshotArbitrary = fc.oneof(
    fc.constant(createAdapterSnapshot('EMPTY')),
    fc.constant(createAdapterSnapshot('ACTIVE')),
    fc.constant(held()),
    fc.constant(null),
    fc.record({ state: fc.string() }),
  );

  test('no random or mutated input produces anything but a frozen closed result or the closed error', () => {
    const outcomes = new Set();
    fc.assert(
      fc.property(requestArbitrary, observationArbitrary, snapshotArbitrary, fc.constantFrom('full', 'missing', 'extra'), (req, observation, snapshot, shape) => {
        const mutated = shape === 'exact'
          ? { request: req, snapshot, observation }
          : { request: req, snapshot, observation };
        if (shape === 'missing') delete mutated.observation;
        if (shape === 'extra') mutated.extra = 1;
        let result;
        try {
          result = invokeAdapter(mutated);
        } catch (error) {
          expect(error).toBeInstanceOf(M2AdapterError);
          expect(M2_ADAPTER.ERROR_CODES).toContain(error.code);
          return true;
        }
        expect(Object.isFrozen(result)).toBe(true);
        expect(M2_ADAPTER.RESULT_KINDS).toContain(result.kind);
        expect(M2_ADAPTER.STATES).toContain(result.stateBefore);
        expect(M2_ADAPTER.STATES).toContain(result.stateAfter);
        const allowed = [...RESULT_COMMON_MEMBERS, ...KIND_MEMBERS[result.kind]];
        expect(Object.keys(result).every((key) => allowed.includes(key))).toBe(true);
        if (result.kind === 'REJECTED') {
          expect(M2_ADAPTER.ERROR_CODES).toContain(result.error.code);
          expect(Object.keys(result.error)).toEqual(['code']);
        }
        if (result.kind === 'SUCCESS') expect(M2_ADAPTER.SUCCESS_CODES).toContain(result.successCode);
        outcomes.add(result.kind);
        return true;
      }),
      { seed: SEED, numRuns: RUNS },
    );
    expect(outcomes.size).toBeGreaterThan(0);
  });

  test('the same seed replays to identical outcomes', () => {
    const run = () => {
      const seen = [];
      fc.assert(
        fc.property(requestArbitrary, fc.uint8Array({ maxLength: 3 }), (req, bytes) => {
          const observation = {
            onboarding: 'SUPPORTED', commitOutcome: 'COMMITTED', operationIdentity: 'x',
            stagedOutput: { embeddedTreeWelcome: bytes },
          };
          let result;
          try {
            result = invokeAdapter({ request: req, snapshot: createAdapterSnapshot('EMPTY'), observation });
          } catch (error) {
            seen.push([error.name, error.code].join(':'));
            return true;
          }
          seen.push([result.kind, code(result)].join(':'));
          return true;
        }),
        { seed: SEED, numRuns: 150 },
      );
      return seen.join('|');
    };
    expect(run()).toBe(run());
  });

  test('permuting the request member order does not change the result', () => {
    const base = request('RESTORE', {});
    const permuted = {};
    for (const key of [...REQUEST_MEMBERS].reverse()) permuted[key] = base[key];
    const observation = restoreObservation({});
    expect(invokeAdapter({ request: permuted, snapshot: empty(), observation }))
      .toEqual(invokeAdapter({ request: base, snapshot: empty(), observation }));
  });
});
