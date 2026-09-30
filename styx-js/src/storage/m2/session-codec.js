// M2 authenticated storage byte codecs. Internal-only: no barrel export.

const TE = new TextEncoder();
const ASCII = (s) => TE.encode(s);
const U64_MAX = (1n << 64n) - 1n;
const MAX_PLAINTEXT = 16 * 1024 * 1024;

export const M2_SCOPE = Object.freeze({ CONTEXT_PRESESSION: 1, SESSION: 2 });
export const M2_KIND = Object.freeze({
  SLOT_REGISTRATION: 1, ISSUANCE_CANDIDATE: 2, ISSUANCE_OUTCOME: 3, KEY_PACKAGE: 4,
  SESSION_STATE: 5, BINDING_PROFILE: 6, REPLAY_RETENTION: 7, COMMIT_RESULT: 8,
  OUTPUT_ESCROW: 9, SELECTION_METADATA: 10, RETAINED_PARENT: 11, LOSING_CANDIDATE: 12,
  MUTATION_HOLD: 13, COMPONENT_SET: 14, ABSENCE_COMMITMENTS: 15, MANIFEST: 16,
  GENERATION_SELECTOR: 17,
});
export const M2_LIFECYCLE = Object.freeze({ UNCONSUMED: 1, RESERVED: 2, CONSUMED: 3, INVALID: 4 });

const CODE = Object.freeze({
  MALFORMED_INPUT: 'MALFORMED_INPUT', UNSUPPORTED_VALUE: 'UNSUPPORTED_VALUE',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED', CONTEXT_MISMATCH: 'CONTEXT_MISMATCH',
  KEY_PACKAGE_ALREADY_USED: 'KEY_PACKAGE_ALREADY_USED',
});

export class M2StorageCodecError extends Error {
  constructor(code, message) { super(message); this.name = 'M2StorageCodecError'; this.code = code; }
}
const fail = (code, message) => { throw new M2StorageCodecError(code, message); };
const malformed = (message) => fail(CODE.MALFORMED_INPUT, message);
const unsupported = (message) => fail(CODE.UNSUPPORTED_VALUE, message);
const mismatch = (message) => fail(CODE.CONTEXT_MISMATCH, message);

function strictObject(value, keys, name = 'value') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) malformed(`${name} must be a plain object`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((k) => typeof k !== 'string' || !keys.includes(k))) {
    malformed(`${name} has an unknown, missing, or symbol property`);
  }
  const out = {};
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) malformed(`${name}.${key} must be enumerable data`);
    out[key] = d.value;
  }
  return out;
}
function bytes(value, length, name) {
  if (!(value instanceof Uint8Array) || (length !== null && value.length !== length)) malformed(`${name} has wrong byte width`);
  // Uint8Array.prototype.slice, never value.slice(): subclasses such as Node Buffer override
  // slice() to return a view, which would alias caller memory and break the snapshot rule.
  return Uint8Array.prototype.slice.call(value);
}
function boundedBytes(value, max, name) {
  const out = bytes(value, null, name);
  if (out.length > max) malformed(`${name} exceeds bound`);
  return out;
}
function nonzero(value, name) {
  const out = bytes(value, 32, name);
  if (out.every((b) => b === 0)) malformed(`${name} must be nonzero`);
  return out;
}
function safeInt(value, max, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) malformed(`${name} is out of range`);
  return value;
}
function u64(value, name) {
  if (typeof value !== 'bigint' || value < 0n || value > U64_MAX) malformed(`${name} is out of range`);
  return value;
}
function bool(value, name) {
  if (typeof value !== 'boolean') malformed(`${name} must be boolean`);
  return value;
}
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const concat = (...parts) => {
  const length = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(length); let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
};
const be16 = (n) => Uint8Array.of((n >>> 8) & 255, n & 255);
const be32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
function be64(n) { const out = new Uint8Array(8); let x = n; for (let i = 7; i >= 0; i -= 1) { out[i] = Number(x & 255n); x >>= 8n; } return out; }
const frame = (x) => concat(be32(x.length), x);
const read16 = (b, o) => b[o] * 256 + b[o + 1];
const read32 = (b, o) => b[o] * 0x1000000 + b[o + 1] * 0x10000 + b[o + 2] * 0x100 + b[o + 3];
function read64(b, o) { let n = 0n; for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(b[o + i]); return n; }
function expectMagic(b, o, magic) { const m = ASCII(magic); if (o + m.length > b.length || !equal(b.slice(o, o + m.length), m)) malformed(`wrong ${magic} magic`); return o + m.length; }

// Compact synchronous SHA-256, needed by the synchronous canonical encoders.
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
const K256 = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]);
function sha256(input) {
  const b = bytes(input, null, 'sha256 input'); const bitLen = BigInt(b.length) * 8n;
  const total = Math.ceil((b.length + 9) / 64) * 64; const p = new Uint8Array(total); p.set(b); p[b.length] = 0x80;
  for (let i = 0; i < 8; i += 1) p[total - 1 - i] = Number((bitLen >> BigInt(i * 8)) & 255n);
  const h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i += 1) w[i] = ((p[off+i*4]<<24)|(p[off+i*4+1]<<16)|(p[off+i*4+2]<<8)|p[off+i*4+3]) >>> 0;
    for (let i = 16; i < 64; i += 1) { const a=w[i-15], z=w[i-2]; const s0=rotr(a,7)^rotr(a,18)^(a>>>3); const s1=rotr(z,17)^rotr(z,19)^(z>>>10); w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0; }
    let [a,c,d,e,f,g,j,k] = h;
    for (let i=0;i<64;i+=1) { const s1=rotr(f,6)^rotr(f,11)^rotr(f,25); const ch=(f&g)^(~f&j); const t1=(k+s1+ch+K256[i]+w[i])>>>0; const s0=rotr(a,2)^rotr(a,13)^rotr(a,22); const maj=(a&c)^(a&d)^(c&d); const t2=(s0+maj)>>>0; k=j;j=g;g=f;f=(e+t1)>>>0;e=d;d=c;c=a;a=(t1+t2)>>>0; }
    const q=[a,c,d,e,f,g,j,k]; for(let i=0;i<8;i+=1) h[i]=(h[i]+q[i])>>>0;
  }
  const out=new Uint8Array(32); for(let i=0;i<8;i+=1){out[i*4]=h[i]>>>24;out[i*4+1]=h[i]>>>16;out[i*4+2]=h[i]>>>8;out[i*4+3]=h[i];} return out;
}

const KIND_NAMES = Object.freeze(['','SLOT_REGISTRATION','ISSUANCE_CANDIDATE','ISSUANCE_OUTCOME','KEY_PACKAGE','SESSION_STATE','BINDING_PROFILE','REPLAY_RETENTION','COMMIT_RESULT','OUTPUT_ESCROW','SELECTION_METADATA','RETAINED_PARENT','LOSING_CANDIDATE','MUTATION_HOLD','COMPONENT_SET','ABSENCE_COMMITMENTS','MANIFEST','GENERATION_SELECTOR']);
const kindVersion = (kind) => { if (!Number.isInteger(kind) || kind < 1 || kind > 17) unsupported('unknown record kind'); return kind === 13 ? 2 : kind === 17 ? 3 : 1; };
function objectId(context, kind) { return sha256(concat(ASCII('STYX-OBJECT-ID-V1'), frame(context), frame(ASCII(KIND_NAMES[kind])))).slice(0,16); }

export function encodeRecordKey(input) {
  const s=strictObject(input,['scope','localContextId','secureSessionIdentity','writeGeneration','recordKind'],'record key');
  const scope=safeInt(s.scope,255,'scope'); if(scope!==1&&scope!==2) unsupported('unknown scope');
  const context=nonzero(s.localContextId,'localContextId'); const gen=u64(s.writeGeneration,'writeGeneration'); if(gen===0n) malformed('generation zero');
  const kind=safeInt(s.recordKind,65535,'recordKind'); if(kind<1||kind>16) unsupported('record key kind');
  let session=new Uint8Array();
  if(scope===M2_SCOPE.SESSION) session=nonzero(s.secureSessionIdentity,'secureSessionIdentity');
  else if(s.secureSessionIdentity!==null) malformed('pre-session has session bytes');
  const oid=kind===16?new Uint8Array():objectId(context,kind);
  return concat(ASCII('STYXKEY1'),be16(1),Uint8Array.of(scope),context,session,be64(gen),be16(kind),Uint8Array.of(oid.length),oid);
}
export function decodeRecordKey(value) {
  const b=bytes(value,null,'record key'); let o=expectMagic(b,0,'STYXKEY1'); if(o+2>b.length)malformed('truncated record key version'); if(read16(b,o)!==1)unsupported('record key version'); o+=2;
  if(o>=b.length) malformed('truncated scope'); const scope=b[o++]; if(scope!==1&&scope!==2) unsupported('scope');
  if(o+32>b.length) malformed('truncated context'); const localContextId=nonzero(b.slice(o,o+32),'localContextId');o+=32;
  let secureSessionIdentity=null; if(scope===2){if(o+32>b.length) malformed('truncated session');secureSessionIdentity=nonzero(b.slice(o,o+32),'secureSessionIdentity');o+=32;}
  if(o+11>b.length) malformed('truncated record key'); const writeGeneration=read64(b,o);o+=8;if(writeGeneration===0n)malformed('generation zero'); const recordKind=read16(b,o);o+=2;if(recordKind<1||recordKind>16)unsupported('record key kind');const n=b[o++];if(o+n!==b.length)malformed('object id length/trailing');const objectIdBytes=b.slice(o);
  const expected=recordKind===16?new Uint8Array():objectId(localContextId,recordKind);if(!equal(objectIdBytes,expected))malformed('noncanonical object id');
  const canonical=encodeRecordKey({scope,localContextId,secureSessionIdentity,writeGeneration,recordKind});if(!equal(canonical,b))malformed('noncanonical record key');
  return Object.freeze({scope,localContextId,secureSessionIdentity,writeGeneration,recordKind,objectId:objectIdBytes.slice()});
}
export function encodeSelectorKey(input){const s=strictObject(input,['localContextId'],'selector key');return concat(ASCII('STYXSEL1'),be16(1),nonzero(s.localContextId,'localContextId'));}
export function decodeSelectorKey(value){const b=bytes(value,null,'selector key');let o=expectMagic(b,0,'STYXSEL1');if(o+2>b.length||b.length!==42)malformed('selector key length');if(read16(b,o)!==1)unsupported('selector key version');o+=2;const localContextId=nonzero(b.slice(o),'localContextId');if(!equal(encodeSelectorKey({localContextId}),b))malformed('noncanonical selector key');return Object.freeze({localContextId});}

async function hkdf(ikm,salt,info){const key=await crypto.subtle.importKey('raw',ikm,'HKDF',false,['deriveBits']);return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt,info},key,256));}
export async function deriveNamespaceKey(input){const s=strictObject(input,['rootStorageKey','localContextId','productProfileDigest'],'namespace KDF');const root=bytes(s.rootStorageKey,32,'rootStorageKey');const c=nonzero(s.localContextId,'localContextId');const p=bytes(s.productProfileDigest,32,'productProfileDigest');const salt=sha256(concat(ASCII('styx/m2/fmt/v1/salt'),frame(c),frame(p)));const info=concat(ASCII('styx/m2/fmt/v1/namespace'),be16(1),frame(c),frame(p));return hkdf(root,salt,info);}
export async function deriveRecordAeadKey(input){const s=strictObject(input,['namespaceKey','recordKey'],'record KDF');const n=bytes(s.namespaceKey,32,'namespaceKey');const k=bytes(s.recordKey,null,'recordKey');decodeRecordKey(k);return hkdf(n,new Uint8Array(32),concat(ASCII('styx/m2/fmt/v1/record-aead'),be16(1),frame(k)));}
export async function deriveSelectorAeadKey(input){const s=strictObject(input,['namespaceKey','selectorKey'],'selector KDF');const n=bytes(s.namespaceKey,32,'namespaceKey');const k=bytes(s.selectorKey,null,'selectorKey');decodeSelectorKey(k);return hkdf(n,new Uint8Array(32),concat(ASCII('styx/m2/fmt/v1/selector-aead'),be16(1),frame(k)));}

function encodeAadDigest(s,bindingDigest){return concat(ASCII('STYXAAD1'),be16(1),be16(1),be16(s.recordKind),be16(kindVersion(s.recordKind)),be16(1),frame(s.recordKey),s.localContextId,s.productProfileDigest,Uint8Array.of(s.scope),s.scope===2?concat(s.secureSessionIdentity,bindingDigest):new Uint8Array(),be64(s.writeGeneration),s.mutationIdentity,be32(s.plaintextLength));}
export async function encodeAad(input){const s=strictObject(input,['recordKey','localContextId','productProfileDigest','scope','secureSessionIdentity','canonicalBinding','writeGeneration','mutationIdentity','plaintextLength','recordKind'],'AAD');s.recordKey=bytes(s.recordKey,null,'recordKey');s.localContextId=nonzero(s.localContextId,'localContextId');s.productProfileDigest=bytes(s.productProfileDigest,32,'productProfileDigest');s.scope=safeInt(s.scope,255,'scope');s.writeGeneration=u64(s.writeGeneration,'writeGeneration');if(s.writeGeneration===0n)malformed('generation zero');s.mutationIdentity=bytes(s.mutationIdentity,32,'mutationIdentity');s.plaintextLength=safeInt(s.plaintextLength,MAX_PLAINTEXT,'plaintextLength');s.recordKind=safeInt(s.recordKind,65535,'recordKind');kindVersion(s.recordKind);
  let bindingDigest=null;if(s.scope===2){s.secureSessionIdentity=nonzero(s.secureSessionIdentity,'secureSessionIdentity');const binding=bytes(s.canonicalBinding,389,'canonicalBinding');bindingDigest=sha256(concat(ASCII('STYX-M2-BINDING-DIGEST-V1'),frame(binding)));}else if(s.scope===1){if(s.secureSessionIdentity!==null||s.canonicalBinding!==null)malformed('pre-session domain must be empty');s.secureSessionIdentity=null;}else unsupported('scope');
  if(s.recordKind===17){const q=decodeSelectorKey(s.recordKey);if(!equal(q.localContextId,s.localContextId))mismatch('selector context');}else{const q=decodeRecordKey(s.recordKey);if(q.scope!==s.scope||!equal(q.localContextId,s.localContextId)||q.writeGeneration!==s.writeGeneration||q.recordKind!==s.recordKind||(s.scope===2&&!equal(q.secureSessionIdentity,s.secureSessionIdentity)))mismatch('record key/AAD mismatch');}
  return encodeAadDigest(s,bindingDigest);
}
export function decodeAad(value){const b=bytes(value,null,'AAD');let o=expectMagic(b,0,'STYXAAD1');if(o+10>b.length)malformed('truncated AAD header');const formatVersion=read16(b,o);o+=2;const envelopeVersion=read16(b,o);o+=2;const recordKind=read16(b,o);o+=2;const recordKindVersion=read16(b,o);o+=2;const keyVersion=read16(b,o);o+=2;if(formatVersion!==1||envelopeVersion!==1||keyVersion!==1)unsupported('AAD version');if(recordKindVersion!==kindVersion(recordKind))unsupported('record kind version');if(o+4>b.length)malformed('truncated key length');const kl=read32(b,o);o+=4;if(o+kl+65>b.length)malformed('truncated AAD');const recordKey=b.slice(o,o+kl);o+=kl;const localContextId=nonzero(b.slice(o,o+32),'localContextId');o+=32;const productProfileDigest=b.slice(o,o+32);o+=32;const scope=b[o++];let secureSessionIdentity=null,bindingDigest=null;if(scope===2){if(o+64>b.length)malformed('truncated session domain');secureSessionIdentity=nonzero(b.slice(o,o+32),'secureSessionIdentity');o+=32;bindingDigest=b.slice(o,o+32);o+=32;}else if(scope!==1)unsupported('scope');if(o+44!==b.length)malformed('AAD trailing/truncation');const writeGeneration=read64(b,o);o+=8;if(writeGeneration===0n)malformed('generation zero');const mutationIdentity=b.slice(o,o+32);o+=32;const plaintextLength=read32(b,o);if(plaintextLength>MAX_PLAINTEXT)malformed('AAD plaintext length exceeds the C-FMT cap');
  if(recordKind===17){const q=decodeSelectorKey(recordKey);if(!equal(q.localContextId,localContextId))mismatch('selector context');}else{const q=decodeRecordKey(recordKey);if(q.scope!==scope||!equal(q.localContextId,localContextId)||q.writeGeneration!==writeGeneration||q.recordKind!==recordKind||(scope===2&&!equal(q.secureSessionIdentity,secureSessionIdentity)))mismatch('record key/AAD mismatch');}
  const s={recordKey,localContextId,productProfileDigest,scope,secureSessionIdentity,writeGeneration,mutationIdentity,plaintextLength,recordKind};if(!equal(encodeAadDigest(s,bindingDigest),b))malformed('noncanonical AAD');return Object.freeze({formatVersion,envelopeVersion,recordKind,recordKindVersion,keyVersion,recordKey:recordKey.slice(),localContextId:localContextId.slice(),productProfileDigest:productProfileDigest.slice(),scope,secureSessionIdentity:secureSessionIdentity?.slice()??null,bindingDigest:bindingDigest?.slice()??null,writeGeneration,mutationIdentity:mutationIdentity.slice(),plaintextLength});}

const SCHEMAS = Object.freeze({
  1:[['slotState','u8'],['registeredBindingRef','b32'],['profileDigest','b32']],2:[['issuanceRef','b32'],['publicKeyPackage','bytes65535'],['privateBundle','bytes65535'],['localKeyPackageRef','b32'],['mlsKeyPackageRef','b32']],3:[['issuanceRef','b32'],['outcome','u8'],['releaseState','u8']],4:[['publicKeyPackage','bytes65535'],['privateBundle','bytes65535'],['localKeyPackageRef','b32'],['mlsKeyPackageRef','b32'],['registeredBindingRef','b32'],['profileDigest','b32'],['lifecycle','u8'],['invalidPending','bool']],5:[['providerState','bytes16777216']],6:[['canonicalBinding','b389'],['profileDigest','b32']],7:[['replayState','bytes16777216'],['retentionState','bytes16777216']],8:[['operationIdentity','b32'],['originalAuthorityDigest','b32'],['originalAuthorityReference','b32'],['candidateDigest','b32'],['candidateReference','b32'],['mutationSetDigest','b32'],['mutationSetReference','b32'],['expectedOriginalState','u8'],['bindingRef','b32'],['profileDigest','b32'],['outcome','u8'],['authenticatedByRS','bool'],['terminal','bool']],9:[['operationIdentity','b32'],['candidateDigest','b32'],['candidateReference','b32'],['mutationSetDigest','b32'],['mutationSetReference','b32'],['outputKind','u8'],['output','bytes16777216'],['resultDigest','b32']],10:[['eligibility','u8'],['selectedCandidate','b32']],11:[['parentReference','b32'],['selectionRole','u8']],12:[['candidateReference','b32'],['evidence','bytes16777216'],['authoritative','bool']],13:[['operationIdentity','b32'],['operation','u8'],['scenario','u16'],['originalApiState','u8'],['originalAuthorityDigest','b32'],['originalAuthorityReference','b32'],['bindingRef','b32'],['profileDigest','b32'],['candidateDigest','b32'],['candidateReference','b32'],['componentSetDigest','b32'],['componentSetReference','b32'],['heldOutputKind','u8'],['heldOutputDigest','b32'],['heldOutputReference','b32'],['expectedSuccessCode','u8'],['expectedStateAfter','u8'],['reconciliationReference','b32'],['resultStatus','u8'],['parentGeneration','u64'],['parentKeyedRoot','b32']],14:[['mutationSetDigest','b32'],['mutationSetReference','b32'],['entries','bytes65535']],15:[['bitmap','u32'],['reasonCodes','bytes255']],16:[['entries','bytes16777216'],['manifestPlainDigest','b32']],17:[['generation','u64'],['manifestKeyDigest','b32'],['manifestCipherDigest','b32'],['keyedRoot','b32'],['state','u8'],['candidateGeneration','u64'],['candidateManifestKey','bytes255'],['candidateManifestKeyDigest','b32'],['candidateManifestCipherDigest','b32'],['candidateKeyedRoot','b32']],
});
const ENUM_SETS=Object.freeze({slotState:new Set([1,2,3,4]),keyPackageLifecycle:new Set([1,2,3,4]),commitOutcome:new Set([1,2,3]),apiState:new Set([1,2,3]),selectorState:new Set([1,2,3]),operation:new Set([1,2,3,4,5,6,7,8]),scenario:new Set([1,2,3,4,5,6,7]),outputKind:new Set([1,2,3,4,5,6]),successCode:new Set([1,2,3,4,5,6,7,8,9,10])});
// Bind a registry by (kind, field) only where the ratified record maps one. ISSUANCE_OUTCOME
// (kind 3) outcome/releaseState and SELECTION_METADATA eligibility / RETAINED_PARENT
// selectionRole have no registry in C-FMT and stay plain u8.
const ENUMS=Object.freeze({'1:slotState':'slotState','4:lifecycle':'keyPackageLifecycle','8:outcome':'commitOutcome','8:expectedOriginalState':'apiState','9:outputKind':'outputKind','13:operation':'operation','13:scenario':'scenario','13:originalApiState':'apiState','13:heldOutputKind':'outputKind','13:expectedSuccessCode':'successCode','13:expectedStateAfter':'apiState','13:resultStatus':'commitOutcome','17:state':'selectorState'});
const enumSet=(kind,name)=>{const registry=ENUMS[`${kind}:${name}`];return registry===undefined?undefined:ENUM_SETS[registry];};
function encodeField(type,value,name,kind){if(type==='b32')return bytes(value,32,name);if(type==='b389')return bytes(value,389,name);if(type==='bool')return Uint8Array.of(bool(value,name)?1:0);if(type==='u8'){const n=safeInt(value,255,name);const set=enumSet(kind,name);if(set&&!set.has(n))unsupported(`unknown ${name}`);return Uint8Array.of(n);}if(type==='u16'){const n=safeInt(value,65535,name);const set=enumSet(kind,name);if(set&&!set.has(n))unsupported(`unknown ${name}`);return be16(n);}if(type==='u32')return be32(safeInt(value,0xffffffff,name));if(type==='u64')return be64(u64(value,name));const max=Number(type.slice(5));return boundedBytes(value,max,name);}
function decodeField(type,value,name,kind){if(type==='b32'||type==='b389'||type.startsWith('bytes')){const expected=type==='b32'?32:type==='b389'?389:null;const v=bytes(value,expected,name);if(expected===null&&v.length>Number(type.slice(5)))malformed(`${name} exceeds bound`);return v;}if(type==='bool'){if(value.length!==1||(value[0]!==0&&value[0]!==1))malformed(`noncanonical ${name}`);return value[0]===1;}if(type==='u8'){if(value.length!==1)malformed(name);const n=value[0];const set=enumSet(kind,name);if(set&&!set.has(n))unsupported(`unknown ${name}`);return n;}if(type==='u16'){if(value.length!==2)malformed(name);const n=read16(value,0);const set=enumSet(kind,name);if(set&&!set.has(n))unsupported(`unknown ${name}`);return n;}if(type==='u32'){if(value.length!==4)malformed(name);return read32(value,0);}if(type==='u64'){if(value.length!==8)malformed(name);return read64(value,0);}malformed('unknown field type');}
function validateSemantic(kind,v){if(kind===4&&v.invalidPending&&v.lifecycle!==M2_LIFECYCLE.RESERVED)unsupported('invalidPending requires RESERVED');if(kind===17){const ck=decodeRecordKey(v.candidateManifestKey);if(ck.recordKind!==16||ck.writeGeneration!==v.candidateGeneration)unsupported('candidate manifest key mismatch');if(!equal(sha256(v.candidateManifestKey),v.candidateManifestKeyDigest))unsupported('candidate manifest key digest mismatch');const same=v.generation===v.candidateGeneration&&equal(v.manifestKeyDigest,v.candidateManifestKeyDigest)&&equal(v.manifestCipherDigest,v.candidateManifestCipherDigest)&&equal(v.keyedRoot,v.candidateKeyedRoot);if((v.state===3)!==(!same))unsupported('selector state/candidate inconsistency');}}
export function encodePlaintext(recordKind,value){kindVersion(recordKind);const schema=SCHEMAS[recordKind];
  const plain=value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
  const descriptor=plain?Object.getOwnPropertyDescriptor(value,'presence'):undefined;
  const presence=descriptor!==undefined&&Object.hasOwn(descriptor,'value')?descriptor.value:undefined;
  const keys=presence===0?['presence']:['presence',...schema.map(([n])=>n)];const v=strictObject(value,keys,'plaintext');if(v.presence!==0&&v.presence!==1)unsupported('presence');if(v.presence===0)return concat(ASCII('STYXPLN1'),be16(1),be16(recordKind),Uint8Array.of(0),be16(0));
  const fields=[];let total=15;for(let i=0;i<schema.length;i+=1){const [name,type]=schema[i];const raw=encodeField(type,v[name],name,recordKind);total+=5+raw.length;if(total>MAX_PLAINTEXT)malformed('plaintext exceeds cap');fields.push(Uint8Array.of(i+1),be32(raw.length),raw);}validateSemantic(recordKind,v);const out=concat(ASCII('STYXPLN1'),be16(1),be16(recordKind),Uint8Array.of(1),be16(schema.length),...fields);if(out.length>MAX_PLAINTEXT)malformed('plaintext exceeds cap');return out;}
export function decodePlaintext(recordKind,value){kindVersion(recordKind);const b=bytes(value,null,'plaintext');if(b.length>MAX_PLAINTEXT)malformed('plaintext exceeds cap');let o=expectMagic(b,0,'STYXPLN1');if(o+7>b.length)malformed('truncated plaintext');if(read16(b,o)!==1)unsupported('plaintext version');o+=2;if(read16(b,o)!==recordKind)mismatch('plaintext kind');o+=2;const presence=b[o++];const count=read16(b,o);o+=2;if(presence===0){if(count!==0||o!==b.length)malformed('noncanonical tombstone');return Object.freeze({presence:0});}if(presence!==1)unsupported('presence');const schema=SCHEMAS[recordKind];if(count!==schema.length)malformed('field count');const out={presence:1};for(let i=0;i<schema.length;i+=1){if(o+5>b.length||b[o++]!==i+1)malformed('field tag/order');const n=read32(b,o);o+=4;if(o+n>b.length)malformed('field truncation');const [name,type]=schema[i];out[name]=decodeField(type,b.slice(o,o+n),name,recordKind);o+=n;}if(o!==b.length)malformed('plaintext trailing');validateSemantic(recordKind,out);if(!equal(encodePlaintext(recordKind,out),b))malformed('noncanonical plaintext');return Object.freeze(out);}

export function encodeEnvelope(input){const s=strictObject(input,['recordKind','recordKey','aad','plaintextLength','nonce','ciphertext','tag'],'envelope');const kind=safeInt(s.recordKind,65535,'recordKind');const key=bytes(s.recordKey,null,'recordKey');const aad=bytes(s.aad,null,'aad');const pLen=safeInt(s.plaintextLength,MAX_PLAINTEXT,'plaintextLength');const nonce=bytes(s.nonce,12,'nonce');const ciphertext=bytes(s.ciphertext,null,'ciphertext');const tag=bytes(s.tag,16,'tag');if(ciphertext.length!==pLen)mismatch('ciphertext/plaintext length');const ad=decodeAad(aad);if(ad.recordKind!==kind||ad.plaintextLength!==pLen||!equal(ad.recordKey,key))mismatch('envelope AAD');if(kind===17)decodeSelectorKey(key);else decodeRecordKey(key);return concat(ASCII('STYXFMT1'),be16(1),be16(kind),be16(kindVersion(kind)),be16(1),be16(1),be16(1),be16(key.length),be32(aad.length),be32(pLen),be32(ciphertext.length),be16(16),key,aad,nonce,ciphertext,tag);}
export function decodeEnvelope(value){const b=bytes(value,null,'envelope');let o=expectMagic(b,0,'STYXFMT1');if(o+28>b.length)malformed('truncated envelope');const envelopeVersion=read16(b,o);o+=2;const recordKind=read16(b,o);o+=2;const recordKindVersion=read16(b,o);o+=2;const formatVersion=read16(b,o);o+=2;const keyVersion=read16(b,o);o+=2;const aeadId=read16(b,o);o+=2;const kl=read16(b,o);o+=2;const al=read32(b,o);o+=4;const plaintextLength=read32(b,o);o+=4;const cl=read32(b,o);o+=4;const tl=read16(b,o);o+=2;if(plaintextLength>MAX_PLAINTEXT)malformed('envelope plaintext length exceeds the C-FMT cap');if(envelopeVersion!==1||formatVersion!==1||keyVersion!==1||aeadId!==1||tl!==16)unsupported('envelope version/algorithm');if(recordKindVersion!==kindVersion(recordKind))unsupported('record kind version');if(cl!==plaintextLength||o+kl+al+12+cl+tl!==b.length)malformed('envelope lengths');const recordKey=b.slice(o,o+kl);o+=kl;const aad=b.slice(o,o+al);o+=al;const nonce=b.slice(o,o+12);o+=12;const ciphertext=b.slice(o,o+cl);o+=cl;const tag=b.slice(o);const ad=decodeAad(aad);if(ad.recordKind!==recordKind||ad.plaintextLength!==plaintextLength||!equal(ad.recordKey,recordKey))mismatch('envelope AAD');if(recordKind===17)decodeSelectorKey(recordKey);else decodeRecordKey(recordKey);return Object.freeze({envelopeVersion,recordKind,recordKindVersion,formatVersion,keyVersion,aeadId,recordKey:recordKey.slice(),aad:aad.slice(),plaintextLength,nonce:nonce.slice(),ciphertext:ciphertext.slice(),tag:tag.slice()});}
function selectorContextCheck(kind,plaintext,aad){if(kind!==17)return;const v=decodePlaintext(17,plaintext);const ad=decodeAad(aad);const locator=decodeSelectorKey(ad.recordKey);const candidate=decodeRecordKey(v.candidateManifestKey);if(!equal(candidate.localContextId,locator.localContextId))mismatch('candidate manifest context');if(ad.writeGeneration!==v.generation)mismatch('selector AAD generation vs selected generation');}
export async function sealRecord(input){const s=strictObject(input,['aeadKey','recordKind','recordKey','aad','plaintext','nonce'],'sealRecord');const key=bytes(s.aeadKey,32,'aeadKey');const kind=safeInt(s.recordKind,65535,'recordKind');const rk=bytes(s.recordKey,null,'recordKey');const aad=bytes(s.aad,null,'aad');const plaintext=bytes(s.plaintext,null,'plaintext');const nonce=bytes(s.nonce,12,'nonce');const ad=decodeAad(aad);if(ad.recordKind!==kind||ad.plaintextLength!==plaintext.length||!equal(ad.recordKey,rk))mismatch('seal expectations');decodePlaintext(kind,plaintext);selectorContextCheck(kind,plaintext,aad);const ck=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt']);let joined;try{joined=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},ck,plaintext));}catch{fail(CODE.AUTHENTICATION_FAILED,'record encryption failed');}return encodeEnvelope({recordKind:kind,recordKey:rk,aad,plaintextLength:plaintext.length,nonce,ciphertext:joined.slice(0,-16),tag:joined.slice(-16)});}
export async function openRecord(input){const s=strictObject(input,['aeadKey','envelope','expectedRecordKey','expectedAad'],'openRecord');const key=bytes(s.aeadKey,32,'aeadKey');const envBytes=bytes(s.envelope,null,'envelope');const expectedRecordKey=bytes(s.expectedRecordKey,null,'expectedRecordKey');const expectedAad=bytes(s.expectedAad,null,'expectedAad');const env=decodeEnvelope(envBytes);if(!equal(env.recordKey,expectedRecordKey)||!equal(env.aad,expectedAad))mismatch('open expectations');const ck=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['decrypt']);let plaintext;try{plaintext=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:env.nonce,additionalData:expectedAad,tagLength:128},ck,concat(env.ciphertext,env.tag)));}catch{fail(CODE.AUTHENTICATION_FAILED,'record authentication failed');}decodePlaintext(env.recordKind,plaintext);selectorContextCheck(env.recordKind,plaintext,expectedAad);return Object.freeze({plaintext:plaintext.slice(),envelope:env});}
export function consumeKeyPackage(value){const schema=SCHEMAS[4];const v=strictObject(value,['presence',...schema.map(([n])=>n)],'KeyPackage');if(v.presence!==1)unsupported('KeyPackage tombstone');const canonical=decodePlaintext(4,encodePlaintext(4,v));if(canonical.lifecycle===M2_LIFECYCLE.CONSUMED)fail(CODE.KEY_PACKAGE_ALREADY_USED,'KeyPackage already consumed');if(canonical.lifecycle!==M2_LIFECYCLE.UNCONSUMED||canonical.invalidPending)unsupported('KeyPackage is not consumable');const out={};for(const [k,val] of Object.entries(canonical))out[k]=val instanceof Uint8Array?val.slice():val;out.lifecycle=M2_LIFECYCLE.CONSUMED;return Object.freeze(out);}
