/**
 * Import guard for the SDK lane trees (I-SDK contract, "Import guard"; owner act #317 comment 6216937687, item 5).
 *
 * Scans every file under `styx-js/src/sdk/**` and `styx-js/test/sdk/**` (except the preview tree
 * `styx-js/test/sdk/flegias-preview/**`, left to the preview contract by C-SDK section 9) and fails when a file
 * imports, statically (`import ... from`, `import '...'`, `export ... from`, `export * from`), with dynamic
 * `import()` or with `require()`, a specifier or a name that the C-SDK section 9 table does not allow for that
 * file's location. Each file is tokenised: comments, string literals, regular-expression literals and the raw
 * text of template literals are inert, every `${ ... }` substitution is tokenised as code at any depth, and every
 * lexing doubt fails the file. It also fails on symbolic links, non-regular files, extensions other than `.js`,
 * `.mjs` and `.cjs`, and on a relay URL scheme substring in a file under `styx-js/src/sdk/**`.
 *
 * This file sits outside both scanned trees and outside the C-SDK section 9 bound. It locates the trees from its
 * own `import.meta.url` by string operations only, reads files and directories, follows no symbolic link and
 * writes nothing. Part (a) runs over the real trees; part (b) runs over synthetic in-memory sources.
 */
import { describe, expect, test } from '@jest/globals';
import { readdirSync, readFileSync } from 'node:fs';

// ---------------------------------------------------------------------------------------------------------------
// Locations (string operations only: no URL global, no node:url, no node:path).
// ---------------------------------------------------------------------------------------------------------------

/**
 * Normalises an absolute `/`-separated path: removes `.` segments and applies `..` segments. A trailing `/` is
 * kept. Returns `null` for a relative path, an empty segment or a `..` above the root.
 */
function normalizeAbsolute(path) {
  if (!path.startsWith('/')) return null;
  const trailing = path.endsWith('/');
  const segments = path.slice(1).split('/');
  const out = [];
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === '') {
      if (trailing && index === segments.length - 1) continue;
      return null;
    }
    if (segment === '.') continue;
    if (segment === '..') {
      if (out.length === 0) return null;
      out.pop();
      continue;
    }
    out.push(segment);
  }
  if (out.length === 0) return '/';
  return '/' + out.join('/') + (trailing ? '/' : '');
}

function locate(moduleUrl) {
  const scheme = 'file://';
  if (!moduleUrl.startsWith(scheme)) throw new Error('the guard must run from a file: module URL');
  const file = decodeURIComponent(moduleUrl.slice(scheme.length));
  const directory = file.slice(0, file.lastIndexOf('/') + 1);
  const located = {
    file,
    directory,
    root: normalizeAbsolute(directory + '../../'),
    src: normalizeAbsolute(directory + '../../src/sdk/'),
    test: normalizeAbsolute(directory + '../sdk/'),
  };
  for (const key of ['root', 'src', 'test']) {
    if (located[key] === null || !located[key].endsWith('/')) throw new Error(`cannot locate the ${key} directory`);
  }
  return located;
}

const HERE = locate(import.meta.url);
const ROOT = HERE.root; // styx-js/
const SRC = HERE.src; // styx-js/src/sdk/
const TEST = HERE.test; // styx-js/test/sdk/
const PREVIEW = TEST + 'flegias-preview/';
const UTILS = ROOT + 'src/utils.js';
const TRANSPORT_INTERFACE = ROOT + 'src/transport/transport-interface.js';
const NOSTR_TRANSPORT = ROOT + 'src/transport/nostr-transport.js';
const CURVES = '@noble/curves/secp256k1';

/** Path relative to the styx-js directory, for reports and allowlists. */
function relative(path) {
  return path.startsWith(ROOT) ? path.slice(ROOT.length) : path;
}

// ---------------------------------------------------------------------------------------------------------------
// The C-SDK section 9 table.
// ---------------------------------------------------------------------------------------------------------------

const UTILS_NAMES = new Set([
  'EventEmitter', 'uuidv4', 'bytesToHex', 'hexToBytes', 'utf8Encode', 'utf8Decode', 'randomBytes',
  'constantTimeEqual', 'concatBytes', 'bytesToBase64', 'base64ToBytes', 'secureZero',
]);
const TRANSPORT_INTERFACE_NAMES = new Set(['TransportInterface', 'TransportState', 'TransportMessage']);
const NOSTR_TRANSPORT_NAMES = new Set(['RelayPool']);

/** Package and built-in rows: `names` null means any name; `testOnly` means allowed only under test/sdk. */
const PACKAGE_ROWS = new Map([
  ['@noble/hashes/sha256', { names: new Set(['sha256']), testOnly: false }],
  [CURVES, { names: new Set(['schnorr']), testOnly: false }],
  ['@jest/globals', {
    names: new Set(['describe', 'test', 'it', 'expect', 'beforeAll', 'beforeEach', 'afterAll', 'afterEach', 'jest']),
    testOnly: true,
  }],
  ['ws', { names: new Set(['WebSocket', 'WebSocketServer']), testOnly: true }],
  ...['node:assert', 'node:events', 'node:net', 'node:http', 'node:timers', 'node:timers/promises', 'node:crypto']
    .map((name) => [name, { names: null, testOnly: true }]),
]);

/** Bare Node built-in names, only used to word the failure reason (every unlisted specifier fails anyway). */
const BARE_BUILTINS = new Set([
  'assert', 'buffer', 'child_process', 'crypto', 'dgram', 'dns', 'events', 'fs', 'fs/promises', 'http', 'http2',
  'https', 'module', 'net', 'os', 'path', 'process', 'stream', 'timers', 'timers/promises', 'tls', 'url', 'util',
  'v8', 'vm', 'worker_threads', 'zlib',
]);

/** Card allowlists of the scope record under the two trees (test files may import test files of their own card). */
const I_SDK_FILES = new Set([
  'src/sdk/index.js', 'src/sdk/client.js', 'src/sdk/delivery/outbox.js', 'src/sdk/delivery/receipts.js',
  'src/sdk/delivery/relay-pool.js', 'test/sdk/client.test.js', 'test/sdk/delivery/outbox.test.js',
  'test/sdk/delivery/receipts.test.js', 'test/sdk/delivery/relay-pool.test.js',
]);
const T_RELAY_PREFIX = 'test/sdk/integration/';

function sameCardAllowlist(importer, target) {
  const a = relative(importer);
  const b = relative(target);
  return (I_SDK_FILES.has(a) && I_SDK_FILES.has(b)) || (a.startsWith(T_RELAY_PREFIX) && b.startsWith(T_RELAY_PREFIX));
}

const SCANNED_EXTENSIONS = ['.js', '.mjs', '.cjs'];
const RELAY_SCHEMES = ['ws:' + '//', 'wss:' + '//'];

// ---------------------------------------------------------------------------------------------------------------
// Lexer.
// ---------------------------------------------------------------------------------------------------------------

class LexDoubt extends Error {}

const ID_START = /^[\p{ID_Start}$_]$/u;
const ID_CONTINUE = /^[\p{ID_Continue}$\u200c\u200d]$/u;
const WHITESPACE = /^[\t\v\f \u00a0\ufeff\p{Zs}]$/u;
const NUMBER = /(?:0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*|(?:(?:0|[1-9](?:_?[0-9])*)(?:\.(?:[0-9](?:_?[0-9])*)?)?|\.[0-9](?:_?[0-9])*)(?:[eE][+-]?[0-9](?:_?[0-9])*)?)n?/y;
const PUNCTUATORS = [
  '>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=', '*=', '%=', '&=', '|=', '^=',
  '**', '<<', '>>', ';', ',', '<', '>', '+', '-', '*', '%', '&', '|', '^', '!', '~', '?', ':', '=', '.', '@',
];
/** Words after which a `/` starts a regular-expression literal. */
const REGEX_AFTER_WORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await',
  'extends',
]);
/** Words after which a `/` cannot be classified without a parser. */
const DOUBT_AFTER_WORDS = new Set(['of']);
/**
 * In a script (a `.cjs` file) `await` and `yield` can also be plain identifiers, after which a `/` is a division:
 * there a `/` after either cannot be classified without a parser either.
 */
const SCRIPT_DOUBT_AFTER_WORDS = new Set(['await', 'yield']);
const CONTROL_WORDS = new Set(['if', 'while', 'for', 'with']);
const SIMPLE_ESCAPES = new Map([['n', '\n'], ['t', '\t'], ['r', '\r'], ['b', '\b'], ['f', '\f'], ['v', '\v']]);

function isDigit(ch) {
  return ch !== undefined && ch >= '0' && ch <= '9';
}

/**
 * Tokenises a source text. Tokens: `name` (value decoded, `escaped` set when it contained a `\u` escape),
 * `hashName`, `string` (value decoded), `number`, `regex`, `template` (one per raw chunk, value null) and `punct`.
 * The `${` and the `}` that open and close a template substitution are `punct` tokens. A `)` carries `control`
 * when it closes the head of `if`, `while`, `for` or `with`. Throws LexDoubt on any lexing doubt. `script` is
 * true for a `.cjs` file, which Node runs as a script rather than a module.
 */
function tokenize(text, { script = false } = {}) {
  const tokens = [];
  const nesting = [];
  let index = 0;
  let line = 1;

  const doubt = (what) => {
    throw new LexDoubt(`${what} (line ${line})`);
  };
  const push = (type, value, extra = {}) => {
    tokens.push({ type, value, line, ...extra });
  };
  const newlineLength = (position) => {
    const ch = text[position];
    if (ch === '\r') return text[position + 1] === '\n' ? 2 : 1;
    return ch === '\n' || ch === '\u2028' || ch === '\u2029' ? 1 : 0;
  };
  const isMemberName = (position) => {
    const previous = tokens[position - 1];
    return previous !== undefined && previous.type === 'punct' && (previous.value === '.' || previous.value === '?.');
  };

  function readUnicodeEscape(position) {
    if (text[position + 2] === '{') {
      const close = text.indexOf('}', position + 3);
      const hex = close === -1 ? '' : text.slice(position + 3, close);
      if (!/^[0-9a-fA-F]+$/.test(hex) || parseInt(hex, 16) > 0x10ffff) doubt('malformed \\u{...} escape');
      return { codePoint: parseInt(hex, 16), length: close + 1 - position };
    }
    const hex = text.slice(position + 2, position + 6);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) doubt('malformed \\u escape');
    return { codePoint: parseInt(hex, 16), length: 6 };
  }

  function slashStartsRegex() {
    const previous = tokens.length === 0 ? null : tokens[tokens.length - 1];
    if (previous === null) return true;
    switch (previous.type) {
      case 'number':
      case 'string':
      case 'template':
      case 'regex':
      case 'hashName':
        return false;
      case 'name':
        if (isMemberName(tokens.length - 1) || previous.escaped) return false;
        if (script && SCRIPT_DOUBT_AFTER_WORDS.has(previous.value)) {
          doubt(`cannot classify "/" after "${previous.value}" in a script`);
        }
        if (REGEX_AFTER_WORDS.has(previous.value)) return true;
        if (DOUBT_AFTER_WORDS.has(previous.value)) doubt(`cannot classify "/" after "${previous.value}"`);
        return false;
      default:
        if (previous.value === ')') return previous.control === true;
        if (previous.value === ']') return false;
        if (['}', '++', '--', '.', '?.'].includes(previous.value)) {
          doubt(`cannot classify "/" after "${previous.value}"`);
        }
        return true;
    }
  }

  function readString(quote) {
    let position = index + 1;
    let value = '';
    for (;;) {
      const ch = text[position];
      if (ch === undefined || ch === '\n' || ch === '\r') doubt('unterminated string literal');
      if (ch === quote) break;
      if (ch !== '\\') {
        if (ch === '\u2028' || ch === '\u2029') line += 1;
        value += ch;
        position += 1;
        continue;
      }
      const escape = text[position + 1];
      if (escape === undefined) doubt('unterminated string literal');
      const continuation = newlineLength(position + 1);
      if (continuation > 0) {
        line += 1;
        position += 1 + continuation;
        continue;
      }
      if (escape === 'x') {
        const hex = text.slice(position + 2, position + 4);
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) doubt('malformed \\x escape');
        value += String.fromCharCode(parseInt(hex, 16));
        position += 4;
        continue;
      }
      if (escape === 'u') {
        const { codePoint, length } = readUnicodeEscape(position);
        value += String.fromCodePoint(codePoint);
        position += length;
        continue;
      }
      if (isDigit(escape)) {
        if (escape === '0' && !isDigit(text[position + 2])) {
          value += '\0';
          position += 2;
          continue;
        }
        doubt('legacy octal, \\8 or \\9 escape');
      }
      value += SIMPLE_ESCAPES.has(escape) ? SIMPLE_ESCAPES.get(escape) : escape;
      position += 2;
    }
    push('string', value);
    index = position + 1;
  }

  function readTemplateChunk() {
    let position = index;
    for (;;) {
      const ch = text[position];
      if (ch === undefined) doubt('unterminated template literal');
      if (ch === '`') {
        push('template', null, { tail: true });
        index = position + 1;
        return;
      }
      if (ch === '$' && text[position + 1] === '{') {
        push('template', null, { tail: false });
        push('punct', '${');
        nesting.push({ open: '${' });
        index = position + 2;
        return;
      }
      if (ch === '\\') {
        position += 1;
        if (text[position] === undefined) doubt('unterminated template literal');
      }
      const newline = newlineLength(position);
      if (newline > 0) {
        line += 1;
        position += newline;
      } else {
        position += 1;
      }
    }
  }

  function readRegex() {
    let position = index + 1;
    let inClass = false;
    for (;;) {
      const ch = text[position];
      if (ch === undefined || newlineLength(position) > 0) doubt('unterminated regular-expression literal');
      if (ch === '\\') {
        if (text[position + 1] === undefined || newlineLength(position + 1) > 0) {
          doubt('unterminated regular-expression literal');
        }
        position += 2;
        continue;
      }
      if (ch === '[') inClass = true;
      else if (ch === ']') inClass = false;
      else if (ch === '/' && !inClass) break;
      position += 1;
    }
    position += 1;
    while (position < text.length && ID_CONTINUE.test(text[position])) position += 1;
    if (text[position] === '\\') doubt('escape in regular-expression flags');
    push('regex', null);
    index = position;
  }

  function readName() {
    let position = index;
    let value = '';
    let escaped = false;
    const hash = text[position] === '#';
    if (hash) position += 1;
    for (;;) {
      let codePoint;
      let length;
      const isEscape = text[position] === '\\';
      if (isEscape) {
        if (text[position + 1] !== 'u') doubt('malformed escape in identifier');
        ({ codePoint, length } = readUnicodeEscape(position));
        escaped = true;
      } else {
        codePoint = text.codePointAt(position);
        if (codePoint === undefined) break;
        length = codePoint > 0xffff ? 2 : 1;
      }
      const ch = String.fromCodePoint(codePoint);
      if (!(value === '' ? ID_START.test(ch) : ID_CONTINUE.test(ch))) {
        if (isEscape) doubt('escape of a non-identifier character in identifier');
        break;
      }
      value += ch;
      position += length;
    }
    if (value === '') doubt('stray "#" or "\\"');
    push(hash ? 'hashName' : 'name', value, { escaped });
    index = position;
  }

  function readNumber() {
    NUMBER.lastIndex = index;
    const match = NUMBER.exec(text);
    if (match === null || match[0] === '') doubt('malformed numeric literal');
    const end = index + match[0].length;
    const next = text[end];
    if (next !== undefined && (isDigit(next) || next === '\\' || ID_START.test(String.fromCodePoint(text.codePointAt(end))))) {
      doubt('malformed numeric literal');
    }
    push('number', match[0]);
    index = end;
  }

  if (text.startsWith('#!')) {
    while (index < text.length && newlineLength(index) === 0) index += 1;
  }

  while (index < text.length) {
    const ch = text[index];
    const newline = newlineLength(index);
    if (newline > 0) {
      line += 1;
      index += newline;
      continue;
    }
    if (WHITESPACE.test(ch)) {
      index += 1;
      continue;
    }
    if (ch === '/' && text[index + 1] === '/') {
      while (index < text.length && newlineLength(index) === 0) index += 1;
      continue;
    }
    if (ch === '/' && text[index + 1] === '*') {
      const close = text.indexOf('*/', index + 2);
      if (close === -1) doubt('unterminated block comment');
      for (let position = index + 2; position < close; position += 1) {
        const length = newlineLength(position);
        if (length > 0) {
          line += 1;
          position += length - 1;
        }
      }
      index = close + 2;
      continue;
    }
    if (ch === '\'' || ch === '"') {
      readString(ch);
      continue;
    }
    if (ch === '`') {
      index += 1;
      readTemplateChunk();
      continue;
    }
    if (ch === '/') {
      if (slashStartsRegex()) {
        readRegex();
      } else {
        const value = text[index + 1] === '=' ? '/=' : '/';
        push('punct', value);
        index += value.length;
      }
      continue;
    }
    if (isDigit(ch) || (ch === '.' && isDigit(text[index + 1]))) {
      readNumber();
      continue;
    }
    if (ch === '#' || ch === '\\' || ID_START.test(String.fromCodePoint(text.codePointAt(index)))) {
      readName();
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      let control = false;
      if (ch === '(') {
        const previous = tokens[tokens.length - 1];
        const isWordAt = (position, words) => {
          const token = tokens[position];
          return token !== undefined && token.type === 'name' && !token.escaped && words.has(token.value)
            && !isMemberName(position);
        };
        control = isWordAt(tokens.length - 1, CONTROL_WORDS)
          || (previous !== undefined && previous.type === 'name' && previous.value === 'await'
            && isWordAt(tokens.length - 2, new Set(['for'])));
      }
      nesting.push({ open: ch, control });
      push('punct', ch);
      index += 1;
      continue;
    }
    if (ch === ')' || ch === ']') {
      const top = nesting.pop();
      if (top === undefined || top.open !== (ch === ')' ? '(' : '[')) doubt(`unbalanced "${ch}"`);
      push('punct', ch, ch === ')' ? { control: top.control } : {});
      index += 1;
      continue;
    }
    if (ch === '}') {
      const top = nesting.pop();
      if (top === undefined || (top.open !== '{' && top.open !== '${')) doubt('unbalanced "}"');
      push('punct', '}');
      index += 1;
      if (top.open === '${') readTemplateChunk();
      continue;
    }
    const punctuator = PUNCTUATORS.find((candidate) => text.startsWith(candidate, index)
      && !(candidate === '?.' && isDigit(text[index + 2])));
    if (punctuator === undefined) doubt(`unexpected character U+${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
    push('punct', punctuator);
    index += punctuator.length;
  }
  if (nesting.length > 0) doubt(`unclosed "${nesting[nesting.length - 1].open}" at end of file`);
  return tokens;
}

// ---------------------------------------------------------------------------------------------------------------
// Import extraction.
// ---------------------------------------------------------------------------------------------------------------

function isPunct(token, value) {
  return token !== undefined && token.type === 'punct' && token.value === value;
}

function isWord(token, value) {
  return token !== undefined && token.type === 'name' && !token.escaped && token.value === value;
}

function isNameOrString(token) {
  return token !== undefined && (token.type === 'name' || token.type === 'string');
}

function isMemberPosition(tokens, position) {
  return isPunct(tokens[position - 1], '.') || isPunct(tokens[position - 1], '?.');
}

/** Reads `{ a, b as c, 'd' as e }` starting at the `{`; returns the items and the index after `}`, or null. */
function readSpecifierList(tokens, start) {
  let position = start + 1;
  const items = [];
  for (;;) {
    if (isPunct(tokens[position], '}')) return { items, end: position + 1 };
    const first = tokens[position];
    if (!isNameOrString(first)) return null;
    let local = first.value;
    position += 1;
    if (isWord(tokens[position], 'as')) {
      if (!isNameOrString(tokens[position + 1])) return null;
      local = tokens[position + 1].value;
      position += 2;
    }
    items.push({ imported: first.value, local });
    if (isPunct(tokens[position], ',')) {
      position += 1;
      continue;
    }
    if (!isPunct(tokens[position], '}')) return null;
  }
}

/** `form(` followed by exactly one string literal and `)`; anything else cannot be checked. */
function readCallArgument(tokens, open, form, line) {
  if (isPunct(tokens[open], '(') && tokens[open + 1] !== undefined && tokens[open + 1].type === 'string'
    && isPunct(tokens[open + 2], ')')) {
    return { form, specifier: tokens[open + 1].value, names: ['*'], bindings: [], line };
  }
  return {
    form, specifier: null, names: [], bindings: [], line,
    problem: `${form} used other than as a call with a single string-literal argument`,
  };
}

function formProblem(form, line) {
  return { form, specifier: null, names: [], bindings: [], line, problem: `unrecognised ${form} form` };
}

function parseImport(tokens, start) {
  const line = tokens[start].line;
  const next = tokens[start + 1];
  if (next === undefined) return { record: formProblem('import', line), end: start + 1 };
  if (isPunct(next, '(')) return { record: readCallArgument(tokens, start + 1, 'import()', line), end: start + 1 };
  if (isPunct(next, '.')) {
    return isWord(tokens[start + 2], 'meta') ? null : { record: formProblem('import', line), end: start + 1 };
  }
  if (isPunct(next, ':')) return null; // a property key named `import`
  if (next.type === 'string') {
    return { record: { form: 'import', specifier: next.value, names: [], bindings: [], line }, end: start + 2 };
  }
  const names = [];
  const bindings = [];
  let position = start + 1;
  let needsClause = true;
  if (next.type === 'name') {
    names.push('default');
    bindings.push({ imported: 'default', local: next.value });
    position += 1;
    needsClause = false;
    if (isPunct(tokens[position], ',')) {
      position += 1;
      needsClause = true;
    }
  }
  if (needsClause) {
    if (isPunct(tokens[position], '*')) {
      if (!isWord(tokens[position + 1], 'as') || tokens[position + 2] === undefined
        || tokens[position + 2].type !== 'name') {
        return { record: formProblem('import', line), end: start + 1 };
      }
      names.push('*');
      bindings.push({ imported: '*', local: tokens[position + 2].value });
      position += 3;
    } else if (isPunct(tokens[position], '{')) {
      const list = readSpecifierList(tokens, position);
      if (list === null) return { record: formProblem('import', line), end: start + 1 };
      for (const item of list.items) {
        names.push(item.imported);
        bindings.push(item);
      }
      position = list.end;
    } else {
      return { record: formProblem('import', line), end: start + 1 };
    }
  }
  if (!isWord(tokens[position], 'from') || tokens[position + 1] === undefined
    || tokens[position + 1].type !== 'string') {
    return { record: formProblem('import', line), end: start + 1 };
  }
  return {
    record: { form: 'import', specifier: tokens[position + 1].value, names, bindings, line },
    end: position + 2,
  };
}

function parseExport(tokens, start) {
  const line = tokens[start].line;
  const next = tokens[start + 1];
  if (isPunct(next, '*')) {
    let position = start + 2;
    if (isWord(tokens[position], 'as')) {
      if (!isNameOrString(tokens[position + 1])) return { record: formProblem('export', line), end: start + 1 };
      position += 2;
    }
    if (!isWord(tokens[position], 'from') || tokens[position + 1] === undefined
      || tokens[position + 1].type !== 'string') {
      return { record: formProblem('export', line), end: start + 1 };
    }
    return {
      record: { form: 'export * from', specifier: tokens[position + 1].value, names: ['*'], bindings: [], line },
      end: position + 2,
    };
  }
  if (isPunct(next, '{')) {
    const list = readSpecifierList(tokens, start + 1);
    if (list === null) return { record: formProblem('export', line), end: start + 1 };
    if (!isWord(tokens[list.end], 'from')) return null; // a local export list
    if (tokens[list.end + 1] === undefined || tokens[list.end + 1].type !== 'string') {
      return { record: formProblem('export', line), end: start + 1 };
    }
    return {
      record: {
        form: 'export from', specifier: tokens[list.end + 1].value,
        names: list.items.map((item) => item.imported), bindings: [], line,
      },
      end: list.end + 2,
    };
  }
  return null;
}

function endsOperand(token) {
  return token !== undefined && (token.type === 'name' || token.type === 'string' || token.type === 'template'
    || isPunct(token, ')') || isPunct(token, ']') || isPunct(token, '?.'));
}

/**
 * Every import of a token list: static imports and re-exports, dynamic `import()`, and every `require` or
 * `createRequire` used as a name, as a member name or as a computed string member. Returns the records and the
 * indices of the tokens that belong to static import and re-export clauses.
 */
function readImports(tokens) {
  const records = [];
  const clauseTokens = new Set();
  for (let position = 0; position < tokens.length; position += 1) {
    const token = tokens[position];
    if (token.type === 'name' && (token.value === 'import' || token.value === 'export')
      && !isMemberPosition(tokens, position)) {
      if (token.escaped) {
        records.push({ ...formProblem(token.value, token.line), problem: `escaped "${token.value}" keyword` });
        continue;
      }
      const parsed = token.value === 'import' ? parseImport(tokens, position) : parseExport(tokens, position);
      if (parsed !== null) {
        records.push(parsed.record);
        for (let index = position; index < parsed.end; index += 1) clauseTokens.add(index);
      }
      continue;
    }
    const requireName = token.type === 'name' && (token.value === 'require' || token.value === 'createRequire');
    const requireKey = token.type === 'string' && (token.value === 'require' || token.value === 'createRequire')
      && isPunct(tokens[position - 1], '[') && isPunct(tokens[position + 1], ']') && endsOperand(tokens[position - 2]);
    if (requireName || requireKey) {
      records.push(readCallArgument(tokens, requireName ? position + 1 : position + 2, token.value, token.line));
    }
  }
  return { records, clauseTokens };
}

// ---------------------------------------------------------------------------------------------------------------
// Rows.
// ---------------------------------------------------------------------------------------------------------------

function nameReason(name) {
  if (name === '*') return 'namespace import, export *, dynamic import() or require() of a name-restricted specifier';
  if (name === 'default') return 'default import of a name-restricted specifier';
  return 'name not allowed by the C-SDK section 9 row';
}

/** Failures of one import record against the rows for the importing file's location. */
function rowFailures(file, record, inventory) {
  const { specifier, names } = record;
  const inSrc = file.startsWith(SRC);
  const whole = (reason) => [{ name: null, reason }];
  const limit = (allowed) => names.filter((name) => !allowed.has(name)).map((name) => ({ name, reason: nameReason(name) }));

  if (specifier.startsWith('./') || specifier.startsWith('../')) {
    if (/[%?#\\]/.test(specifier)) return whole('relative specifier containing %, ?, # or a backslash');
    const target = normalizeAbsolute(file.slice(0, file.lastIndexOf('/') + 1) + specifier);
    if (target === null) return whole('relative specifier with an empty segment or above the root');
    if (target.startsWith(SRC)) {
      return target.endsWith('.js') && inventory.has(target) ? [] : whole('no such lane module (.js file) under src/sdk');
    }
    if (target === UTILS) return limit(UTILS_NAMES);
    if (target === TRANSPORT_INTERFACE) return limit(TRANSPORT_INTERFACE_NAMES);
    if (target === NOSTR_TRANSPORT) return limit(NOSTR_TRANSPORT_NAMES);
    if (target.startsWith(TEST)) {
      if (inSrc) return whole('a src/sdk module may not import a test file');
      if (!sameCardAllowlist(file, target)) return whole('test file outside the importing file\'s card allowlist');
      return inventory.has(target) ? [] : whole('no such test file');
    }
    return whole('path outside every row of the C-SDK section 9 table');
  }
  const row = PACKAGE_ROWS.get(specifier);
  if (row !== undefined) {
    if (row.testOnly && inSrc) return whole('specifier allowed in test/sdk only');
    return row.names === null ? [] : limit(row.names);
  }
  if (specifier.startsWith('node:') || BARE_BUILTINS.has(specifier)) {
    return whole(inSrc ? 'Node built-in under src/sdk' : 'Node built-in outside the seven allowed in test/sdk');
  }
  return whole('specifier outside every row of the C-SDK section 9 table');
}

/**
 * Checks one file. Returns failures `{ file, specifier, name, reason }` (specifier and name are null when the
 * failure concerns the file as a whole). `inventory` is the set of scanned file paths.
 */
function checkFile(file, text, inventory) {
  const failures = [];
  const add = (specifier, name, reason) => failures.push({ file: relative(file), specifier, name, reason });
  if (!SCANNED_EXTENSIONS.some((extension) => file.endsWith(extension))) {
    add(null, null, 'extension other than .js, .mjs or .cjs');
    return failures;
  }
  const inSrc = file.startsWith(SRC);
  if (inSrc) {
    const lower = text.toLowerCase();
    if (RELAY_SCHEMES.some((scheme) => lower.includes(scheme))) add(null, null, 'relay URL scheme substring under src/sdk');
  }
  let tokens;
  try {
    tokens = tokenize(text, { script: file.endsWith('.cjs') });
  } catch (error) {
    if (!(error instanceof LexDoubt)) throw error;
    add(null, null, `lexing doubt: ${error.message}`);
    return failures;
  }
  const { records, clauseTokens } = readImports(tokens);
  const schnorrLocals = new Set();
  for (const record of records) {
    if (record.problem !== undefined) {
      add(record.specifier, null, `${record.problem} (line ${record.line})`);
      continue;
    }
    for (const failure of rowFailures(file, record, inventory)) add(record.specifier, failure.name, failure.reason);
    if (inSrc && record.specifier === CURVES) {
      if (record.form === 'export from') add(CURVES, 'schnorr', 're-export of schnorr under src/sdk (only schnorr.verify)');
      for (const binding of record.bindings) {
        if (binding.imported === 'schnorr') schnorrLocals.add(binding.local);
      }
    }
  }
  if (inSrc && schnorrLocals.size > 0) {
    for (let position = 0; position < tokens.length; position += 1) {
      const token = tokens[position];
      if (token.type !== 'name' || !schnorrLocals.has(token.value) || clauseTokens.has(position)
        || isMemberPosition(tokens, position)) {
        continue;
      }
      const dot = tokens[position + 1];
      const member = tokens[position + 2];
      const isMember = isPunct(dot, '.') || isPunct(dot, '?.');
      if (isMember && member !== undefined && member.type === 'name' && member.value === 'verify') continue;
      const what = isMember && member !== undefined && member.type === 'name' ? `schnorr.${member.value}` : 'schnorr';
      add(CURVES, what, `schnorr use other than .verify under src/sdk (line ${token.line})`);
    }
  }
  return failures;
}

// ---------------------------------------------------------------------------------------------------------------
// Trees.
// ---------------------------------------------------------------------------------------------------------------

/** Walks both trees with `readDirectory(dir)` (Dirent-like entries); follows no symbolic link. */
function listTrees(readDirectory) {
  const files = [];
  const failures = [];
  const visit = (directory) => {
    const entries = [...readDirectory(directory)]
      .sort((a, b) => (a.name < b.name ? -1 : (a.name > b.name ? 1 : 0)));
    for (const entry of entries) {
      const path = directory + entry.name;
      if (path + '/' === PREVIEW) continue;
      if (entry.isSymbolicLink()) {
        failures.push({ file: relative(path), specifier: null, name: null, reason: 'symbolic link' });
      } else if (entry.isDirectory()) {
        visit(path + '/');
      } else if (entry.isFile()) {
        files.push(path);
      } else {
        failures.push({ file: relative(path), specifier: null, name: null, reason: 'not a regular file' });
      }
    }
  };
  visit(SRC);
  visit(TEST);
  return { files, failures };
}

function runGuard(readDirectory, readText) {
  const { files, failures } = listTrees(readDirectory);
  const inventory = new Set(files);
  for (const file of files) {
    const text = readText(file);
    if (text === null) {
      failures.push({ file: relative(file), specifier: null, name: null, reason: 'not valid UTF-8' });
    } else {
      failures.push(...checkFile(file, text, inventory));
    }
  }
  return { files, failures };
}

function readRealDirectory(directory) {
  return readdirSync(directory, { withFileTypes: true });
}

function readRealText(file) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(file));
  } catch (error) {
    if (error instanceof TypeError) return null;
    throw error;
  }
}

let realResult = null;
function realScan() {
  if (realResult === null) realResult = runGuard(readRealDirectory, readRealText);
  return realResult;
}

function report(failures) {
  return failures.map((failure) => `${failure.file} | specifier ${JSON.stringify(failure.specifier)}`
    + ` | name ${JSON.stringify(failure.name)} | ${failure.reason}`);
}

// ---------------------------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------------------------

const MIMIC_FILES = [SRC + 'client.js', SRC + 'index.js', TEST + 'client.test.js'];

/** Checks a synthetic source against the real inventory plus the mimic files, the file itself and `extra`. */
function synthetic(file, source, extra = []) {
  return checkFile(file, source, new Set([...realScan().files, ...MIMIC_FILES, file, ...extra]));
}

const WS_LOWER = ['ws', '//'].join(':');
const WS_UPPER = ['WS', '//'].join(':');
const WSS_MIXED = ['WsS', '//'].join(':');

const S = (path) => SRC + path;
const T = (path) => TEST + path;
const CURVES_IMPORT = "import { schnorr } from '@noble/curves/secp256k1';\n";

/**
 * Synthetic cases: [title, file, source, expected ('pass' | 'fail'), expected failure fields (for 'fail')].
 * The first group is the Coverage (b) list of the contract, in its order.
 */
const COVERAGE_CASES = [
  ['uint32BE from utils.js', S('client.js'), "import { uint32BE } from '../utils.js';", 'fail',
    { specifier: '../utils.js', name: 'uint32BE' }],
  ['readUint32BE from utils.js', S('delivery/extra.js'), "import { bytesToHex, readUint32BE } from '../../utils.js';",
    'fail', { specifier: '../../utils.js', name: 'readUint32BE' }],
  ['NostrTransport from nostr-transport.js', S('client.js'),
    "import { NostrTransport } from '../transport/nostr-transport.js';", 'fail', { name: 'NostrTransport' }],
  ['OutboxWorker from nostr-transport.js', T('delivery/outbox.test.js'),
    "import { RelayPool, OutboxWorker } from '../../../src/transport/nostr-transport.js';", 'fail',
    { name: 'OutboxWorker' }],
  ['a namespace import of utils.js', S('client.js'), "import * as utils from '../utils.js';", 'fail',
    { specifier: '../utils.js', name: '*' }],
  ['a default import of utils.js', T('client.test.js'), "import utils from '../../src/utils.js';", 'fail',
    { specifier: '../../src/utils.js', name: 'default' }],
  ['export { uint32BE } from utils.js', S('index.js'), "export { uint32BE } from '../utils.js';", 'fail',
    { specifier: '../utils.js', name: 'uint32BE' }],
  ['export * from utils.js', S('index.js'), "export * from '../utils.js';", 'fail',
    { specifier: '../utils.js', name: '*' }],
  ["import('node:fs') under src/sdk", S('client.js'), "const fs = await import('node:fs');", 'fail',
    { specifier: 'node:fs', reason: 'Node built-in under src/sdk' }],
  ["require('node:fs') under src/sdk", S('client.js'), "const fs = require('node:fs');", 'fail',
    { specifier: 'node:fs', reason: 'Node built-in under src/sdk' }],
  ["import 'fs' under src/sdk", S('client.js'), "import 'fs';", 'fail',
    { specifier: 'fs', reason: 'Node built-in under src/sdk' }],
  ["import('../utils.js') under src/sdk", S('client.js'), "const utils = await import('../utils.js');", 'fail',
    { specifier: '../utils.js', name: '*' }],
  ['a non-literal import(x)', S('client.js'), "const x = './delivery/retry.js';\nconst m = await import(x);", 'fail',
    { specifier: null, reason: expect.stringContaining('other than as a call with a single string-literal argument') }],
  ["import('node:fs') inside a template substitution", S('client.js'),
    "const s = `value ${await import('node:fs')} end`;", 'fail', { specifier: 'node:fs' }],
  ["require('node:fs') inside a template substitution", T('client.test.js'),
    "const s = `value ${require('node:fs').sep} end`;", 'fail', { specifier: 'node:fs' }],
  ['ws under src/sdk', S('delivery/relay-extra.js'), "import { WebSocket } from 'ws';", 'fail',
    { specifier: 'ws', reason: 'specifier allowed in test/sdk only' }],
  ['@jest/globals under src/sdk', S('client.js'), "import { describe } from '@jest/globals';", 'fail',
    { specifier: '@jest/globals', reason: 'specifier allowed in test/sdk only' }],
  ['schnorr.sign under src/sdk', S('delivery/extra.js'),
    CURVES_IMPORT + 'export const sign = (message, key) => schnorr.sign(message, key);', 'fail',
    { specifier: CURVES, name: 'schnorr.sign' }],
  ['schnorr.verify under src/sdk', S('delivery/extra.js'),
    CURVES_IMPORT + 'export const check = (sig, id, key) => schnorr.verify(sig, id, key) === true;', 'pass'],
  ['schnorr from @noble/curves/secp256k1 in test/sdk', T('delivery/receipts.test.js'),
    CURVES_IMPORT + 'const key = schnorr.getPublicKey(randomSeed);\nconst sig = schnorr.sign(new Uint8Array(32), key);',
    'pass'],
  ['node:crypto in test/sdk', T('delivery/relay-pool.test.js'),
    "import { randomBytes } from 'node:crypto';\nimport * as nodeCrypto from 'node:crypto';", 'pass'],
  ['readFileSync from node:fs in client.test.js', T('client.test.js'), "import { readFileSync } from 'node:fs';",
    'fail', { specifier: 'node:fs', name: null }],
  ['readFileSync from node:fs in another file under test/sdk', T('delivery/outbox.test.js'),
    "import { readFileSync } from 'node:fs';", 'fail', { specifier: 'node:fs', name: null }],
  ['an import of an src/sdk path that does not exist', S('client.js'),
    "import { createThing } from './delivery/does-not-exist.js';", 'fail',
    { specifier: './delivery/does-not-exist.js', reason: 'no such lane module (.js file) under src/sdk' }],
  ["module.require('node:fs')", T('client.test.js'), "const fs = module.require('node:fs');", 'fail',
    { specifier: 'node:fs' }],
  ["globalThis.require('node:fs')", S('client.js'), "const fs = globalThis.require('node:fs');", 'fail',
    { specifier: 'node:fs' }],
  ['an upper-case WS relay URL literal under src/sdk (built at run time)', S('client.js'), `export const relay = '${WS_UPPER}127.0.0.1:7000';`, 'fail',
    { specifier: null, reason: 'relay URL scheme substring under src/sdk' }],
  ['an import of src/storage/...', S('client.js'), "import { MemoryStore } from '../storage/memory-store.js';",
    'fail', { specifier: '../storage/memory-store.js', reason: 'path outside every row of the C-SDK section 9 table' }],
  ['an import of src/crypto/...', T('client.test.js'), "import { createEngine } from '../../src/crypto/mls/engine.js';",
    'fail', { specifier: '../../src/crypto/mls/engine.js' }],
  ['a .mjs file with a forbidden import', S('delivery/extra.mjs'), "import { readFileSync } from 'node:fs';", 'fail',
    { file: 'src/sdk/delivery/extra.mjs', specifier: 'node:fs' }],
  ['a commented-out forbidden import', S('client.js'),
    "// import { readFileSync } from 'node:fs';\n/* const fs = require('node:fs'); import('node:fs') */\nexport const x = 1;",
    'pass'],
  ['a forbidden import inside a string literal', S('client.js'),
    "export const text = \"import { readFileSync } from 'node:fs'; require('node:fs')\" + 'import(\"node:fs\")';",
    'pass'],
];

const EXTRA_CASES = [
  // Lane modules: any names, every form, both locations.
  ['lane modules with named, namespace, export * and dynamic forms under src/sdk', S('client.js'),
    "import { planRetry } from './delivery/retry.js';\nimport * as receipts from './delivery/receipts.js';\n"
    + "export * from './delivery/outbox.js';\nconst pool = await import('./delivery/relay-pool.js');", 'pass'],
  ['lane modules with namespace and dynamic forms under test/sdk', T('delivery/retry.test.js'),
    "import * as retryModule from '../../../src/sdk/delivery/retry.js';\n"
    + "const m = await import('../../../src/sdk/delivery/outbox.js');", 'pass'],
  ['an extensionless lane module specifier', S('client.js'), "import { planRetry } from './delivery/retry';", 'fail',
    { reason: 'no such lane module (.js file) under src/sdk' }],
  ['a lane module specifier with a percent escape', S('client.js'), "import { planRetry } from './delivery/r%65try.js';",
    'fail', { reason: 'relative specifier containing %, ?, # or a backslash' }],
  ['a side-effect import of utils.js (no name reached)', S('client.js'), "import '../utils.js';", 'pass'],
  ['utils.js { default as x }', S('client.js'), "import { default as utils } from '../utils.js';", 'fail',
    { name: 'default' }],
  ['the twelve utils.js names with aliases', S('client.js'),
    `import { ${[...UTILS_NAMES].map((name) => `${name} as local${name}`).join(', ')} } from '../utils.js';`, 'pass'],
  ['transport-interface.js named exports', T('client.test.js'),
    "import { TransportInterface, TransportState, TransportMessage } from '../../src/transport/transport-interface.js';",
    'pass'],
  ['RelayPool from nostr-transport.js', S('delivery/extra.js'),
    "import { RelayPool } from '../../transport/nostr-transport.js';", 'pass'],
  ['another file under src/transport', S('client.js'), "import { X } from '../transport/webrtc-transport.js';", 'fail',
    { reason: 'path outside every row of the C-SDK section 9 table' }],
  ['src/config and apps', T('client.test.js'),
    "import { load } from '../../src/config/index.js';\nimport { app } from '../../apps/web/main.js';", 'fail',
    { specifier: '../../src/config/index.js' }],
  ['a bare crypto built-in in test/sdk', T('client.test.js'), "import { randomBytes } from 'crypto';", 'fail',
    { specifier: 'crypto', reason: 'Node built-in outside the seven allowed in test/sdk' }],
  ["import('node:fs') in test/sdk", T('client.test.js'), "const fs = await import('node:fs');", 'fail',
    { specifier: 'node:fs' }],
  ['a default import of ws', T('client.test.js'), "import WebSocket from 'ws';", 'fail', { specifier: 'ws', name: 'default' }],
  ['an unlisted @jest/globals name', T('client.test.js'), "import { describe, vi } from '@jest/globals';", 'fail',
    { name: 'vi' }],
  ['the nine @jest/globals names and the ws names', T('client.test.js'),
    "import { describe, test, it, expect, beforeAll, beforeEach, afterAll, afterEach, jest } from '@jest/globals';\n"
    + "import { WebSocket, WebSocketServer } from 'ws';", 'pass'],
  ['node built-ins: default, namespace and require in test/sdk', T('delivery/relay-pool.test.js'),
    "import events from 'node:events';\nimport * as timers from 'node:timers/promises';\n"
    + "const net = require('node:net');\nconst http = module.require('node:http');", 'pass'],
  ['an aliased schnorr member other than verify under src/sdk', S('delivery/extra.js'),
    "import { schnorr as curve } from '@noble/curves/secp256k1';\nconst key = curve.getPublicKey(randomSeed);", 'fail',
    { name: 'schnorr.getPublicKey' }],
  ['schnorr destructured or computed under src/sdk', S('delivery/extra.js'),
    CURVES_IMPORT + "const { sign } = schnorr;\nconst other = schnorr['sign'];", 'fail', { name: 'schnorr' }],
  ['schnorr re-exported under src/sdk', S('index.js'), "export { schnorr } from '@noble/curves/secp256k1';", 'fail',
    { name: 'schnorr' }],
  ['a namespace import of @noble/hashes/sha256', T('client.test.js'), "import * as hashes from '@noble/hashes/sha256';",
    'fail', { name: '*' }],
  // Test files importing test files.
  ['an I-SDK test importing an I-SDK test', T('client.test.js'), "import { helper } from './delivery/outbox.test.js';",
    'pass'],
  ['an I-SDK test importing a test of another card', T('client.test.js'),
    "import { helper } from './delivery/retry.test.js';", 'fail',
    { reason: 'test file outside the importing file\'s card allowlist' }],
  ['a test of another card importing an I-SDK test', T('delivery/retry.test.js'),
    "import { helper } from './outbox.test.js';", 'fail',
    { reason: 'test file outside the importing file\'s card allowlist' }],
  ['a T-RELAY test importing a T-RELAY file', T('integration/scenario.test.js'),
    "import { startRelay } from './helpers/relay.js';", 'pass', null, [T('integration/helpers/relay.js')]],
  ['a T-RELAY test importing an I-SDK test', T('integration/scenario.test.js'),
    "import { helper } from '../client.test.js';", 'fail',
    { reason: 'test file outside the importing file\'s card allowlist' }],
  ['a test importing the guard file', T('client.test.js'), "import '../sdk-guard/import-guard.test.js';", 'fail',
    { reason: 'path outside every row of the C-SDK section 9 table' }],
  ['a src/sdk module importing a test file', S('client.js'), "import { helper } from '../../test/sdk/client.test.js';",
    'fail', { reason: 'a src/sdk module may not import a test file' }],
  // require forms.
  ['require used without a call', T('client.test.js'), 'const load = require;\nload(\'node:fs\');', 'fail',
    { specifier: null, reason: expect.stringContaining('other than as a call with a single string-literal argument') }],
  ['createRequire', T('client.test.js'), 'const load = createRequire(import.meta.url);', 'fail',
    { specifier: null, reason: expect.stringContaining('other than as a call with a single string-literal argument') }],
  ['an escaped require name', S('client.js'), "const fs = requir\\u0065('node:fs');", 'fail', { specifier: 'node:fs' }],
  ['a computed require member', T('client.test.js'), "const fs = module['require']('node:fs');", 'fail',
    { specifier: 'node:fs' }],
  ['require with a non-literal argument', T('client.test.js'), "const fs = require('node:' + 'fs');", 'fail',
    { specifier: null, reason: expect.stringContaining('other than as a call with a single string-literal argument') }],
  ['import() with an options argument', S('client.js'), "const m = await import('./delivery/retry.js', { with: {} });",
    'fail', { specifier: null, reason: expect.stringContaining('other than as a call with a single string-literal argument') }],
  ['a specifier with string escapes', S('client.js'), "const fs = await import('node:\\x66s');", 'fail',
    { specifier: 'node:fs' }],
  ['import.meta is not an import', S('client.js'), 'export const here = import.meta.url;', 'pass'],
  ['an unrecognised import form', S('client.js'), "import defer * as utils from '../utils.js';", 'fail',
    { specifier: null, reason: expect.stringContaining('unrecognised import form') }],
  ['a lane relay URL scheme in mixed case', S('delivery/extra.js'), `const relays = ['${WSS_MIXED}127.0.0.1'];`, 'fail',
    { reason: 'relay URL scheme substring under src/sdk' }],
  // Lexing.
  ['template raw text is inert', S('client.js'), "export const s = `import('node:fs') require('node:fs') \\${x}`;",
    'pass'],
  ['a substitution nested three deep', S('client.js'),
    "export const s = `a${`b${`c${ { k: await import('node:fs') }.k }`}`}`;", 'fail', { specifier: 'node:fs' }],
  ['a regular-expression literal is inert', S('client.js'),
    "const re = /import\\('node:fs'\\)|require\\(/u;\nexport const v = re.test(x) / 2;", 'pass'],
  ['a regular expression after a control-statement head', S('client.js'),
    "if (x) /require('node:fs')/.test(y);\nfor (const a of b) /import('node:fs')[/]/g.exec(a);", 'pass'],
  ['a regular expression after return', S('client.js'),
    "export function f(x) { return /import('node:fs')/.test(x); }", 'pass'],
  ['a division followed by a real import()', S('client.js'),
    "const v = a / b;\nconst w = (c) / (await import('node:fs')).length;", 'fail', { specifier: 'node:fs' }],
  ['a "/" after "}" cannot be classified', S('client.js'), "function f() {}\n/x/.test('');", 'fail',
    { specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['an unterminated string', S('client.js'), "const s = 'abc;\n", 'fail', { specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['an unterminated block comment', S('client.js'), 'const s = 1; /* no end', 'fail', { specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['an unterminated template', S('client.js'), 'const s = `abc ${x}', 'fail', { specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['an unterminated regular expression', S('client.js'), 'const r = /abc\n/;', 'fail', { specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['an unbalanced brace', S('client.js'), 'function f() {', 'fail', { specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['a "/" after an await identifier in a script hiding require()', S('delivery/extra.cjs'),
    "const await = 1;\nawait / require('node:fs') / 1;", 'fail',
    { file: 'src/sdk/delivery/extra.cjs', specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['a "/" after an await identifier in a script hiding import()', S('delivery/extra.cjs'),
    "const await = 1;\nawait / import('node:fs') / 1;", 'fail',
    { file: 'src/sdk/delivery/extra.cjs', specifier: null, reason: expect.stringContaining('lexing doubt') }],
  ['a "/" after a yield identifier in a script hiding require()', T('delivery/extra.cjs'),
    "var yield = 1;\nyield / require('node:fs') / 1;", 'fail',
    { file: 'test/sdk/delivery/extra.cjs', specifier: null, reason: expect.stringContaining('lexing doubt') }],
];

function asCases(rows) {
  return rows.map(([title, file, source, expected, match = null, extra = []]) => ({
    title: `${title} in ${relative(file)}`, file, source, expected, match, extra,
  }));
}

/** A conforming client.js, index.js and client.test.js, as the I-SDK contract describes them. */
const MIMIC_CLIENT = `/**
 * Client assembly (synthetic stand-in).
 */
import { createOutbox } from './delivery/outbox.js';
import { createReceipts } from './delivery/receipts.js';
import { createRelaySet } from './delivery/relay-pool.js';
import { retryDelayMs } from './delivery/retry.js';
import { bytesToHex, randomBytes } from '../utils.js';

export const SDK_INTERFACE_VERSION = 'styx-m3-sdk/0.1';
const HEX64 = /^[0-9a-f]{64}$/;
export const ClientState = Object.freeze({ CREATED: 'CREATED', RUNNING: 'RUNNING', STOPPED: 'STOPPED' });

export function createStyxClient(config) {
  const subscriptionId = \`s\${bytesToHex(randomBytes(16))}\`;
  const half = Math.floor(config.delivery.perRelayTimeoutMs / 2);
  const ratio = (a, b) => a / b / 2;
  if (!HEX64.test(config.key)) return { ok: false, code: 'E_SDK_INVALID_CONFIG' };
  const filter = { kinds: [4741, 4742], '#p': [config.key] };
  queueMicrotask(() => {});
  return { ok: true, value: { subscriptionId, half, ratio, filter, createOutbox, createReceipts, createRelaySet, retryDelayMs } };
}
`;

const MIMIC_INDEX = `export {
  SDK_INTERFACE_VERSION,
  SdkResultCode,
  DeliveryState,
  RelayOutcome,
  ClientState,
  SdkEventKind,
  isKnownResultCode,
  createStyxClient,
} from './client.js';
`;

const MIMIC_CLIENT_TEST = `import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '../../src/utils.js';
import * as sdk from '../../src/sdk/index.js';
import * as clientModule from '../../src/sdk/client.js';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { randomUUID } from 'node:crypto';

globalThis.WebSocket = WebSocket;

describe('client', () => {
  test('re-export identity', () => {
    for (const name of Object.keys(clientModule)) expect(sdk[name]).toBe(clientModule[name]);
  });

  test('a mocked outbox', async () => {
    jest.resetModules();
    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({ createOutbox: () => ({ inspectStore: () => ({}) }) }));
    const { createStyxClient } = await import('../../src/sdk/client.js');
    const secretKey = randomBytes(32);
    const key = schnorr.getPublicKey(secretKey);
    const digest = sha256(randomBytes(32));
    const sig = schnorr.sign(digest, key);
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening');
    const url = \`${WS_LOWER}127.0.0.1:\${server.address().port}\`;
    const ratio = sig.length / 2 / 1;
    expect(/^[0-9a-f]+$/.test(bytesToHex(hexToBytes('00')))).toBe(true);
    expect(typeof createStyxClient).toBe('function');
    await delay(1);
    server.close();
    return { url, ratio, id: randomUUID() };
  });
});
`;

describe('import guard (C-SDK section 9)', () => {
  test('locates both trees from import.meta.url as directories outside the guard directory', () => {
    expect(SRC).toBe(ROOT + 'src/sdk/');
    expect(TEST).toBe(ROOT + 'test/sdk/');
    expect(HERE.directory).toBe(ROOT + 'test/sdk-guard/');
    expect(HERE.directory.startsWith(TEST)).toBe(false);
    expect(HERE.file.startsWith(SRC) || HERE.file.startsWith(TEST)).toBe(false);
    const { files } = realScan();
    expect(files).toContain(SRC + 'delivery/retry.js');
    expect(files).toContain(TEST + 'delivery/retry.test.js');
    expect(files.every((file) => file.startsWith(SRC) || file.startsWith(TEST))).toBe(true);
    expect(files.some((file) => file.startsWith(PREVIEW))).toBe(false);
  });

  test('(a) the real trees import only what the C-SDK section 9 table allows', () => {
    expect(report(realScan().failures)).toEqual([]);
  });

  test('the guard file imports only describe, test, expect and readFileSync, readdirSync', () => {
    const { records } = readImports(tokenize(readFileSync(HERE.file, 'utf8')));
    expect(records.map(({ form, specifier, names }) => ({ form, specifier, names }))).toEqual([
      { form: 'import', specifier: '@jest/globals', names: ['describe', 'expect', 'test'] },
      { form: 'import', specifier: 'node:fs', names: ['readdirSync', 'readFileSync'] },
    ]);
  });

  describe('(b) synthetic sources: Coverage list of the contract', () => {
    test.each(asCases(COVERAGE_CASES))('$title: expected $expected', ({ file, source, expected, match, extra }) => {
      const failures = synthetic(file, source, extra);
      if (expected === 'pass') {
        expect(report(failures)).toEqual([]);
      } else {
        expect(failures.length).toBeGreaterThan(0);
        expect(failures).toEqual(expect.arrayContaining([expect.objectContaining(match)]));
      }
    });
  });

  describe('(b) synthetic sources: further rows, forms and lexing cases', () => {
    test.each(asCases(EXTRA_CASES))('$title: expected $expected', ({ file, source, expected, match, extra }) => {
      const failures = synthetic(file, source, extra);
      if (expected === 'pass') {
        expect(report(failures)).toEqual([]);
      } else {
        expect(failures.length).toBeGreaterThan(0);
        expect(failures).toEqual(expect.arrayContaining([expect.objectContaining(match)]));
      }
    });
  });

  test('(b) a conforming client.js, index.js and client.test.js pass', () => {
    expect(report(synthetic(S('client.js'), MIMIC_CLIENT))).toEqual([]);
    expect(report(synthetic(S('index.js'), MIMIC_INDEX))).toEqual([]);
    expect(report(synthetic(T('client.test.js'), MIMIC_CLIENT_TEST))).toEqual([]);
    const specifiers = (source) => readImports(tokenize(source)).records.map((record) => `${record.form} ${record.specifier}`);
    expect(specifiers(MIMIC_CLIENT)).toEqual([
      'import ./delivery/outbox.js', 'import ./delivery/receipts.js', 'import ./delivery/relay-pool.js',
      'import ./delivery/retry.js', 'import ../utils.js',
    ]);
    expect(specifiers(MIMIC_INDEX)).toEqual(['export from ./client.js']);
    // jest.unstable_mockModule(...) is a call with a string argument, not an import: it yields no record.
    expect(specifiers(MIMIC_CLIENT_TEST)).toEqual([
      'import @jest/globals', 'import ws', `import ${CURVES}`, 'import @noble/hashes/sha256', 'import ../../src/utils.js',
      'import ../../src/sdk/index.js', 'import ../../src/sdk/client.js', 'import node:events',
      'import node:timers/promises', 'import node:crypto', 'import() ../../src/sdk/client.js',
    ]);
  });

  test('(b) the same client.js without one of its lane modules fails', () => {
    const inventory = new Set(realScan().files.filter((file) => file !== SRC + 'delivery/retry.js'));
    inventory.add(SRC + 'client.js');
    expect(checkFile(SRC + 'client.js', MIMIC_CLIENT, inventory)).toEqual([expect.objectContaining({
      specifier: './delivery/retry.js', reason: 'no such lane module (.js file) under src/sdk',
    })]);
  });

  test('(b) tree walk: symbolic links, non-regular files and other extensions fail; the preview tree is skipped', () => {
    const entry = (name, kind) => ({
      name,
      isFile: () => kind === 'file',
      isDirectory: () => kind === 'dir',
      isSymbolicLink: () => kind === 'symlink',
    });
    const tree = new Map([
      [SRC, [entry('delivery', 'dir'), entry('link.js', 'symlink'), entry('notes.txt', 'file')]],
      [SRC + 'delivery/', [entry('outbox.js', 'file'), entry('pipe', 'fifo'), entry('extra.cjs', 'file')]],
      [TEST, [entry('flegias-preview', 'dir'), entry('flegias-previewx', 'dir'), entry('client.test.js', 'file')]],
      [TEST + 'flegias-previewx/', [entry('a.test.mjs', 'file')]],
    ]);
    const texts = new Map([
      [SRC + 'notes.txt', 'plain text'],
      [SRC + 'delivery/outbox.js', "import { planRetry } from './extra.cjs';"],
      [SRC + 'delivery/extra.cjs', 'module.exports = 1;'],
      [TEST + 'client.test.js', "import { describe } from '@jest/globals';"],
      [TEST + 'flegias-previewx/a.test.mjs', "import { readFileSync } from 'node:fs';"],
    ]);
    const readDirectory = (directory) => {
      if (!tree.has(directory)) throw new Error(`unexpected directory read: ${directory}`);
      return tree.get(directory);
    };
    const { files, failures } = runGuard(readDirectory, (file) => texts.get(file));
    expect(files).toEqual([
      SRC + 'delivery/extra.cjs', SRC + 'delivery/outbox.js', SRC + 'notes.txt', TEST + 'client.test.js',
      TEST + 'flegias-previewx/a.test.mjs',
    ]);
    expect(failures).toEqual([
      { file: 'src/sdk/delivery/pipe', specifier: null, name: null, reason: 'not a regular file' },
      { file: 'src/sdk/link.js', specifier: null, name: null, reason: 'symbolic link' },
      // A lane module must be a .js file: the .cjs one is scanned, but is not an importable lane module.
      {
        file: 'src/sdk/delivery/outbox.js', specifier: './extra.cjs', name: null,
        reason: 'no such lane module (.js file) under src/sdk',
      },
      { file: 'src/sdk/notes.txt', specifier: null, name: null, reason: 'extension other than .js, .mjs or .cjs' },
      {
        file: 'test/sdk/flegias-previewx/a.test.mjs', specifier: 'node:fs', name: null,
        reason: 'Node built-in outside the seven allowed in test/sdk',
      },
    ]);
  });
});
