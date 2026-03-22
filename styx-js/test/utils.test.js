import { describe, test, expect, beforeEach } from '@jest/globals';
import {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  concatBytes,
  constantTimeEqual,
  randomBytes,
  uuidv4,
  utf8Encode,
  utf8Decode,
  uint32BE,
  readUint32BE,
  secureZero,
  EventEmitter,
} from '../src/utils.js';

describe('bytesToHex / hexToBytes', () => {
  test('roundtrip with known bytes', () => {
    const bytes = new Uint8Array([0x00, 0xff, 0xab, 0x12]);
    const hex = bytesToHex(bytes);
    expect(hex).toBe('00ffab12');
    expect(hexToBytes(hex)).toEqual(bytes);
  });

  test('empty array produces empty string', () => {
    expect(bytesToHex(new Uint8Array([]))).toBe('');
    expect(hexToBytes('')).toEqual(new Uint8Array([]));
  });

  test('hexToBytes throws on odd-length string', () => {
    expect(() => hexToBytes('abc')).toThrow('Invalid hex string');
  });

  test('hexToBytes handles uppercase by parsing correctly', () => {
    const result = hexToBytes('FF');
    expect(result).toEqual(new Uint8Array([255]));
  });
});

describe('bytesToBase64 / base64ToBytes', () => {
  test('roundtrip with known bytes', () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const b64 = bytesToBase64(bytes);
    expect(base64ToBytes(b64)).toEqual(bytes);
  });

  test('empty array roundtrip', () => {
    const bytes = new Uint8Array([]);
    const b64 = bytesToBase64(bytes);
    expect(base64ToBytes(b64)).toEqual(bytes);
  });
});

describe('concatBytes', () => {
  test('concatenates multiple Uint8Arrays', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    const c = new Uint8Array([6]);
    const result = concatBytes(a, b, c);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  test('single array returns copy', () => {
    const a = new Uint8Array([10, 20]);
    const result = concatBytes(a);
    expect(result).toEqual(a);
    expect(result).not.toBe(a);
  });

  test('empty arrays produce empty result', () => {
    const result = concatBytes(new Uint8Array([]), new Uint8Array([]));
    expect(result.length).toBe(0);
  });
});

describe('constantTimeEqual', () => {
  test('equal arrays return true', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  test('different arrays return false', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  test('different lengths return false', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([1, 2, 3]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  test('empty arrays are equal', () => {
    expect(constantTimeEqual(new Uint8Array([]), new Uint8Array([]))).toBe(true);
  });
});

describe('randomBytes', () => {
  test('returns Uint8Array of requested length', () => {
    const bytes = randomBytes(32);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);
  });

  test('two calls produce different results (with overwhelming probability)', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  test('zero length returns empty array', () => {
    const bytes = randomBytes(0);
    expect(bytes.length).toBe(0);
  });
});

describe('uuidv4', () => {
  test('matches UUID v4 format 8-4-4-4-12', () => {
    const uuid = uuidv4();
    const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    expect(uuid).toMatch(pattern);
  });

  test('two UUIDs are unique', () => {
    const a = uuidv4();
    const b = uuidv4();
    expect(a).not.toBe(b);
  });
});

describe('utf8Encode / utf8Decode', () => {
  test('roundtrip with ASCII', () => {
    const str = 'hello world';
    expect(utf8Decode(utf8Encode(str))).toBe(str);
  });

  test('roundtrip with unicode', () => {
    const str = 'ciao mondo \u{1F600}';
    expect(utf8Decode(utf8Encode(str))).toBe(str);
  });

  test('empty string roundtrip', () => {
    expect(utf8Decode(utf8Encode(''))).toBe('');
  });
});

describe('uint32BE / readUint32BE', () => {
  test('roundtrip with known value', () => {
    const bytes = uint32BE(0x01020304);
    expect(bytes).toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(readUint32BE(bytes)).toBe(0x01020304);
  });

  test('zero', () => {
    expect(uint32BE(0)).toEqual(new Uint8Array([0, 0, 0, 0]));
    expect(readUint32BE(uint32BE(0))).toBe(0);
  });

  test('max uint32', () => {
    const max = 0xffffffff;
    expect(readUint32BE(uint32BE(max))).toBe(max);
  });

  test('readUint32BE with offset', () => {
    const buf = new Uint8Array([0, 0, 0x01, 0x02, 0x03, 0x04]);
    expect(readUint32BE(buf, 2)).toBe(0x01020304);
  });
});

describe('secureZero', () => {
  test('fills array with zeros', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    secureZero(bytes);
    expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0]));
  });
});

describe('EventEmitter', () => {
  let emitter;

  beforeEach(() => {
    emitter = new EventEmitter();
  });

  test('on and emit', () => {
    const calls = [];
    emitter.on('test', (val) => calls.push(val));
    emitter.emit('test', 42);
    emitter.emit('test', 99);
    expect(calls).toEqual([42, 99]);
  });

  test('off removes listener', () => {
    const calls = [];
    const fn = (val) => calls.push(val);
    emitter.on('test', fn);
    emitter.emit('test', 1);
    emitter.off('test', fn);
    emitter.emit('test', 2);
    expect(calls).toEqual([1]);
  });

  test('on returns unsubscribe function', () => {
    const calls = [];
    const unsub = emitter.on('test', (val) => calls.push(val));
    emitter.emit('test', 1);
    unsub();
    emitter.emit('test', 2);
    expect(calls).toEqual([1]);
  });

  test('once fires only once', () => {
    const calls = [];
    emitter.once('test', (val) => calls.push(val));
    emitter.emit('test', 'a');
    emitter.emit('test', 'b');
    expect(calls).toEqual(['a']);
  });

  test('removeAllListeners with event name', () => {
    const calls = [];
    emitter.on('a', () => calls.push('a'));
    emitter.on('b', () => calls.push('b'));
    emitter.removeAllListeners('a');
    emitter.emit('a');
    emitter.emit('b');
    expect(calls).toEqual(['b']);
  });

  test('removeAllListeners without event name clears all', () => {
    const calls = [];
    emitter.on('a', () => calls.push('a'));
    emitter.on('b', () => calls.push('b'));
    emitter.removeAllListeners();
    emitter.emit('a');
    emitter.emit('b');
    expect(calls).toEqual([]);
  });

  test('emit with multiple arguments', () => {
    let received;
    emitter.on('multi', (a, b, c) => {
      received = [a, b, c];
    });
    emitter.emit('multi', 1, 2, 3);
    expect(received).toEqual([1, 2, 3]);
  });

  test('emit on non-existent event does nothing', () => {
    expect(() => emitter.emit('nonexistent')).not.toThrow();
  });
});
