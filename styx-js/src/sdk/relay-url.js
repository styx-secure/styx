/**
 * Relay URL rule of the SDK -- PROTOTYPE (branch proto/sdk-demo-2026-10).
 *
 * C-SDK 4.1 / I-SDK draft: an absolute ws:/wss: URL (RFC 3986 subset, no
 * userinfo, no fragment) whose host is a loopback IP literal. The prototype
 * ALSO admits wss: URLs whose host is exactly one allowlisted public relay,
 * default port only. Shared by the client and the invite flow.
 */

/**
 * PROTOTYPE ONLY. C-SDK 4.1 admits loopback IP literals only. This branch
 * also admits `wss:` URLs whose host is exactly one of these public relays
 * (host names, no scheme, so no relay URL literal appears in src/sdk).
 */
export const PROTOTYPE_PUBLIC_RELAY_HOSTS = Object.freeze(['relay.damus.io', 'relay.primal.net', 'offchain.pub']);

/* --- relay URL rule (RFC 3986 subset, as the I-SDK draft states) ---------- */

const UNRESERVED_SUB = "A-Za-z0-9\\-._~!$&'()*+,;=";
const PCT_OK = /%(?![0-9A-Fa-f]{2})/;
const PATH_RE = new RegExp(`^(?:/(?:[${UNRESERVED_SUB}:@]|%[0-9A-Fa-f]{2})*)*$`);
const QUERY_RE = new RegExp(`^(?:[${UNRESERVED_SUB}:@/?]|%[0-9A-Fa-f]{2})*$`);

function isLoopbackV4(h) {
  const parts = h.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) if (!/^(?:0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255) return false;
  return parts[0] === '127';
}

function ipv6Value(s) {
  // returns array of 8 numbers or null
  let tail = [];
  let str = s;
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m) {
    const v4 = m[2].split('.');
    if (v4.some((p) => !/^(?:0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255)) return null;
    tail = [(Number(v4[0]) << 8) | Number(v4[1]), (Number(v4[2]) << 8) | Number(v4[3])];
    str = m[1].endsWith('::') ? m[1] : m[1].slice(0, -1);
  }
  const want = 8 - tail.length;
  const dbl = str.split('::');
  if (dbl.length > 2) return null;
  const grp = (x) => (x === '' ? [] : x.split(':'));
  const head = grp(dbl[0]);
  const rest = dbl.length === 2 ? grp(dbl[1]) : [];
  for (const g of [...head, ...rest]) if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) return null;
  let groups;
  if (dbl.length === 2) {
    const fill = want - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array(fill).fill('0'), ...rest];
  } else {
    if (head.length !== want) return null;
    groups = head;
  }
  return [...groups.map((g) => parseInt(g, 16)), ...tail];
}

export function relayUrlAllowed(url) {
  if (typeof url !== 'string') return false;
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?$/.exec(url);
  if (!m || url.includes('#')) return false;
  const scheme = m[1].toLowerCase();
  if (scheme !== 'ws' && scheme !== 'wss') return false;
  const authority = m[2];
  if (authority.includes('@')) return false;
  if (PCT_OK.test(url)) return false;
  if (!PATH_RE.test(m[3]) || (m[4] !== undefined && !QUERY_RE.test(m[4]))) return false;
  let host;
  let port;
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) return false;
    host = authority.slice(0, end + 1);
    port = authority.slice(end + 1);
  } else {
    const c = authority.lastIndexOf(':');
    host = c >= 0 ? authority.slice(0, c) : authority;
    port = c >= 0 ? authority.slice(c) : '';
  }
  if (port !== '' && !/^:[0-9]*$/.test(port)) return false;
  if (host.startsWith('[')) {
    const inner = host.slice(1, -1);
    if (/^[vV]/.test(inner) || inner.includes('%')) return false;
    const v = ipv6Value(inner);
    return !!v && v.slice(0, 7).every((x) => x === 0) && v[7] === 1;
  }
  if (isLoopbackV4(host)) return true;
  // PROTOTYPE: public relay allowlist, wss only, exact host name, default port.
  return scheme === 'wss' && port === '' && PROTOTYPE_PUBLIC_RELAY_HOSTS.includes(host.toLowerCase())
    && host === host.toLowerCase();
}

