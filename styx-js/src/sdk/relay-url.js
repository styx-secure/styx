// Card-owned relay validation; no URL global and no network side effects.
const SCHEME_SEPARATOR = ':' + '/' + '/';
const PCHAR_CLASS = "A-Za-z0-9\\-._~!$&'()*+,;=:@";
const PATH_ABEMPTY = new RegExp(`^(?:/(?:[${PCHAR_CLASS}]|%[0-9A-Fa-f]{2})*)*$`);
const QUERY = new RegExp(`^(?:[${PCHAR_CLASS}/?]|%[0-9A-Fa-f]{2})*$`);
const DEC_OCTET = /^(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
const H16 = /^[0-9A-Fa-f]{1,4}$/;

/**
 * The four octets of an RFC 3986 `IPv4address`, or `null`.
 *
 * @param {string} text
 * @returns {number[] | null}
 */
function ipv4Octets(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  for (const part of parts) if (!DEC_OCTET.test(part)) return null;
  return parts.map((part) => Number(part));
}

/**
 * The eight 16-bit groups of an RFC 3986 `IPv6address`, or `null`.
 *
 * @param {string} text
 * @returns {number[] | null}
 */
function ipv6Groups(text) {
  let head = text;
  let tail = [];
  const lastColon = text.lastIndexOf(':');
  if (lastColon < 0) return null;
  const last = text.slice(lastColon + 1);
  if (last.includes('.')) {
    const octets = ipv4Octets(last);
    if (octets === null) return null;
    tail = [octets[0] * 256 + octets[1], octets[2] * 256 + octets[3]];
    head = text.slice(0, lastColon + 1);
    // `x:` before the IPv4 tail loses its separator; `::` keeps it.
    if (!head.endsWith('::')) head = head.slice(0, -1);
  }
  const wanted = 8 - tail.length;
  const halves = head.split('::');
  if (halves.length > 2) return null;
  const groupsOf = (part) => (part === '' ? [] : part.split(':'));
  const before = groupsOf(halves[0]);
  const after = halves.length === 2 ? groupsOf(halves[1]) : [];
  for (const group of [...before, ...after]) if (!H16.test(group)) return null;
  let groups;
  if (halves.length === 2) {
    const elided = wanted - before.length - after.length;
    if (elided < 1) return null;
    groups = [...before, ...new Array(elided).fill('0'), ...after];
  } else {
    if (before.length !== wanted) return null;
    groups = before;
  }
  return [...groups.map((group) => Number.parseInt(group, 16)), ...tail];
}

/**
 * True when `url` is an absolute `ws:` or `wss:` URL, with no userinfo and no
 * fragment, whose host is a loopback IP address literal.
 *
 * @param {unknown} url
 * @returns {boolean}
 */
function isLoopbackRelayUrl(url) {
  if (typeof url !== 'string') return false;
  if (url.includes('#')) return false;
  const separator = url.indexOf(SCHEME_SEPARATOR);
  if (separator < 0) return false;
  const scheme = url.slice(0, separator).toLowerCase();
  if (scheme !== 'ws' && scheme !== 'wss') return false;
  const rest = url.slice(separator + SCHEME_SEPARATOR.length);
  let authorityEnd = rest.length;
  for (const mark of ['/', '?']) {
    const at = rest.indexOf(mark);
    if (at >= 0 && at < authorityEnd) authorityEnd = at;
  }
  const authority = rest.slice(0, authorityEnd);
  let remainder = rest.slice(authorityEnd);
  let query = null;
  const questionMark = remainder.indexOf('?');
  if (questionMark >= 0) {
    query = remainder.slice(questionMark + 1);
    remainder = remainder.slice(0, questionMark);
  }
  if (!PATH_ABEMPTY.test(remainder)) return false;
  if (query !== null && !QUERY.test(query)) return false;
  if (authority.includes('@')) return false;

  let host;
  let port;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) return false;
    host = authority.slice(1, close);
    port = authority.slice(close + 1);
    if (port !== '' && !/^:[0-9]*$/.test(port)) return false;
    // An IPvFuture literal and a zone identifier are rejected.
    if (/^[vV]/.test(host) || host.includes('%')) return false;
    const groups = ipv6Groups(host);
    if (groups === null || groups.length !== 8) return false;
    for (let i = 0; i < 7; i += 1) if (groups[i] !== 0) return false;
    return groups[7] === 1;
  }
  const colon = authority.indexOf(':');
  host = colon >= 0 ? authority.slice(0, colon) : authority;
  port = colon >= 0 ? authority.slice(colon) : '';
  if (port !== '' && !/^:[0-9]*$/.test(port)) return false;
  const octets = ipv4Octets(host);
  return octets !== null && octets[0] === 127;
}

/** The exact ASCII host rule of C-SDK section 4.1; no normalisation. */
export function isPublicRelayHost(host) {
  if (typeof host !== 'string' || host.length < 1 || host.length > 253) return false;
  if (/[^a-z0-9.-]/.test(host)) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false;
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) return false;
  }
  const last = labels[labels.length - 1];
  return !/^[0-9]+$/.test(last) && !/^0x[0-9a-f]*$/.test(last);
}

/** Loopback behaviour is unchanged; remote hosts require caller admission. */
export function isAllowedRelayUrl(url, publicRelayHosts = []) {
  if (isLoopbackRelayUrl(url)) return true;
  if (typeof url !== 'string') return false;
  const separator = url.indexOf(SCHEME_SEPARATOR);
  if (separator < 0 || url.slice(0, separator).toLowerCase() !== 'wss') return false;
  const rest = url.slice(separator + SCHEME_SEPARATOR.length);
  const authority = rest.endsWith('/') ? rest.slice(0, -1) : rest;
  // Host syntax excludes userinfo, ports, path/query/fragment and IP literals.
  if (/[^A-Za-z0-9.-]/.test(authority)) return false;
  const host = authority.toLowerCase();
  return isPublicRelayHost(host) && publicRelayHosts.includes(host);
}
