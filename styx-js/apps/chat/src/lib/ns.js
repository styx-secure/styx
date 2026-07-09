// ns.js — optional peer namespace from the URL (?ns=alice).
// Lets two same-origin tabs hold separate identities (separate localStorage
// prefix) while still connecting over the shared-origin BroadcastChannel.
// Empty for the normal single-user app.
export function peerNamespace() {
  try {
    return new URLSearchParams(window.location.search).get('ns') || '';
  } catch {
    return '';
  }
}
