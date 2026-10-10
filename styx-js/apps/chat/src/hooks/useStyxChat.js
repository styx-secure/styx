// useStyxChat — encapsulates the single StyxChat instance and all subscriptions.
// Components read reactive state (me, contacts, messagesByContact, typingByContact)
// and call wrapped actions; they never touch the library directly.

import { useCallback, useEffect, useRef, useState } from 'react';
import { getStyxChat } from '../lib/styx-adapter.js';
import { acquireWriterLock } from '../lib/writer-lock.js';
import { peerNamespace } from '../lib/ns.js';
import { getRelays, getBridgeUrl, transportOptions } from '../lib/config.js';
import { browserNotifier } from '../lib/notify.js';
import { openVaultSettings } from '../lib/vault-settings.js';
import { PushRegistrar } from 'styx-js';

const PAGE = 20;

// M2 single-tab beta guard (owner act m2-rescope-c-reduced §3, #317 comment 6091950328). Only the
// stage-gated `test-profile` build carries the M2 beta, so only that build loads the guard. The
// condition is a literal, compile-time foldable token: stage-off bundles drop the dynamic import.
const M2_BETA_STAGE = Boolean(import.meta.env) && import.meta.env.VITE_VAULT_STAGE === 'test-profile';
const loadM2BetaGate = M2_BETA_STAGE
  ? () => import('../../../../src/storage/m2/beta-gate.js')
  : async () => null;

// Delivery-state ordering. A receipt that arrives out of order (e.g. a delayed
// 'delivered' after 'read') must never downgrade the tick.
// One stop per vault settings session: a logout, a repeated logout and the app's own stop all await
// the same promise, so no caller can free the M2 lock while another's stop is still pending.
const workerStops = new WeakMap();
function stopSession(session) {
  if (session === null || (typeof session !== 'object' && typeof session !== 'function')) return Promise.resolve();
  let stopping = workerStops.get(session);
  if (!stopping) {
    stopping = (async () => {
      let stop;
      try { stop = session.stop; } catch { stop = null; }
      try { await stop?.call(session); } catch { /* bounded worker teardown */ }
    })();
    workerStops.set(session, stopping);
  }
  return stopping;
}

const STATE_RANK = { sending: 0, sent: 1, delivered: 2, read: 3, failed: 1 };
const advances = (from, to) => (STATE_RANK[to] ?? -1) > (STATE_RANK[from] ?? -1);

export function useStyxChat() {
  const chatRef = useRef(null);
  const subsRef = useRef([]);
  const activeRef = useRef(null); // the active startup/session controller ({ abort }) or null
  const attemptRef = useRef(0); // startup attempt counter: a logout or a newer attempt makes older ones stale
  const busyRef = useRef(null); // work still retiring (an attempt, a logout's ordered release), awaited by unlock
  const typingTimers = useRef({});
  const notifierRef = useRef(null);
  const vaultSettingsRef = useRef(null);
  if (!notifierRef.current) notifierRef.current = browserNotifier();

  const [ready, setReady] = useState(false);
  const [fatalError, setFatalError] = useState(null);
  const [secondaryTab, setSecondaryTab] = useState(false);
  const [unsupportedBrowser, setUnsupportedBrowser] = useState(false);
  const [me, setMe] = useState(null);
  const [contacts, setContacts] = useState([]);
  const [messagesByContact, setMessagesByContact] = useState({});
  const [typingByContact, setTypingByContact] = useState({});
  const [noMore, setNoMore] = useState({});
  const [pendingPairings, setPendingPairings] = useState([]);
  const [vaultPreferences, setVaultPreferences] = useState(null);

  // --- append/patch helpers (functional, closure-safe) ---
  const upsertMessage = useCallback((msg) => {
    setMessagesByContact((prev) => {
      const list = prev[msg.contactPubkey] || [];
      if (list.some((m) => m.id === msg.id)) return prev; // dedup by id
      const next = [...list, msg].sort((a, b) => a.ts - b.ts);
      return { ...prev, [msg.contactPubkey]: next };
    });
  }, []);

  const patchMessageState = useCallback((messageId, state) => {
    setMessagesByContact((prev) => {
      let touched = false;
      const next = {};
      for (const [k, list] of Object.entries(prev)) {
        next[k] = list.map((m) => {
          if (m.id === messageId && advances(m.state, state)) {
            touched = true;
            return { ...m, state };
          }
          return m;
        });
      }
      return touched ? next : prev;
    });
  }, []);

  // --- lifecycle ---
  const enablePush = useCallback(async () => {
    const chat = chatRef.current;
    if (!chat) return false;
    const bridgeUrl = getBridgeUrl();
    if (!bridgeUrl) return false;
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return false;
    if (!('serviceWorker' in navigator)) return false;
    try {
      const reg = await navigator.serviceWorker.ready;
      const registrar = new PushRegistrar({
        bridgeUrl,
        pubkey: chat.me.pubkey,
        sign: (action, endpoint) => chat.signBridgeRegistration(action, endpoint),
        fetchImpl: (...a) => fetch(...a),
        pushManager: reg.pushManager,
      });
      return await registrar.enable();
    } catch (e) {
      console.debug('enablePush failed', e);
      return false;
    }
  }, []);

  const unlock = useCallback(async ({ password, alias, firstRun }) => {
    // One startup attempt at a time. Starting an attempt (or a logout) makes any earlier attempt
    // stale and retires it, releasing what it acquired in the act §3 order. This attempt first
    // waits for everything still retiring, so the tab never meets its own locks and misreports
    // "another tab".
    attemptRef.current += 1;
    const attempt = attemptRef.current;
    const stale = () => attemptRef.current !== attempt;
    retireActive();
    const previous = busyRef.current;
    let retire;
    const retired = new Promise((resolve) => { retire = resolve; });
    const busy = (async () => {
      try { await previous; } catch { /* retiring work frees its locks in a finally */ }
      await retired;
    })();
    busyRef.current = busy;
    try {
      let StyxChat;
      try {
        StyxChat = await getStyxChat();
      } catch (e) {
        // A missing crypto module is a hard stop, not a wrong-password error: surface it
        // as a blocking state instead of letting the app fall through to fake data.
        if (stale()) return undefined;
        if (e?.name === 'FatalCryptoError') { setFatalError(e); return undefined; }
        throw e;
      }
      if (stale()) return undefined;
      const ns = peerNamespace();
      try { await previous; } catch { /* retiring work frees its locks in a finally */ }
      if (stale()) return undefined;
      return await startSession({ StyxChat, ns, password, alias, firstRun, stale });
    } finally {
      retire();
      void busy.finally(() => { if (busyRef.current === busy) busyRef.current = null; });
    }
  }, [upsertMessage, patchMessageState]);

  // Acquire both locks and start the chat. The attempt registers a controller in `activeRef`
  // before acquiring anything, so a logout (or unmount, or a newer attempt) reaches its resources
  // at any point, even while a startup step is still pending:
  // - at once: subscriptions off, chat destroyed, the M2 token revoked (`isHeld()` false), the vault
  //   worker's stop started;
  // - then, once the pending step has returned (nothing new can be acquired after that): withdraw
  //   the held report (or terminate the peer), the worker stopped, the `styx-m2:` lock freed, and
  //   the legacy writer lock freed last.
  async function startSession({ StyxChat, ns, password, alias, firstRun, stale }) {
    let gate = null;
    let gateReleasing = null;
    let chat = null;
    let settingsSession = null;
    let releaseWriter = null;
    const subs = [];
    let settleBody;
    const bodySettled = new Promise((resolve) => { settleBody = resolve; });
    let finalizing = null;

    const stopWorker = () => stopSession(settingsSession);
    const revokeNow = () => {
      for (const off of subs.splice(0)) { try { off?.(); } catch { /* ignore */ } }
      try { chat?.destroy(); } catch { /* best-effort transport teardown */ }
      if (settingsSession) void stopWorker();
      if (gate && !gateReleasing) {
        const g = gate;
        // `release()` turns `isHeld()` false synchronously; the lock itself is kept until the
        // pending startup step has returned and the worker is stopped.
        gateReleasing = g.release({ beforeFree: async () => { await bodySettled; await stopWorker(); } });
      }
    };
    const abort = () => {
      revokeNow();
      if (!finalizing) {
        finalizing = (async () => {
          await bodySettled; // the in-flight step returned: whatever it acquired is visible here
          revokeNow();
          try { await gateReleasing; } catch { /* the gate frees its lock in a finally */ }
          await stopWorker();
          // Web Locks are not reentrant: without releasing here, a retry would find OUR OWN lock
          // held and misreport "secondary tab".
          try { await releaseWriter?.(); } catch { /* ignore */ }
        })();
      }
      return finalizing;
    };
    const controller = Object.freeze({ abort });
    activeRef.current = controller;

    const STALE = Symbol('stale');
    const checkpoint = () => { if (stale()) throw STALE; };

    const run = async () => {
      // Become the single MLS writer for this profile, or refuse to start a writer.
      // A second tab that cannot get the lock must not construct a writable engine —
      // that is what corrupts mls:state.
      const writer = await acquireWriterLock(navigator.locks, `styx-mls:${ns}`);
      if (!writer.held) {
        // Fail closed: no Web Locks is an "unsupported browser" refusal, never a degraded writer.
        return { refused: writer.reason === 'unsupported' ? 'unsupported' : 'secondary' };
      }
      releaseWriter = writer.release;
      checkpoint();

      // M2 beta (test-profile build only): one exclusive `styx-m2:<vault db>` lock, taken on the
      // main thread before the vault worker can receive any M2 request. Any refusal stops the whole
      // entry, with the same screens as the writer lock, and releases the writer lock.
      const m2BetaGate = await loadM2BetaGate();
      checkpoint();
      if (m2BetaGate) {
        const acquired = await m2BetaGate.acquireM2BetaGate({ locks: navigator.locks });
        if (acquired.entered) gate = acquired;
        checkpoint();
        if (!acquired.entered) {
          return { refused: acquired.reason === m2BetaGate.M2_GATE_REFUSALS.UNSUPPORTED ? 'unsupported' : 'secondary' };
        }
      }

      chat = new StyxChat();
      const identity = await chat.init({
        password, alias: alias?.trim(), ns, ...transportOptions(getRelays()), autoStart: false,
      }); // throws on wrong password or unloadable MLS state (fail-closed)
      checkpoint();
      if (firstRun && alias && alias.trim() && chat.me?.alias !== alias.trim()) {
        await chat.setAlias(alias.trim());
        checkpoint();
      }

      let preferences = null;
      try {
        const pairingActive = await chat.hasActivePairing();
        settingsSession = await openVaultSettings({
          password, peerProfile: ns, pairingActive,
        });
        preferences = settingsSession?.initial?.preferences ?? null;
      } catch (e) {
        // Shadow migration is stage-gated. A vault failure must never deny access
        // to the unchanged legacy identity/settings path.
        await stopWorker();
        settingsSession = null;
        console.debug('vault unavailable; continuing with legacy product data', e?.code);
      }
      checkpoint();

      // This is the first operation permitted to touch the network. Identity
      // migration has either verified its vault readback or selected fallback.
      await chat.start();
      checkpoint();

      const started = chat;
      const refreshContacts = async (list) => {
        // The event may carry the full list (real lib) or fire as a bare signal
        // (mock) — in the latter case we re-fetch. Either way, never set undefined.
        if (Array.isArray(list)) setContacts(list);
        else setContacts(await started.listContacts());
      };
      // Each disposer is kept as soon as it exists, so a later failure can still undo it.
      subs.push(started.onMessage((msg) => {
        upsertMessage(msg);
        if (msg.direction === 'in') notifierRef.current.notifyIncoming();
      }));
      subs.push(started.onMessageState((id, state) => patchMessageState(id, state)));
      subs.push(started.onContactsChanged((list) => { refreshContacts(list); }));
      // A peer we authenticated joined our group, but adding them is the user's call.
      subs.push(started.onPairing?.(({ pubkey }) => setPendingPairings((prev) => (
        prev.some((p) => p.pubkey === pubkey) ? prev : [...prev, { pubkey }]
      ))));
      subs.push(started.onTyping((pubkey, isTyping) => {
        // Auto-expire: if no "stopped typing" arrives (lost, or a stale relayed
        // event), clear the indicator after a few seconds so it never sticks.
        clearTimeout(typingTimers.current[pubkey]);
        if (isTyping) {
          typingTimers.current[pubkey] = setTimeout(
            () => setTypingByContact((prev) => ({ ...prev, [pubkey]: false })),
            6000,
          );
        }
        setTypingByContact((prev) => ({ ...prev, [pubkey]: !!isTyping }));
      }));
      const contactList = await started.listContacts();
      checkpoint();

      // Success, and still current: publish what this attempt owns (the controller stays in
      // `activeRef`; a logout tears all of it down through `abort`).
      chatRef.current = started;
      subsRef.current = subs.filter(Boolean); // onPairing is absent on the mock
      vaultSettingsRef.current = settingsSession;
      setVaultPreferences(preferences);
      setMe(started.me || identity);
      setContacts(contactList);
      setReady(true);
      // Opt-in: if a bridge is configured and permission is already granted, register.
      enablePush();
      return { identity: started.me || identity };
    };

    let outcome;
    try {
      outcome = await run();
    } catch (e) {
      settleBody();
      if (activeRef.current === controller) activeRef.current = null;
      await abort();
      if (e === STALE) return undefined; // a logout or a newer attempt superseded this one
      throw e;
    }
    settleBody();
    if (outcome.refused) {
      if (activeRef.current === controller) activeRef.current = null;
      await abort();
      if (stale()) return undefined;
      if (outcome.refused === 'unsupported') setUnsupportedBrowser(true);
      else setSecondaryTab(true);
      return undefined;
    }
    return outcome.identity;
  }

  const stopVaultSettings = useCallback(async () => {
    const session = vaultSettingsRef.current;
    vaultSettingsRef.current = null;
    setVaultPreferences(null);
    await stopSession(session); // the same stop a teardown awaits before freeing the M2 lock
  }, []);

  const destroyVaultSettings = useCallback(async () => {
    await vaultSettingsRef.current?.destroy?.();
  }, []);

  // Retire the active attempt (in flight or published): its resources are revoked at once and its
  // locks freed in the act §3 order. Repeated calls are no-ops: one teardown owns the release.
  function retireActive() {
    const controller = activeRef.current;
    activeRef.current = null;
    subsRef.current = [];
    chatRef.current = null;
    vaultSettingsRef.current = null;
    if (!controller) return;
    const teardown = controller.abort();
    const previous = busyRef.current;
    const busy = Promise.allSettled([previous, teardown]);
    busyRef.current = busy;
    void busy.finally(() => { if (busyRef.current === busy) busyRef.current = null; });
  }

  const lock = useCallback(() => {
    attemptRef.current += 1; // an in-flight startup attempt is now stale
    // Release order (act §3): the M2 gate's `isHeld()` turns false at once, the held report is
    // withdrawn, the vault worker is stopped (terminated), and only then is the `styx-m2:` lock
    // freed; the legacy writer lock is freed last. Tab close kills everything together.
    retireActive();
    setReady(false);
    setMe(null);
    setContacts([]);
    setMessagesByContact({});
    setTypingByContact({});
    setNoMore({});
    setPendingPairings([]);
    setVaultPreferences(null);
  }, []);

  useEffect(() => () => lock(), [lock]); // teardown on unmount

  // --- actions ---
  const openConversation = useCallback(async (pubkey) => {
    const chat = chatRef.current;
    if (!chat) return;
    const initial = await chat.listMessages(pubkey, { limit: PAGE });
    setMessagesByContact((prev) => ({ ...prev, [pubkey]: initial }));
    setNoMore((prev) => ({ ...prev, [pubkey]: initial.length < PAGE }));
    const last = initial[initial.length - 1];
    if (last) chat.markRead(pubkey, last.id);
  }, []);

  const loadOlder = useCallback(async (pubkey) => {
    const chat = chatRef.current;
    if (!chat) return { added: 0 };
    const current = messagesByContact[pubkey] || [];
    const oldest = current[0];
    const older = await chat.listMessages(pubkey, { before: oldest?.ts, limit: PAGE });
    if (!older.length) {
      setNoMore((prev) => ({ ...prev, [pubkey]: true }));
      return { added: 0 };
    }
    setMessagesByContact((prev) => {
      const seen = new Set((prev[pubkey] || []).map((m) => m.id));
      const merged = [...older.filter((m) => !seen.has(m.id)), ...(prev[pubkey] || [])];
      return { ...prev, [pubkey]: merged };
    });
    return { added: older.length };
  }, [messagesByContact]);

  const sendText = useCallback(async (pubkey, text) => {
    const chat = chatRef.current;
    if (!chat) return;
    const msg = await chat.sendText(pubkey, text); // mock emits onMessage synchronously
    if (msg) upsertMessage(msg); // safety: dedup handles the double
  }, [upsertMessage]);

  const markRead = useCallback((pubkey, messageId) => {
    chatRef.current?.markRead(pubkey, messageId);
  }, []);

  const setTyping = useCallback((pubkey, isTyping) => {
    chatRef.current?.setTyping(pubkey, isTyping);
  }, []);

  // A welcome no longer adds a contact on its own: the user accepts it here.
  const acceptPending = useCallback(async (pubkey, alias) => {
    const chat = chatRef.current;
    if (!chat) return;
    await chat.confirmPairing({ contactPubkey: pubkey, alias });
    setPendingPairings((prev) => prev.filter((p) => p.pubkey !== pubkey));
    setContacts(await chat.listContacts());
  }, []);

  const dismissPending = useCallback((pubkey) => {
    setPendingPairings((prev) => prev.filter((p) => p.pubkey !== pubkey));
  }, []);

  /** The number to read aloud. '' when no session exists yet. */
  const safetyNumber = useCallback((pubkey) => {
    try { return chatRef.current?.safetyNumber(pubkey) || ''; } catch { return ''; }
  }, []);

  const setVerified = useCallback(async (pubkey, verified) => {
    const chat = chatRef.current;
    if (!chat?.setVerified) return;
    await chat.setVerified(pubkey, verified);
    setContacts(await chat.listContacts());
  }, []);

  const setAlias = useCallback(async (alias) => {
    const updated = await chatRef.current?.setAlias(alias);
    if (updated) setMe({ ...updated });
    return updated;
  }, []);

  const setThemePreference = useCallback(async (theme) => {
    const session = vaultSettingsRef.current;
    if (!session) return null;
    const result = await session.setTheme(theme);
    if (result.preferences) setVaultPreferences(result.preferences);
    return result;
  }, []);

  const dismissInstallHint = useCallback(async () => {
    const session = vaultSettingsRef.current;
    if (!session) return null;
    const result = await session.dismissInstallHint();
    if (result.preferences) setVaultPreferences(result.preferences);
    return result;
  }, []);

  // pairing passthroughs
  const pairing = {
    createQrInvite: (...a) => chatRef.current.createQrInvite(...a),
    acceptQrInvite: (...a) => chatRef.current.acceptQrInvite(...a),
    startRemotePairing: (...a) => chatRef.current.startRemotePairing(...a),
    joinRemotePairing: (...a) => chatRef.current.joinRemotePairing(...a),
    confirmPairing: (...a) => chatRef.current.confirmPairing(...a),
    removeContact: (...a) => chatRef.current.removeContact(...a),
  };

  return {
    ready, fatalError, secondaryTab, unsupportedBrowser, me, contacts, messagesByContact, typingByContact, noMore, pendingPairings,
    unlock, lock, openConversation, loadOlder, sendText, markRead, setTyping,
    setAlias, enablePush, acceptPending, dismissPending, safetyNumber, setVerified,
    vaultPreferences, setThemePreference, dismissInstallHint, stopVaultSettings, destroyVaultSettings,
    chatRef,
    ...pairing,
  };
}
