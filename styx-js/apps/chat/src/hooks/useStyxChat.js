// useStyxChat — encapsulates the single StyxChat instance and all subscriptions.
// Components read reactive state (me, contacts, messagesByContact, typingByContact)
// and call wrapped actions; they never touch the library directly.

import { useCallback, useEffect, useRef, useState } from 'react';
import { getStyxChat } from '../lib/styx-adapter.js';
import { acquireWriterLock } from '../lib/writer-lock.js';
import { peerNamespace } from '../lib/ns.js';
import { getRelays, getBridgeUrl, transportOptions } from '../lib/config.js';
import { browserNotifier } from '../lib/notify.js';
import { PushRegistrar } from 'styx-js';

const PAGE = 20;

// Delivery-state ordering. A receipt that arrives out of order (e.g. a delayed
// 'delivered' after 'read') must never downgrade the tick.
const STATE_RANK = { sending: 0, sent: 1, delivered: 2, read: 3, failed: 1 };
const advances = (from, to) => (STATE_RANK[to] ?? -1) > (STATE_RANK[from] ?? -1);

export function useStyxChat() {
  const chatRef = useRef(null);
  const subsRef = useRef([]);
  const lockReleaseRef = useRef(null);
  const typingTimers = useRef({});
  const notifierRef = useRef(null);
  if (!notifierRef.current) notifierRef.current = browserNotifier();

  const [ready, setReady] = useState(false);
  const [fatalError, setFatalError] = useState(null);
  const [secondaryTab, setSecondaryTab] = useState(false);
  const [me, setMe] = useState(null);
  const [contacts, setContacts] = useState([]);
  const [messagesByContact, setMessagesByContact] = useState({});
  const [typingByContact, setTypingByContact] = useState({});
  const [noMore, setNoMore] = useState({});
  const [pendingPairings, setPendingPairings] = useState([]);

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
    let StyxChat;
    try {
      StyxChat = await getStyxChat();
    } catch (e) {
      // A missing crypto module is a hard stop, not a wrong-password error: surface it
      // as a blocking state instead of letting the app fall through to fake data.
      if (e?.name === 'FatalCryptoError') { setFatalError(e); return; }
      throw e;
    }
    const ns = peerNamespace();

    // Become the single MLS writer for this profile, or refuse to start a writer.
    // A second tab that cannot get the lock must not construct a writable engine —
    // that is what corrupts mls:state.
    const { held, release } = await acquireWriterLock(navigator.locks, `styx-mls:${ns}`);
    if (!held) { setSecondaryTab(true); return; }
    lockReleaseRef.current = release;

    const chat = new StyxChat();
    const identity = await chat.init({
      password, alias: alias?.trim(), ns, ...transportOptions(getRelays()),
    }); // throws on wrong password
    if (firstRun && alias && alias.trim() && chat.me?.alias !== alias.trim()) {
      await chat.setAlias(alias.trim());
    }
    chatRef.current = chat;

    const refreshContacts = async (list) => {
      // The event may carry the full list (real lib) or fire as a bare signal
      // (mock) — in the latter case we re-fetch. Either way, never set undefined.
      if (Array.isArray(list)) setContacts(list);
      else setContacts(await chat.listContacts());
    };

    subsRef.current = [
      chat.onMessage((msg) => {
        upsertMessage(msg);
        if (msg.direction === 'in') notifierRef.current.notifyIncoming();
      }),
      chat.onMessageState((id, state) => patchMessageState(id, state)),
      chat.onContactsChanged((list) => { refreshContacts(list); }),
      // A peer we authenticated joined our group, but adding them is the user's call.
      chat.onPairing?.(({ pubkey }) => setPendingPairings((prev) => (
        prev.some((p) => p.pubkey === pubkey) ? prev : [...prev, { pubkey }]
      ))),
      chat.onTyping((pubkey, isTyping) => {
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
      }),
    ];

    subsRef.current = subsRef.current.filter(Boolean); // onPairing is absent on the mock

    setMe(chat.me || identity);
    setContacts(await chat.listContacts());
    setReady(true);
    // Opt-in: if a bridge is configured and permission is already granted, register.
    enablePush();
    return chat.me || identity;
  }, [upsertMessage, patchMessageState]);

  const lock = useCallback(() => {
    subsRef.current.forEach((off) => {
      try { off(); } catch { /* ignore */ }
    });
    subsRef.current = [];
    try { chatRef.current?.destroy?.(); } catch { /* ignore */ }
    chatRef.current = null;
    try { lockReleaseRef.current?.(); } catch { /* ignore */ }
    lockReleaseRef.current = null;
    setReady(false);
    setMe(null);
    setContacts([]);
    setMessagesByContact({});
    setTypingByContact({});
    setNoMore({});
    setPendingPairings([]);
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
    ready, fatalError, secondaryTab, me, contacts, messagesByContact, typingByContact, noMore, pendingPairings,
    unlock, lock, openConversation, loadOlder, sendText, markRead, setTyping,
    setAlias, enablePush, acceptPending, dismissPending, safetyNumber, setVerified,
    chatRef,
    ...pairing,
  };
}
