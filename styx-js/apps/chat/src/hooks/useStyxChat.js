// useStyxChat — encapsulates the single StyxChat instance and all subscriptions.
// Components read reactive state (me, contacts, messagesByContact, typingByContact)
// and call wrapped actions; they never touch the library directly.

import { useCallback, useEffect, useRef, useState } from 'react';
import { getStyxChat } from '../lib/styx-adapter.js';
import { peerNamespace } from '../lib/ns.js';
import { getRelays } from '../lib/config.js';

const PAGE = 20;

export function useStyxChat() {
  const chatRef = useRef(null);
  const subsRef = useRef([]);

  const [ready, setReady] = useState(false);
  const [me, setMe] = useState(null);
  const [contacts, setContacts] = useState([]);
  const [messagesByContact, setMessagesByContact] = useState({});
  const [typingByContact, setTypingByContact] = useState({});
  const [noMore, setNoMore] = useState({});

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
          if (m.id === messageId) {
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
  const unlock = useCallback(async ({ password, alias, firstRun }) => {
    const StyxChat = await getStyxChat();
    const chat = new StyxChat();
    const ns = peerNamespace();
    const identity = await chat.init({ password, alias: alias?.trim(), ns, relays: getRelays() }); // throws on wrong password
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
      chat.onMessage((msg) => upsertMessage(msg)),
      chat.onMessageState((id, state) => patchMessageState(id, state)),
      chat.onContactsChanged((list) => { refreshContacts(list); }),
      chat.onTyping((pubkey, isTyping) =>
        setTypingByContact((prev) => ({ ...prev, [pubkey]: !!isTyping })),
      ),
    ];

    setMe(chat.me || identity);
    setContacts(await chat.listContacts());
    setReady(true);
    return chat.me || identity;
  }, [upsertMessage, patchMessageState]);

  const lock = useCallback(() => {
    subsRef.current.forEach((off) => {
      try { off(); } catch { /* ignore */ }
    });
    subsRef.current = [];
    try { chatRef.current?.destroy?.(); } catch { /* ignore */ }
    chatRef.current = null;
    setReady(false);
    setMe(null);
    setContacts([]);
    setMessagesByContact({});
    setTypingByContact({});
    setNoMore({});
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
    ready, me, contacts, messagesByContact, typingByContact, noMore,
    unlock, lock, openConversation, loadOlder, sendText, markRead, setTyping,
    setAlias, ...pairing,
  };
}
