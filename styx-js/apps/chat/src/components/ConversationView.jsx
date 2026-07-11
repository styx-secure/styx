import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import MessageBubble from './MessageBubble.jsx';
import Composer from './Composer.jsx';
import { identicon } from '../lib/identicon.js';
import { dayLabel, sameDay } from '../lib/format.js';
import { ShieldCheck, Lock, Back } from './Icons.jsx';

export default function ConversationView({
  contact, messages, typing, noMore, isMobile,
  onBack, onSend, onSetTyping, onLoadOlder, onMarkRead, onRetry, onShowSafetyNumber,
}) {
  const scrollRef = useRef(null);
  const bottomRef = useRef(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const prevKeyRef = useRef(null);
  const pendingRestore = useRef(null);

  // Scroll to bottom when opening a conversation.
  useEffect(() => {
    if (!contact) return;
    if (prevKeyRef.current !== contact.pubkey) {
      prevKeyRef.current = contact.pubkey;
      requestAnimationFrame(() => bottomRef.current?.scrollIntoView({ block: 'end' }));
    }
  }, [contact, messages.length]);

  // Auto-scroll on new message if near bottom or it's outgoing.
  const lastLenRef = useRef(0);
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !messages.length) return;
    const last = messages[messages.length - 1];
    const grew = messages.length > lastLenRef.current;
    lastLenRef.current = messages.length;
    if (!grew) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 160;
    if (nearBottom || last.direction === 'out') {
      requestAnimationFrame(() => bottomRef.current?.scrollIntoView({ block: 'end' }));
    }
    if (last.direction === 'in') onMarkRead?.(last.id);
  }, [messages, onMarkRead]);

  // Preserve scroll position after prepending older messages.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (el && pendingRestore.current != null) {
      el.scrollTop = el.scrollHeight - pendingRestore.current;
      pendingRestore.current = null;
    }
  }, [messages]);

  const onScroll = async () => {
    const el = scrollRef.current;
    if (!el || loadingMore || noMore) return;
    if (el.scrollTop < 36) {
      setLoadingMore(true);
      pendingRestore.current = el.scrollHeight;
      await onLoadOlder();
      setLoadingMore(false);
    }
  };

  if (!contact) {
    return (
      <div className="cv-empty">
        <div className="card">
          <div className="shield"><ShieldCheck size={32} /></div>
          <h3>Seleziona una conversazione</h3>
          <p>Cifrato end-to-end con forward secrecy. I relay instradano i messaggi ma non possono leggerli.</p>
        </div>
      </div>
    );
  }

  let lastDay = null;
  return (
    <>
      <div className="cv-header">
        {isMobile && <button className="icon-btn" onClick={onBack} aria-label="Indietro"><Back size={20} /></button>}
        <img className="avatar" src={identicon(contact.pubkey)} alt="" />
        <div style={{ minWidth: 0 }}>
          <div className="alias">{contact.alias}</div>
          {/* No online/offline: the lib has no presence protocol, so any dot would be
              fabricated. The typing indicator is real (typing events) and stays. */}
          {typing && (
            <div className="status on">
              <span className="sx-dot" /><span className="sx-dot" /><span className="sx-dot" /> sta scrivendo…
            </div>
          )}
        </div>
        <div className="spacer" />
        <button
          className="e2e-badge"
          data-testid="safety-badge"
          title="Mostra il numero di sicurezza"
          onClick={() => onShowSafetyNumber?.(contact.pubkey)}
        >
          {contact.verified
            ? <><ShieldCheck size={13} /> Verificato</>
            : <><Lock size={13} /> E2E</>}
        </button>
      </div>

      <div className="cv-msgs sx-scroll" ref={scrollRef} onScroll={onScroll}>
        {loadingMore && <div className="loading-more">Carico messaggi precedenti…</div>}
        <div className="cv-banner"><Lock size={12} /> I messaggi sono cifrati end-to-end</div>
        {messages.map((m) => {
          const showSep = !lastDay || !sameDay(lastDay, m.ts);
          lastDay = m.ts;
          return (
            <div key={m.id} style={{ display: 'contents' }}>
              {showSep && <div className="daysep">{dayLabel(m.ts)}</div>}
              <MessageBubble msg={m} onRetry={onRetry} />
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      <Composer onSend={onSend} onTyping={onSetTyping} />
    </>
  );
}
