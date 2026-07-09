import { useRef, useState } from 'react';
import { Paperplane } from './Icons.jsx';

export default function Composer({ onSend, onTyping }) {
  const [text, setText] = useState('');
  const taRef = useRef(null);
  const typingTimer = useRef(null);

  const grow = () => {
    const ta = taRef.current;
    if (!ta) return;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 140) + 'px';
  };

  const signalTyping = () => {
    onTyping?.(true);
    clearTimeout(typingTimer.current);
    typingTimer.current = setTimeout(() => onTyping?.(false), 1500);
  };

  const send = () => {
    const t = text.trim();
    if (!t) return;
    onSend(t);
    setText('');
    clearTimeout(typingTimer.current);
    onTyping?.(false);
    requestAnimationFrame(() => { if (taRef.current) taRef.current.style.height = 'auto'; });
  };

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div className="composer">
      <div className="input-pill">
        <textarea
          ref={taRef}
          rows={1}
          value={text}
          placeholder="Scrivi un messaggio…"
          aria-label="Scrivi un messaggio"
          onChange={(e) => { setText(e.target.value); grow(); signalTyping(); }}
          onKeyDown={onKeyDown}
        />
      </div>
      <button className="send-btn" onClick={send} disabled={!text.trim()} aria-label="Invia">
        <Paperplane size={20} />
      </button>
    </div>
  );
}
