import { hhmm } from '../lib/format.js';
import { Clock, Check, DoubleCheck } from './Icons.jsx';

function Ticks({ state }) {
  if (state === 'sending') return <span className="ticks"><Clock size={13} sw={2} /></span>;
  if (state === 'sent') return <span className="ticks"><Check size={13} sw={2.2} /></span>;
  if (state === 'delivered') return <span className="ticks"><DoubleCheck size={15} sw={2.2} /></span>;
  if (state === 'read') return <span className="ticks read"><DoubleCheck size={15} sw={2.2} /></span>;
  return null;
}

export default function MessageBubble({ msg, onRetry }) {
  const out = msg.direction === 'out';
  return (
    <div className={`bubble ${out ? 'out' : 'in'} sx-msg`}>
      <span>{msg.text}</span>
      <div className="meta">
        <span className="time">{hhmm(msg.ts)}</span>
        {out && msg.state === 'failed' ? (
          <button className="retry" onClick={() => onRetry?.(msg)}>! riprova</button>
        ) : out ? (
          <Ticks state={msg.state} />
        ) : null}
      </div>
    </div>
  );
}
