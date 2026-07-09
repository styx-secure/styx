import { useState } from 'react';
import ContactRow from './ContactRow.jsx';
import { identicon } from '../lib/identicon.js';
import { Search, Plus, Sun, Moon, Gear } from './Icons.jsx';

export default function ContactList({ me, contacts, activeKey, onOpen, onNew, onSettings, theme, onToggleTheme }) {
  const [q, setQ] = useState('');
  const filtered = contacts.filter((c) => {
    if (!q) return true;
    const s = q.toLowerCase();
    return c.alias.toLowerCase().includes(s) || (c.lastPreview || '').toLowerCase().includes(s);
  });

  return (
    <>
      <div className="clist-header">
        <img className="me-avatar" src={identicon(me?.pubkey)} alt="" />
        <div style={{ minWidth: 0 }}>
          <div className="me-name">{me?.alias}</div>
          <div className="me-status">● identità sbloccata</div>
        </div>
        <div className="spacer" />
        <button className="icon-btn" onClick={onToggleTheme} aria-label="Cambia tema">
          {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button className="icon-btn" onClick={onSettings} aria-label="Impostazioni"><Gear size={18} /></button>
      </div>

      <div className="search-wrap">
        <span className="s-icon"><Search size={16} /></span>
        <input className="field" placeholder="Cerca contatti" value={q}
          onChange={(e) => setQ(e.target.value)} aria-label="Cerca contatti" />
      </div>

      <div className="clist sx-scroll">
        {filtered.map((c) => (
          <ContactRow key={c.pubkey} contact={c} active={c.pubkey === activeKey} onClick={() => onOpen(c.pubkey)} />
        ))}
        {!filtered.length && (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-faint)', fontSize: 13 }}>
            {contacts.length ? 'Nessun risultato' : 'Nessun contatto. Aggiungine uno.'}
          </div>
        )}
      </div>

      <div className="clist-footer">
        <button className="btn btn-accent" onClick={onNew}><Plus size={18} /> Nuovo contatto</button>
      </div>
    </>
  );
}
