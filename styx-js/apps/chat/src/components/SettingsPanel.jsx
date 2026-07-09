import { useState } from 'react';
import { identicon, shortKey } from '../lib/identicon.js';
import { Close, Copy, Trash, Lock } from './Icons.jsx';

export default function SettingsPanel({ me, contacts, onClose, onSetAlias, onRemoveContact, onLock, onReset, onToast }) {
  const [alias, setAlias] = useState(me?.alias || '');

  const copyKey = async () => {
    try {
      await navigator.clipboard.writeText(me.pubkey);
      onToast?.('Copiato ✓');
    } catch { /* ignore */ }
  };

  return (
    <div className="overlay sx-overlay" onClick={onClose}>
      <div className="modal sx-sheet" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="modal-title">Impostazioni</span>
          <button className="icon-btn" onClick={onClose} aria-label="Chiudi"><Close size={18} /></button>
        </div>

        <div className="section" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <img src={identicon(me?.pubkey)} alt="" style={{ width: 56, height: 56, borderRadius: 16 }} />
          <div style={{ flex: 1 }}>
            <label className="label">Alias</label>
            <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
              <input className="field" value={alias} onChange={(e) => setAlias(e.target.value)} />
              <button className="btn btn-accent" style={{ padding: '0 16px' }} onClick={() => onSetAlias(alias)}>Salva</button>
            </div>
          </div>
        </div>

        <div className="section">
          <label className="label">La tua chiave pubblica</label>
          <div className="copy-box" style={{ marginTop: 8 }}>
            <span>{me?.pubkey}</span>
            <span className="spacer" />
            <button className="icon-btn" onClick={copyKey} aria-label="Copia chiave"><Copy size={16} /></button>
          </div>
        </div>

        <div className="section">
          <div className="security-card">
            <Lock size={18} />
            <span>Ogni messaggio usa forward secrecy: le chiavi ruotano di continuo, quindi compromettere una chiave non rivela le conversazioni passate.</span>
          </div>
        </div>

        {contacts.length > 0 && (
          <div className="section">
            <label className="label">Contatti</label>
            <div style={{ marginTop: 6 }}>
              {contacts.map((c) => (
                <div className="contact-manage" key={c.pubkey}>
                  <img className="avatar" src={identicon(c.pubkey)} alt="" />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 650, fontSize: 14 }}>{c.alias}</div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>{shortKey(c.pubkey)}</div>
                  </div>
                  <span className="spacer" />
                  <button className="icon-btn" style={{ color: 'var(--danger)' }} onClick={() => onRemoveContact(c.pubkey)} aria-label="Rimuovi"><Trash size={16} /></button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="section" style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" style={{ flex: 1 }} onClick={onLock}>Blocca</button>
          <button className="btn btn-danger" style={{ flex: 1 }} onClick={onReset}>Reimposta identità</button>
        </div>
      </div>
    </div>
  );
}
