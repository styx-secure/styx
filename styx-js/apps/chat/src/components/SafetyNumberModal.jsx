import { useState } from 'react';
import { Close, ShieldCheck } from './Icons.jsx';

/**
 * The MITM ceremony: both sides read the same 60 digits aloud. They match only if
 * no one sits between them. Verification is a deliberate act, never automatic.
 */
export default function SafetyNumberModal({ contact, number, onVerify, onClose }) {
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);

  const verify = async () => {
    setBusy(true);
    try { await onVerify(contact.pubkey, true); onClose(); } finally { setBusy(false); }
  };

  const unverify = async () => {
    setBusy(true);
    try { await onVerify(contact.pubkey, false); } finally { setBusy(false); }
  };

  return (
    <div className="overlay sx-overlay" onClick={onClose}>
      <div className="modal sx-sheet" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="modal-title">Numero di sicurezza</span>
          <button className="icon-btn" onClick={onClose} aria-label="Chiudi"><Close size={18} /></button>
        </div>

        {!number ? (
          <div className="section">
            <p style={{ fontSize: 13.5 }}>
              Nessuna sessione cifrata con {contact.alias}: il numero sarà disponibile
              dopo il primo scambio di chiavi.
            </p>
          </div>
        ) : (
          <div className="section">
            <div className="code-card">
              <div className="code mono" data-testid="safety-number" style={{ fontSize: 15, lineHeight: 1.9, letterSpacing: '0.06em' }}>
                {number}
              </div>
              <div className="hint">
                Leggetelo a voce con {contact.alias}. Se i due numeri coincidono, nessuno
                si è messo in mezzo. Se differiscono, la conversazione è intercettata.
              </div>
            </div>

            {contact.verified ? (
              <>
                <p style={{ fontSize: 13, color: 'var(--text-dim)', marginTop: 10 }}>
                  <ShieldCheck size={14} /> Verificato
                  {contact.verifiedAt ? ` il ${new Date(contact.verifiedAt).toLocaleDateString()}` : ''}.
                </p>
                <button className="btn btn-ghost" style={{ width: '100%', marginTop: 10 }} disabled={busy} onClick={unverify}>
                  Rimuovi la verifica
                </button>
              </>
            ) : (
              <>
                <label className="check-row" style={{ marginTop: 10 }}>
                  <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                  I numeri coincidono su entrambi i dispositivi
                </label>
                <button className="btn btn-accent" style={{ width: '100%', marginTop: 10 }} disabled={!confirmed || busy} onClick={verify}>
                  {busy ? <><span className="spinner sm" /> Salvo…</> : 'Segna come verificato'}
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
