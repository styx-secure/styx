import { useState } from 'react';
import { ShieldCheck } from './Icons.jsx';

/**
 * An authenticated peer joined our group after scanning our QR. They are not a
 * contact until the user says so — a valid welcome proves the scan, not consent.
 */
export default function PairingRequest({ request, onAccept, onDismiss }) {
  const [alias, setAlias] = useState('');
  const [busy, setBusy] = useState(false);

  const accept = async () => {
    setBusy(true);
    try { await onAccept(request.pubkey, alias.trim() || undefined); } finally { setBusy(false); }
  };

  return (
    <div className="overlay sx-overlay">
      <div className="modal sx-sheet" role="dialog" aria-modal="true" aria-label="Richiesta di contatto">
        <div className="modal-head">
          <span className="modal-title">Richiesta di contatto</span>
        </div>
        <div className="section">
          <div className="shield" style={{ marginBottom: 8 }}><ShieldCheck size={28} /></div>
          <p style={{ fontSize: 13.5 }}>
            Qualcuno ha scansionato il tuo invito e ha completato lo scambio di chiavi.
            Aggiungilo solo se ti aspettavi questa richiesta.
          </p>
          <div className="field mono" style={{ padding: 8, marginTop: 8, fontSize: 11, wordBreak: 'break-all' }}>
            {request.pubkey}
          </div>
          <label className="label" style={{ marginTop: 12 }}>Alias del contatto</label>
          <input
            className="field"
            style={{ marginTop: 8 }}
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            placeholder="Come chiamarlo (opzionale)"
            autoFocus
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button className="btn btn-ghost" style={{ flex: 1 }} disabled={busy} onClick={() => onDismiss(request.pubkey)}>
              Ignora
            </button>
            <button className="btn btn-accent" style={{ flex: 1 }} disabled={busy} onClick={accept}>
              {busy ? <><span className="spinner sm" /> Aggiungo…</> : 'Aggiungi contatto'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
