import { useEffect, useState } from 'react';
import { ShieldCheck, Lock, Warning } from './Icons.jsx';
import { getStyxChat } from '../lib/styx-adapter.js';
import { peerNamespace } from '../lib/ns.js';

export default function UnlockScreen({ onUnlock }) {
  const [firstRun, setFirstRun] = useState(null); // null = loading
  const [alias, setAlias] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let alive = true;
    getStyxChat()
      .then((S) => S.hasIdentity({ ns: peerNamespace() }))
      .then((has) => { if (alive) setFirstRun(!has); })
      .catch(() => { if (alive) setFirstRun(true); });
    return () => { alive = false; };
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    if (busy) return;
    setError('');
    setBusy(true);
    try {
      await onUnlock({ password, alias, firstRun });
    } catch (err) {
      setError(err?.message || 'Errore di sblocco');
      setBusy(false);
    }
  };

  if (firstRun === null) {
    return (
      <div className="loading-screen">
        <span className="spinner" />
        <span>Carico Styx Chat…</span>
      </div>
    );
  }

  return (
    <div className="unlock">
      <div className="unlock-card">
        <div className="unlock-logo"><ShieldCheck size={30} /></div>
        <div className="unlock-title">Styx Chat</div>
        <p className="unlock-sub">Messaggistica sovrana, end-to-end</p>

        <form className="unlock-form" onSubmit={submit}>
          <div className="unlock-title" style={{ fontSize: 19, textAlign: 'center', margin: 0 }}>
            {firstRun ? 'Crea la tua identità' : 'Bentornato'}
          </div>
          <p className="unlock-sub" style={{ margin: '0 0 6px', textAlign: 'center' }}>
            {firstRun
              ? 'Scegli un alias e una password. La password cifra le tue chiavi solo su questo dispositivo — non lascia mai il tuo browser.'
              : 'Inserisci la password per decifrare le tue chiavi e sbloccare le conversazioni.'}
          </p>

          {firstRun && (
            <input className="field" placeholder="Alias pubblico" value={alias}
              onChange={(e) => setAlias(e.target.value)} autoFocus aria-label="Alias pubblico" />
          )}
          <input className="field" type="password" placeholder="Password locale" value={password}
            onChange={(e) => setPassword(e.target.value)} autoFocus={!firstRun} aria-label="Password locale" />

          {error && (
            <div className="error-box" role="alert"><Warning size={16} /> {error}</div>
          )}

          <button className="btn btn-accent" type="submit" disabled={busy || !password || (firstRun && !alias.trim())}>
            {busy
              ? <><span className="spinner sm" /> {firstRun ? 'Creazione…' : 'Sblocco…'}</>
              : firstRun ? 'Crea identità' : 'Sblocca'}
          </button>
        </form>

        <div className="claim">
          <Lock size={18} />
          <span>
            Nessun server, nessun account. Le chiavi restano cifrate qui, e ogni messaggio usa{' '}
            <b>forward secrecy</b>: il passato resta illeggibile anche se una chiave viene compromessa.
          </span>
        </div>
      </div>
    </div>
  );
}
