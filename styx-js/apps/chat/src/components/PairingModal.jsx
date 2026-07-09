import { useEffect, useRef, useState } from 'react';
import { Close, QrFrame } from './Icons.jsx';
import { qrToSvg, startQrScanner } from '../lib/qr.js';

export default function PairingModal({ api, onClose, onAdded }) {
  const [tab, setTab] = useState('qr');
  return (
    <div className="overlay sx-overlay" onClick={onClose}>
      <div className="modal sx-sheet" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="modal-title">Nuovo contatto</span>
          <button className="icon-btn" onClick={onClose} aria-label="Chiudi"><Close size={18} /></button>
        </div>
        <div className="tabs">
          <button className={`tab${tab === 'qr' ? ' active' : ''}`} onClick={() => setTab('qr')}>Codice QR</button>
          <button className={`tab${tab === 'remote' ? ' active' : ''}`} onClick={() => setTab('remote')}>Pairing remoto</button>
        </div>
        {tab === 'qr'
          ? <QrTab api={api} onAdded={onAdded} />
          : <RemoteTab api={api} onAdded={onAdded} />}
      </div>
    </div>
  );
}

function QrTab({ api, onAdded }) {
  const [svg, setSvg] = useState('');
  const [paste, setPaste] = useState('');
  const [pending, setPending] = useState(null); // { contactPubkey }
  const [alias, setAlias] = useState('');
  const [scanning, setScanning] = useState(false);
  const videoRef = useRef(null);
  const stopRef = useRef(null);

  // Generate our own invite QR once on mount.
  useEffect(() => {
    let alive = true;
    api.createQrInvite().then(({ qr }) => qrToSvg(qr)).then((s) => { if (alive) setSvg(s); });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const accept = async (payload) => {
    const res = await api.acceptQrInvite(payload);
    setPending(res);
  };

  // Start/stop the camera scanner when `scanning` toggles (after the <video> mounts).
  useEffect(() => {
    if (!scanning) return undefined;
    let cancelled = false;
    startQrScanner(videoRef.current, (text) => {
      setScanning(false);
      accept(text);
    })
      .then((stop) => {
        if (cancelled) stop();
        else stopRef.current = stop;
      })
      .catch(() => {
        if (!cancelled) {
          setScanning(false);
          alert('Camera non disponibile: incolla l’invito qui sotto.');
        }
      });
    return () => { cancelled = true; stopRef.current?.(); stopRef.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanning]);

  const toggleScan = () => setScanning((s) => !s);

  const confirm = async () => {
    await api.confirmPairing({ contactPubkey: pending.contactPubkey, alias });
    onAdded(pending.contactPubkey);
  };

  if (pending) {
    return (
      <div className="section">
        <label className="label">Alias del contatto</label>
        <input className="field" style={{ marginTop: 8 }} value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="Come chiamarlo" autoFocus />
        <button className="btn btn-accent" style={{ width: '100%', marginTop: 12 }} onClick={confirm}>Aggiungi contatto</button>
      </div>
    );
  }

  return (
    <>
      <div className="section">
        <label className="label">Il tuo invito</label>
        <div className="qr-box" style={{ marginTop: 8 }} dangerouslySetInnerHTML={{ __html: svg }} />
      </div>
      <div className="section">
        <label className="label">Invito ricevuto</label>
        {scanning
          ? <video ref={videoRef} className="scan-video" style={{ marginTop: 8 }} muted playsInline />
          : <textarea className="field mono" style={{ height: 70, padding: 10, marginTop: 8 }} placeholder="styx://…" value={paste} onChange={(e) => setPaste(e.target.value)} />}
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          <button className="btn btn-ghost" style={{ flex: 1 }} onClick={toggleScan}><QrFrame size={18} /> {scanning ? 'Ferma' : 'Scansiona'}</button>
          <button className="btn btn-accent" style={{ flex: 1 }} disabled={!paste.trim()} onClick={() => accept(paste.trim())}>Accetta invito</button>
        </div>
      </div>
    </>
  );
}

function RemoteTab({ api, onAdded }) {
  const [mode, setMode] = useState('choose'); // choose | generate | join
  const [mnemonic, setMnemonic] = useState('');
  const [input, setInput] = useState('');
  const [code, setCode] = useState('');
  const [pubkey, setPubkey] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [alias, setAlias] = useState('');

  const generate = async () => {
    const { mnemonic: m } = await api.startRemotePairing();
    setMnemonic(m);
    setMode('generate');
  };
  const join = async () => {
    const { doubleCheckCode, contactPubkey } = await api.joinRemotePairing(input.trim());
    setCode(doubleCheckCode);
    setPubkey(contactPubkey);
    setMode('join');
  };
  const confirm = async () => {
    await api.confirmPairing({ contactPubkey: pubkey || undefined, alias });
    onAdded(pubkey);
  };

  if (mode === 'choose') {
    return (
      <div style={{ display: 'grid', gap: 10 }}>
        <button className="btn btn-accent" onClick={generate}>Genera 12 parole</button>
        <button className="btn btn-ghost" onClick={() => setMode('join')}>Inserisci 12 parole</button>
      </div>
    );
  }

  const AntiMitm = (
    <>
      <div className="code-card">
        <div className="code">{code || '••••••'}</div>
        <div className="hint">Confermate a voce che vedete lo stesso codice: se coincide, nessuno si è messo in mezzo (protezione MITM).</div>
      </div>
      <label className="check-row">
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
        I codici coincidono su entrambi i dispositivi
      </label>
      <input className="field" placeholder="Alias del contatto" value={alias} onChange={(e) => setAlias(e.target.value)} />
      <button className="btn btn-accent" style={{ width: '100%', marginTop: 10 }} disabled={!confirmed} onClick={confirm}>Conferma e aggiungi</button>
    </>
  );

  if (mode === 'generate') {
    return (
      <>
        <label className="label">Detta queste 12 parole all’altro dispositivo</label>
        <div className="mnemonic-grid">
          {mnemonic.split(' ').map((w, i) => (
            <div className="word mono" key={i}><span className="n">{i + 1}</span>{w}</div>
          ))}
        </div>
        <p style={{ fontSize: 12.5, color: 'var(--text-dim)' }}>Poi verificate insieme il codice a 6 cifre che comparirà sull’altro dispositivo.</p>
      </>
    );
  }

  // join
  return (
    <>
      {!code && (
        <>
          <label className="label">Inserisci le 12 parole ricevute</label>
          <textarea className="field mono" style={{ height: 80, padding: 10, marginTop: 8 }} value={input} onChange={(e) => setInput(e.target.value)} placeholder="parola1 parola2 …" />
          <button className="btn btn-accent" style={{ width: '100%', marginTop: 10 }} disabled={input.trim().split(/\s+/).length < 12} onClick={join}>Continua</button>
        </>
      )}
      {code && AntiMitm}
    </>
  );
}
