import { useEffect, useState } from 'react';
import { installHintKind, isIOSDevice, isStandalone } from '../lib/install-hint.js';

export default function InstallHint() {
  const [deferred, setDeferred] = useState(null);
  const [dismissed, setDismissed] = useState(() => {
    try { return localStorage.getItem('styx-install-dismissed') === '1'; } catch { return false; }
  });

  useEffect(() => {
    const onPrompt = (e) => { e.preventDefault(); setDeferred(e); };
    window.addEventListener('beforeinstallprompt', onPrompt);
    return () => window.removeEventListener('beforeinstallprompt', onPrompt);
  }, []);

  if (dismissed) return null;
  const kind = installHintKind({ standalone: isStandalone(), isIOS: isIOSDevice(), deferredPrompt: deferred });
  if (kind === 'none') return null;

  const dismiss = () => {
    setDismissed(true);
    try { localStorage.setItem('styx-install-dismissed', '1'); } catch { /* ignore */ }
  };

  const install = async () => {
    if (!deferred) return;
    deferred.prompt();
    try { await deferred.userChoice; } catch { /* ignore */ }
    setDeferred(null);
    dismiss();
  };

  const text = kind === 'ios'
    ? 'Installa Styx: tocca Condividi e poi "Aggiungi a Home" per abilitare le notifiche.'
    : 'Installa Styx come app per riceverne le notifiche.';

  return (
    <div className="install-hint sx-badge">
      <span style={{ flex: 1 }}>{text}</span>
      {kind === 'android' && (
        <button className="btn btn-accent" style={{ padding: '0 12px' }} onClick={install}>Installa</button>
      )}
      <button className="icon-btn" onClick={dismiss} aria-label="Chiudi">×</button>
    </div>
  );
}
