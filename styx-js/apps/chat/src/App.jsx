import { useCallback, useEffect, useState } from 'react';
import { useStyxChat } from './hooks/useStyxChat.js';
import UnlockScreen from './components/UnlockScreen.jsx';
import ChatShell from './components/ChatShell.jsx';
import PairingModal from './components/PairingModal.jsx';
import PairingRequest from './components/PairingRequest.jsx';
import SafetyNumberModal from './components/SafetyNumberModal.jsx';
import SettingsPanel from './components/SettingsPanel.jsx';
import InstallHint from './components/InstallHint.jsx';
import { factoryReset } from './lib/factory-reset.js';

const MOBILE_BP = 820;

export default function App() {
  const chat = useStyxChat();
  const [activeKey, setActiveKey] = useState(null);
  const [modal, setModal] = useState(null); // 'new' | 'settings'
  const [safetyFor, setSafetyFor] = useState(null); // pubkey whose safety number is shown
  const [toast, setToast] = useState('');
  const [isMobile, setIsMobile] = useState(() => window.innerWidth < MOBILE_BP);
  const [mobileView, setMobileView] = useState('list');
  const [theme, setTheme] = useState(() => localStorage.getItem('styx-theme') || '');

  // Responsive.
  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < MOBILE_BP);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  // Theme: apply data-theme (empty = follow OS).
  useEffect(() => {
    if (theme) document.documentElement.setAttribute('data-theme', theme);
    else document.documentElement.removeAttribute('data-theme');
  }, [theme]);

  const toggleTheme = () => {
    const current = theme || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = current === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('styx-theme', next);
  };

  const showToast = useCallback((t) => {
    setToast(t);
    setTimeout(() => setToast(''), 1600);
  }, []);

  const openConversation = useCallback(async (pubkey) => {
    setActiveKey(pubkey);
    if (isMobile) setMobileView('convo');
    await chat.openConversation(pubkey);
  }, [chat, isMobile]);

  const onUnlock = useCallback(async (creds) => {
    await chat.unlock(creds);
  }, [chat]);

  const onLock = () => {
    chat.lock();
    setActiveKey(null);
    setModal(null);
    setSafetyFor(null);
    setMobileView('list');
  };

  const onReset = async () => {
    if (!window.confirm(
      'Reset totale: identità, messaggi, contatti e chiavi verranno eliminati da questo '
      + 'dispositivo. Operazione irreversibile. Procedere?',
    )) return;
    await factoryReset({ chat: chat.chatRef.current });
    // factoryReset reloads the page; nothing runs after it.
  };

  const removeContact = async (pubkey) => {
    await chat.removeContact(pubkey);
    if (pubkey === activeKey) { setActiveKey(null); if (isMobile) setMobileView('list'); }
  };

  const activeMessages = (activeKey && chat.messagesByContact[activeKey]) || [];
  const activeTyping = !!(activeKey && chat.typingByContact[activeKey]);
  const activeNoMore = !!(activeKey && chat.noMore[activeKey]);

  if (chat.fatalError) {
    return (
      <div className="fatal">
        <h1>Impossibile avviare Styx in sicurezza</h1>
        <p>{chat.fatalError.message}</p>
        <p>Ricarica la pagina. Se il problema persiste, la build potrebbe essere corrotta o incompleta.</p>
        <button onClick={() => location.reload()}>Ricarica</button>
      </div>
    );
  }

  if (chat.secondaryTab) {
    return (
      <div className="fatal">
        <h1>Styx è già aperto in un'altra scheda</h1>
        <p>Per proteggere lo stato cifrato, una sola scheda alla volta può scrivere. Usa la scheda già aperta, oppure chiudila e ricarica qui.</p>
        <button onClick={() => location.reload()}>Ricarica</button>
      </div>
    );
  }

  if (!chat.ready) return <UnlockScreen onUnlock={onUnlock} />;

  return (
    <>
      <ChatShell
        me={chat.me}
        contacts={chat.contacts}
        activeKey={activeKey}
        messages={activeMessages}
        typing={activeTyping}
        noMore={activeNoMore}
        isMobile={isMobile}
        mobileView={mobileView}
        theme={theme || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')}
        onToggleTheme={toggleTheme}
        onOpen={openConversation}
        onBack={() => setMobileView('list')}
        onNew={() => setModal('new')}
        onSettings={() => setModal('settings')}
        onSend={(text) => chat.sendText(activeKey, text)}
        onSetTyping={(t) => chat.setTyping(activeKey, t)}
        onLoadOlder={() => chat.loadOlder(activeKey)}
        onMarkRead={(id) => chat.markRead(activeKey, id)}
        onRetry={(m) => chat.sendText(activeKey, m.text)}
        onShowSafetyNumber={(pubkey) => setSafetyFor(pubkey)}
      />

      {/* A security decision: it precedes whatever else is open. */}
      {chat.pendingPairings.length > 0 && (
        <PairingRequest
          request={chat.pendingPairings[0]}
          onAccept={async (pubkey, alias) => {
            await chat.acceptPending(pubkey, alias);
            showToast('Contatto aggiunto ✓');
          }}
          onDismiss={chat.dismissPending}
        />
      )}

      {safetyFor && (
        <SafetyNumberModal
          contact={chat.contacts.find((c) => c.pubkey === safetyFor) || { pubkey: safetyFor, alias: safetyFor }}
          number={chat.safetyNumber(safetyFor)}
          onVerify={async (pubkey, verified) => {
            await chat.setVerified(pubkey, verified);
            showToast(verified ? 'Contatto verificato ✓' : 'Verifica rimossa');
          }}
          onClose={() => setSafetyFor(null)}
        />
      )}

      {modal === 'new' && (
        <PairingModal
          api={chat}
          onClose={() => setModal(null)}
          onAdded={(pubkey) => { setModal(null); if (pubkey) openConversation(pubkey); }}
        />
      )}
      {modal === 'settings' && (
        <SettingsPanel
          me={chat.me}
          contacts={chat.contacts}
          onClose={() => setModal(null)}
          onSetAlias={async (a) => { await chat.setAlias(a); showToast('Alias aggiornato ✓'); }}
          onRemoveContact={removeContact}
          onLock={onLock}
          onReset={onReset}
          onToast={showToast}
          onEnablePush={chat.enablePush}
        />
      )}

      {toast && <div className="toast sx-badge">{toast}</div>}

      <InstallHint />
    </>
  );
}
