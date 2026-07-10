import { useCallback, useEffect, useState } from 'react';
import { useStyxChat } from './hooks/useStyxChat.js';
import UnlockScreen from './components/UnlockScreen.jsx';
import ChatShell from './components/ChatShell.jsx';
import PairingModal from './components/PairingModal.jsx';
import SettingsPanel from './components/SettingsPanel.jsx';
import InstallHint from './components/InstallHint.jsx';
import { getStyxChat } from './lib/styx-adapter.js';

const MOBILE_BP = 820;

export default function App() {
  const chat = useStyxChat();
  const [activeKey, setActiveKey] = useState(null);
  const [modal, setModal] = useState(null); // 'new' | 'settings'
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

  const onLock = () => { chat.lock(); setActiveKey(null); setModal(null); setMobileView('list'); };

  const onReset = async () => {
    const S = await getStyxChat();
    if (S.hasIdentity) {
      // Best-effort local identity wipe for the mock/demo.
      try { localStorage.removeItem('styx-identity'); } catch { /* ignore */ }
    }
    onLock();
  };

  const removeContact = async (pubkey) => {
    await chat.removeContact(pubkey);
    if (pubkey === activeKey) { setActiveKey(null); if (isMobile) setMobileView('list'); }
  };

  const activeMessages = (activeKey && chat.messagesByContact[activeKey]) || [];
  const activeTyping = !!(activeKey && chat.typingByContact[activeKey]);
  const activeNoMore = !!(activeKey && chat.noMore[activeKey]);

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
      />

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
        />
      )}

      {toast && <div className="toast sx-badge">{toast}</div>}

      <InstallHint />
    </>
  );
}
