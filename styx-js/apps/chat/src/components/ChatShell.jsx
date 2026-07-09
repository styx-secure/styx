import ContactList from './ContactList.jsx';
import ConversationView from './ConversationView.jsx';

export default function ChatShell({
  me, contacts, activeKey, messages, typing, noMore,
  isMobile, mobileView,
  theme, onToggleTheme, onOpen, onBack, onNew, onSettings,
  onSend, onSetTyping, onLoadOlder, onMarkRead, onRetry,
}) {
  const activeContact = contacts.find((c) => c.pubkey === activeKey) || null;
  const showList = !isMobile || mobileView === 'list';
  const showConvo = !isMobile || mobileView === 'convo';

  return (
    <div className={`shell${isMobile ? ' mobile' : ''}`}>
      <aside className={`sidebar${showList ? '' : ' hide'}`}>
        <ContactList
          me={me} contacts={contacts} activeKey={activeKey}
          onOpen={onOpen} onNew={onNew} onSettings={onSettings}
          theme={theme} onToggleTheme={onToggleTheme}
        />
      </aside>
      <main className={`convo-pane${showConvo ? '' : ' hide'}`}>
        <ConversationView
          contact={activeContact}
          messages={messages}
          typing={typing}
          noMore={noMore}
          isMobile={isMobile}
          onBack={onBack}
          onSend={onSend}
          onSetTyping={onSetTyping}
          onLoadOlder={onLoadOlder}
          onMarkRead={onMarkRead}
          onRetry={onRetry}
        />
      </main>
    </div>
  );
}
