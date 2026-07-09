import { identicon } from '../lib/identicon.js';
import { relTime } from '../lib/format.js';

export default function ContactRow({ contact, active, onClick }) {
  const { pubkey, alias, online, unread, lastPreview, lastTs } = contact;
  return (
    <div
      className={`crow${active ? ' active' : ''}`}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter') onClick(); }}
    >
      <div className="avatar-wrap">
        <img className="avatar" src={identicon(pubkey)} alt="" />
        <span className={`presence${online ? ' on' : ''}`} />
      </div>
      <div style={{ minWidth: 0 }}>
        <div className="row1">
          <span className="alias">{alias}</span>
          <span className="ts">{relTime(lastTs)}</span>
        </div>
        <div className="row2">
          <span className="preview">{lastPreview || ''}</span>
          {unread > 0 && <span className="badge sx-badge">{unread}</span>}
        </div>
      </div>
    </div>
  );
}
