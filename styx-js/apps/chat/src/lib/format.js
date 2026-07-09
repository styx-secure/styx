// format.js — date/time helpers for the chat UI (Italian locale).

const pad = (n) => String(n).padStart(2, '0');

/** HH:MM */
export function hhmm(ts) {
  const d = new Date(ts);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Relative timestamp for the contact list: "ora", "5m", "14:30", "lun", date. */
export function relTime(ts) {
  if (!ts) return '';
  const now = Date.now();
  const diff = now - ts;
  const min = 60000;
  if (diff < min) return 'ora';
  if (diff < 60 * min) return `${Math.floor(diff / min)}m`;
  const d = new Date(ts);
  if (sameDay(ts, now)) return hhmm(ts);
  if (sameDay(ts, now - 86400000)) return 'ieri';
  if (diff < 7 * 86400000) return d.toLocaleDateString('it-IT', { weekday: 'short' });
  return d.toLocaleDateString('it-IT', { day: '2-digit', month: '2-digit' });
}

export function sameDay(a, b) {
  const x = new Date(a);
  const y = new Date(b);
  return x.getFullYear() === y.getFullYear() && x.getMonth() === y.getMonth() && x.getDate() === y.getDate();
}

/** Day-separator label: "Oggi" / "Ieri" / extended date. */
export function dayLabel(ts) {
  const now = Date.now();
  if (sameDay(ts, now)) return 'Oggi';
  if (sameDay(ts, now - 86400000)) return 'Ieri';
  return new Date(ts).toLocaleDateString('it-IT', { day: 'numeric', month: 'long', year: 'numeric' });
}
