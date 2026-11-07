// format.js — date/time helpers for the chat UI (Italian locale).
//
// The helpers format only a finite number that is a valid Date; anything else
// formats as '' (and sameDay is false), so a malformed record cannot make a
// render throw.

const pad = (n) => String(n).padStart(2, '0');

/** True for a timestamp the helpers can format. */
export function isTimestamp(ts) {
  return typeof ts === 'number' && Number.isFinite(ts) && Math.abs(ts) <= 8.64e15;
}

/** HH:MM */
export function hhmm(ts) {
  if (!isTimestamp(ts)) return '';
  const d = new Date(ts);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Relative timestamp for the contact list: "ora", "5m", "14:30", "lun", date. */
export function relTime(ts) {
  if (!ts || !isTimestamp(ts)) return '';
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
  if (!isTimestamp(a) || !isTimestamp(b)) return false;
  const x = new Date(a);
  const y = new Date(b);
  return x.getFullYear() === y.getFullYear() && x.getMonth() === y.getMonth() && x.getDate() === y.getDate();
}

/** Day-separator label: "Oggi" / "Ieri" / extended date. */
export function dayLabel(ts) {
  if (!isTimestamp(ts)) return '';
  const now = Date.now();
  if (sameDay(ts, now)) return 'Oggi';
  if (sameDay(ts, now - 86400000)) return 'Ieri';
  return new Date(ts).toLocaleDateString('it-IT', { day: 'numeric', month: 'long', year: 'numeric' });
}
