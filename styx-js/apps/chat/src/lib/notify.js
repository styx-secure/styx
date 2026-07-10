// notify.js — local (in-app) notifications. The pure `createNotifier` holds the
// decision logic (permission × page visibility × coalescing) with injected deps
// so it is unit-testable; `browserNotifier` wires the real browser globals.

const TITLE = 'Styx Chat';
const BODY = 'Hai un nuovo messaggio'; // generic on purpose — content stays E2E
const TAG = 'styx-new';

/**
 * @param {object} deps
 * @param {() => string} deps.getPermission current Notification permission
 * @param {() => boolean} deps.isPageVisible whether the app is in the foreground
 * @param {(n:{title:string,body:string,tag:string}) => void} deps.show raise it
 * @param {() => number} deps.now epoch millis
 * @param {number} [deps.coalesceMs] min gap between notifications
 */
export function createNotifier({ getPermission, isPageVisible, show, now, coalesceMs = 4000 }) {
  let lastShownAt = -Infinity;
  return {
    /** Decide + maybe show a notification for an inbound event. @returns {boolean} shown */
    notifyIncoming() {
      if (getPermission() !== 'granted') return false;
      if (isPageVisible()) return false; // foreground: the UI already shows it
      const t = now();
      if (t - lastShownAt < coalesceMs) return false; // coalesce bursts
      lastShownAt = t;
      show({ title: TITLE, body: BODY, tag: TAG });
      return true;
    },
  };
}

/** Notifier wired to the real browser globals. Safe no-op notifier if unsupported. */
export function browserNotifier() {
  const supported = typeof Notification !== 'undefined' && typeof document !== 'undefined';
  if (!supported) return { notifyIncoming: () => false };
  return createNotifier({
    getPermission: () => Notification.permission,
    isPageVisible: () => document.visibilityState === 'visible',
    show: ({ title, body, tag }) => { try { new Notification(title, { body, tag }); } catch { /* ignore */ } },
    now: () => Date.now(),
  });
}

/** Ask for notification permission (call on a user gesture). @returns {Promise<string>} */
export async function requestNotificationPermission() {
  if (typeof Notification === 'undefined') return 'denied';
  try { return await Notification.requestPermission(); } catch { return 'denied'; }
}
