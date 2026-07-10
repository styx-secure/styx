// web-push-sender.js — thin wrapper over the `web-push` library. Sends an EMPTY,
// VAPID-signed push (the Web Push encryption still applies) whose only job is to
// wake the device; the content stays E2E and is never here.
import webpush from 'web-push';

export function makeSender({ subject, publicKey, privateKey }) {
  webpush.setVapidDetails(subject, publicKey, privateKey);
  return (subscription) => webpush.sendNotification(subscription, '', { TTL: 60 });
}
