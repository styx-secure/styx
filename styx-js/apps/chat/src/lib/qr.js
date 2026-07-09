// qr.js — real QR generation (qrcode) + camera scanning (@zxing/browser).
// Replaces the decorative mock QR: these produce scannable codes and read real ones.

import QRCode from 'qrcode';
import { BrowserQRCodeReader } from '@zxing/browser';

/**
 * Render `text` as a scannable QR into an SVG string.
 * @param {string} text
 * @returns {Promise<string>} inline SVG markup
 */
export async function qrToSvg(text) {
  return QRCode.toString(String(text ?? ''), {
    type: 'svg',
    margin: 1,
    errorCorrectionLevel: 'M',
    color: { dark: '#0b1f1a', light: '#ffffff' },
  });
}

/**
 * Start scanning QR codes from the camera into a <video> element.
 * @param {HTMLVideoElement} videoEl
 * @param {(text: string) => void} onResult called once with the decoded text
 * @returns {Promise<() => void>} a stop() function; rejects if camera is unavailable/denied
 */
export async function startQrScanner(videoEl, onResult) {
  const reader = new BrowserQRCodeReader();
  let stopped = false;
  const controls = await reader.decodeFromVideoDevice(undefined, videoEl, (result, _err, ctrl) => {
    if (stopped) return;
    if (result) {
      stopped = true;
      ctrl.stop();
      onResult(result.getText());
    }
  });
  return () => {
    stopped = true;
    try {
      controls.stop();
    } catch {
      /* already stopped */
    }
  };
}
