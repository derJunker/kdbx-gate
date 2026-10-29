// QR codes in the browser: drawing an otpauth:// link on a canvas so an authenticator app can scan it.
import { encodeQR } from 'qr';

/** Draws `text` as a QR code (dark on white, whatever the colour scheme) with `scale` pixels per module. */
export function drawQr(canvas, text, scale = 6) {
  const grid = encodeQR(text, 'raw', { ecc: 'medium', border: 4 });
  canvas.width = grid.length * scale;
  canvas.height = grid.length * scale;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000000';
  grid.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) ctx.fillRect(x * scale, y * scale, scale, scale);
    }),
  );
}
