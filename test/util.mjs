/** Convert a Uint8Array to a hex string. */
export function toHex(buf) {
  return Buffer.from(buf).toString('hex');
}
