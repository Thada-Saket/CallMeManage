export const ASCII_TEXT_GUIDANCE =
  "Use English keyboard characters only: A-Z, a-z, 0-9, spaces, and symbols (!@#$%^&* etc.).";

export const ASCII_TEXT_ERROR =
  `Unsupported character detected. ${ASCII_TEXT_GUIDANCE}`;

// Printable ASCII deliberately includes spaces, digits and punctuation, while
// excluding Thai and every other non-ASCII script/control character.
export function isPrintableAscii(value) {
  return /^[\x20-\x7E]*$/.test(String(value ?? ""));
}

export function unsupportedAsciiCharacters(value) {
  return [...new Set([...String(value ?? "")].filter((char) => !isPrintableAscii(char)))];
}
