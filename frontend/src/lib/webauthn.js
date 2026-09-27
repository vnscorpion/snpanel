// The browser side of passkeys.
//
// The panel sends WebAuthn options as JSON, with every binary field in
// base64url; `navigator.credentials` wants ArrayBuffers in and gives
// ArrayBuffers back. These turn one into the other in both directions, and
// nothing else - the checking is the server's (snpanel_core::crypto::webauthn).

function fromBase64url(text) {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function toBase64url(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const withIds = (list) => (list || []).map((c) => ({ ...c, id: fromBase64url(c.id) }));

// A passkey can only be made or used in a secure context, by a browser that
// has the API at all.
export function passkeysSupported() {
  return typeof window !== 'undefined' && window.isSecureContext && !!window.PublicKeyCredential;
}

// navigator.credentials.create, from the panel's options to what it checks.
export async function createPasskey(publicKey, signal) {
  const credential = await navigator.credentials.create({
    publicKey: {
      ...publicKey,
      challenge: fromBase64url(publicKey.challenge),
      user: { ...publicKey.user, id: fromBase64url(publicKey.user.id) },
      excludeCredentials: withIds(publicKey.excludeCredentials),
    },
    signal,
  });
  return {
    id: credential.id,
    type: credential.type,
    response: {
      clientDataJSON: toBase64url(credential.response.clientDataJSON),
      attestationObject: toBase64url(credential.response.attestationObject),
    },
  };
}

// navigator.credentials.get, likewise.
export async function getPasskeyAssertion(publicKey, signal) {
  const credential = await navigator.credentials.get({
    publicKey: {
      ...publicKey,
      challenge: fromBase64url(publicKey.challenge),
      allowCredentials: withIds(publicKey.allowCredentials),
    },
    signal,
  });
  return {
    id: credential.id,
    type: credential.type,
    response: {
      clientDataJSON: toBase64url(credential.response.clientDataJSON),
      authenticatorData: toBase64url(credential.response.authenticatorData),
      signature: toBase64url(credential.response.signature),
    },
  };
}
