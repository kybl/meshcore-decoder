// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License
//
// Lightweight crypto primitives backed by the tiny, audited @noble packages.
// This replaces the previous full crypto-js dependency (which bundled every
// cipher/hash and dominated build size) with only what the decoder needs:
// SHA-256 / SHA-512 / HMAC-SHA256 and AES-ECB (no padding).

import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2';
import { hmac as nobleHmac } from '@noble/hashes/hmac';
import { ecb } from '@noble/ciphers/aes';

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function sha512(data: Uint8Array): Uint8Array {
  return nobleSha512(data);
}

export function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return nobleHmac(nobleSha256, key, msg);
}

/** AES-ECB decrypt with no padding. Key length selects AES-128/192/256. */
export function aesEcbDecryptNoPad(key: Uint8Array, data: Uint8Array): Uint8Array {
  return ecb(key, { disablePadding: true }).decrypt(data);
}
