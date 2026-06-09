// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License
//
// Ed25519 key derivation / signing / verification for the orlp/ed25519 key
// format (64-byte expanded private key = clamped scalar a || prefix), backed by
// the tiny @noble/ed25519 instead of the orlp WebAssembly build. Deriving the
// public key is the scalar multiplication A = a·B; signing follows RFC 8032 with
// the already-expanded key. Output is byte-for-byte identical to the previous
// WASM implementation, so it interoperates with MeshCore signatures unchanged.

import * as ed from '@noble/ed25519';
import { hexToBytes, bytesToHex } from '../utils/hex';
import { sha512 } from './lite-crypto';

const Point: any = (ed as any).ExtendedPoint ?? (ed as any).Point;
const L: bigint = ed.CURVE.n;
const mod = (ed as any).etc.mod as (a: bigint, b?: bigint) => bigint;
const concatBytes = (ed as any).etc.concatBytes as (...arrays: Uint8Array[]) => Uint8Array;

// @noble/ed25519 needs a SHA-512 implementation wired in for verify(); provide
// the bundled one (idempotent — the verifier module sets the same function).
(ed as any).etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(concatBytes(...m));
(ed as any).etc.sha512Async = async (...m: Uint8Array[]): Promise<Uint8Array> => sha512(concatBytes(...m));

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

function numberToBytesLE(n: bigint, len = 32): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

// Encoding of the identity point (0,1) — what scalar 0 maps to. @noble refuses
// to serialize the neutral element, so handle it explicitly (matches orlp).
const IDENTITY_POINT = (() => {
  const b = new Uint8Array(32);
  b[0] = 1;
  return b;
})();

// scalar·B as a 32-byte compressed point, accepting any scalar in [0, L).
function scalarMultBaseBytes(scalar: bigint): Uint8Array {
  if (scalar === 0n) return IDENTITY_POINT.slice();
  return Point.BASE.multiply(scalar).toRawBytes();
}

/**
 * Derive the Ed25519 public key from a 64-byte orlp/ed25519 private key.
 * The first 32 bytes are the clamped scalar a; the public key is A = a·B.
 */
export async function derivePublicKey(privateKeyHex: string): Promise<string> {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  if (privateKeyBytes.length !== 64) {
    throw new Error(`Invalid private key length: expected 64 bytes, got ${privateKeyBytes.length}`);
  }
  const a = mod(bytesToNumberLE(privateKeyBytes.subarray(0, 32)), L);
  return bytesToHex(scalarMultBaseBytes(a));
}

/**
 * Validate that a 64-byte private key derives to the given 32-byte public key.
 */
export async function validateKeyPair(privateKeyHex: string, expectedPublicKeyHex: string): Promise<boolean> {
  try {
    const privateKeyBytes = hexToBytes(privateKeyHex);
    const expectedPublicKeyBytes = hexToBytes(expectedPublicKeyHex);
    if (privateKeyBytes.length !== 64 || expectedPublicKeyBytes.length !== 32) {
      return false;
    }
    const derived = await derivePublicKey(privateKeyHex);
    return derived.toLowerCase() === expectedPublicKeyHex.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Sign a message with a 64-byte orlp/ed25519 expanded private key (RFC 8032).
 * Produces the standard 64-byte Ed25519 signature.
 */
export async function sign(messageHex: string, privateKeyHex: string, publicKeyHex: string): Promise<string> {
  const message = hexToBytes(messageHex);
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const publicKeyBytes = hexToBytes(publicKeyHex);
  if (privateKeyBytes.length !== 64) {
    throw new Error(`Invalid private key length: expected 64 bytes, got ${privateKeyBytes.length}`);
  }
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKeyBytes.length}`);
  }
  const a = mod(bytesToNumberLE(privateKeyBytes.subarray(0, 32)), L);
  const prefix = privateKeyBytes.subarray(32, 64);
  const r = mod(bytesToNumberLE(sha512(concatBytes(prefix, message))), L);
  const R = scalarMultBaseBytes(r);
  const k = mod(bytesToNumberLE(sha512(concatBytes(R, publicKeyBytes, message))), L);
  const S = mod(r + k * a, L);
  return bytesToHex(concatBytes(R, numberToBytesLE(S, 32)));
}

/**
 * Verify a standard Ed25519 signature.
 */
export async function verify(signatureHex: string, messageHex: string, publicKeyHex: string): Promise<boolean> {
  try {
    const signature = hexToBytes(signatureHex);
    const message = hexToBytes(messageHex);
    const publicKey = hexToBytes(publicKeyHex);
    if (signature.length !== 64 || publicKey.length !== 32) {
      return false;
    }
    return await ed.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
