// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { DecryptionResult } from '../types/crypto';
import { hexToBytes } from '../utils/hex';
import { sha256, hmacSha256, aesEcbDecryptNoPad } from './lite-crypto';

export class ChannelCrypto {
  /**
   * Decrypt GroupText message using MeshCore algorithm:
   * - HMAC-SHA256 verification with 2-byte MAC (key padded to 32 bytes)
   * - AES ECB decryption (no padding), plaintext = timestamp(4) + flags(1) + text
   */
  static decryptGroupTextMessage(
    ciphertext: string,
    cipherMac: string,
    channelKey: string
  ): DecryptionResult {
    try {
      const keyBytes = hexToBytes(channelKey);
      const macBytes = hexToBytes(cipherMac);
      const ciphertextBytes = hexToBytes(ciphertext);

      // MeshCore uses a 32-byte channel secret (key zero-padded) as the HMAC key
      const channelSecret = new Uint8Array(32);
      channelSecret.set(keyBytes.subarray(0, 32), 0);

      // Step 1: verify the first 2 bytes of HMAC-SHA256(secret, ciphertext)
      const calculatedMac = hmacSha256(channelSecret, ciphertextBytes);
      if (calculatedMac[0] !== macBytes[0] || calculatedMac[1] !== macBytes[1]) {
        return { success: false, error: 'MAC verification failed' };
      }

      // Step 2: AES-ECB decrypt (no padding) over whole 16-byte blocks
      const blockLen = ciphertextBytes.length - (ciphertextBytes.length % 16);
      if (blockLen === 0) {
        return { success: false, error: 'Decrypted content too short' };
      }
      const decryptedBytes = aesEcbDecryptNoPad(keyBytes, ciphertextBytes.subarray(0, blockLen));

      if (decryptedBytes.length < 5) {
        return { success: false, error: 'Decrypted content too short' };
      }

      // parse MeshCore format: timestamp(4 LE) + flags(1) + message_text
      const timestamp =
        decryptedBytes[0] |
        (decryptedBytes[1] << 8) |
        (decryptedBytes[2] << 16) |
        (decryptedBytes[3] << 24);

      const flagsAndAttempt = decryptedBytes[4];

      const messageBytes = decryptedBytes.slice(5);
      let messageText = new TextDecoder('utf-8').decode(messageBytes);

      // remove null terminator / trailing padding if present
      const nullIndex = messageText.indexOf('\0');
      if (nullIndex >= 0) {
        messageText = messageText.substring(0, nullIndex);
      }

      // parse sender and message (format: "sender: message")
      const colonIndex = messageText.indexOf(': ');
      let sender: string | undefined;
      let content: string;
      if (colonIndex > 0 && colonIndex < 50) {
        const potentialSender = messageText.substring(0, colonIndex);
        if (!/[:[\]]/.test(potentialSender)) {
          sender = potentialSender;
          content = messageText.substring(colonIndex + 2);
        } else {
          content = messageText;
        }
      } else {
        content = messageText;
      }

      return {
        success: true,
        data: { timestamp, flags: flagsAndAttempt, sender, message: content },
      };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Decryption failed' };
    }
  }

  /**
   * Calculate MeshCore channel hash from a secret key.
   * Returns the first byte of SHA256(secret) as a lowercase hex string.
   */
  static calculateChannelHash(secretKeyHex: string): string {
    const hash = sha256(hexToBytes(secretKeyHex));
    return hash[0].toString(16).padStart(2, '0');
  }
}
