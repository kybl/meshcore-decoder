// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { PathPayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class PathPayloadDecoder {
  static decode(payload: Uint8Array): PathPayload | null {
    try {
      // Per MeshCore docs/payloads.md ("Returned path, request, response, and
      // plain text message are all formatted in the same way") and
      // Mesh::createPathReturn / Mesh::onRecvPacket in the firmware:
      // - destination_hash (1 byte)
      // - source_hash (1 byte)
      // - cipher_mac (2 bytes)
      // - ciphertext (rest) — encrypted {path_len, path, extra_type, extra},
      //   readable only by the destination node (pairwise shared secret).
      //
      // The upstream decoder parsed the OUTER payload as if it began with the
      // plaintext path_len — i.e. it applied the decrypted body's layout to
      // the encrypted envelope, reading the destination hash as a path length.
      // Real-world Path packets then failed with bogus errors like
      // "Path payload too short (need 140 bytes …)".

      if (payload.length < 4) {
        return {
          type: PayloadType.Path,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Path payload too short (minimum 4 bytes: dest + source + MAC)'],
          destinationHash: '',
          sourceHash: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0
        };
      }

      return {
        type: PayloadType.Path,
        version: PayloadVersion.Version1,
        isValid: true,
        destinationHash: byteToHex(payload[0]),
        sourceHash: byteToHex(payload[1]),
        cipherMac: bytesToHex(payload.subarray(2, 4)),
        ciphertext: bytesToHex(payload.subarray(4)),
        ciphertextLength: payload.length - 4
      };
    } catch (error) {
      return {
        type: PayloadType.Path,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode path payload'],
        destinationHash: '',
        sourceHash: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0
      };
    }
  }
}
