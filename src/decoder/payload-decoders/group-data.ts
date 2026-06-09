// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { GroupDataPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class GroupDataPayloadDecoder {
  // channel_hash(1) + cipher_mac(2) + encrypted data (data_type/len/data live encrypted)
  static decode(
    payload: Uint8Array,
    options?: { includeSegments?: boolean; segmentOffset?: number }
  ): (GroupDataPayload & { segments?: PayloadSegment[] }) | null {
    try {
      if (payload.length < 3) {
        return {
          type: PayloadType.GroupData,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['GroupData payload too short (minimum 3 bytes: channel_hash + MAC)'],
          channelHash: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0,
        };
      }
      const channelHash = byteToHex(payload[0]);
      const cipherMac = bytesToHex(payload.subarray(1, 3));
      const ciphertext = bytesToHex(payload.subarray(3));
      const result: GroupDataPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.GroupData,
        version: PayloadVersion.Version1,
        isValid: true,
        channelHash,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 3,
      };
      if (options?.includeSegments) {
        const off = options.segmentOffset || 0;
        result.segments = [
          { name: 'Channel Hash', description: "First byte of SHA256 of channel's shared key", startByte: off, endByte: off, value: channelHash },
          { name: 'Cipher MAC', description: 'MAC for encrypted data', startByte: off + 1, endByte: off + 2, value: cipherMac },
          { name: 'Ciphertext', description: 'Encrypted group datagram (data_type + length + data)', startByte: off + 3, endByte: off + payload.length - 1, value: ciphertext },
        ];
      }
      return result;
    } catch (error) {
      return {
        type: PayloadType.GroupData,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode GroupData payload'],
        channelHash: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0,
      };
    }
  }
}
