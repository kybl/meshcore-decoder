// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { MultipartPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class MultipartPayloadDecoder {
  // Multi-packet segment. The on-air segment layout is not part of the public
  // spec, so expose the raw bytes and flag it as partial rather than guess.
  static decode(
    payload: Uint8Array,
    options?: { includeSegments?: boolean; segmentOffset?: number }
  ): (MultipartPayload & { segments?: PayloadSegment[] }) | null {
    const raw = bytesToHex(payload);
    const result: MultipartPayload & { segments?: PayloadSegment[] } = {
      type: PayloadType.Multipart,
      version: PayloadVersion.Version1,
      isValid: true,
      partial: true,
      raw,
      length: payload.length,
    };
    if (options?.includeSegments && payload.length > 0) {
      const off = options.segmentOffset || 0;
      result.segments = [
        { name: 'Multipart Payload', description: `Multi-packet segment (${payload.length} bytes); on-air layout not part of the public spec`, startByte: off, endByte: off + payload.length - 1, value: raw },
      ];
    }
    return result;
  }
}
