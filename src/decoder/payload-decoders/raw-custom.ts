// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { RawCustomPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class RawCustomPayloadDecoder {
  // Custom payload with application-defined (custom) encryption — opaque bytes.
  static decode(
    payload: Uint8Array,
    options?: { includeSegments?: boolean; segmentOffset?: number }
  ): (RawCustomPayload & { segments?: PayloadSegment[] }) | null {
    const raw = bytesToHex(payload);
    const result: RawCustomPayload & { segments?: PayloadSegment[] } = {
      type: PayloadType.RawCustom,
      version: PayloadVersion.Version1,
      isValid: true,
      encrypted: true,
      raw,
      length: payload.length,
    };
    if (options?.includeSegments && payload.length > 0) {
      const off = options.segmentOffset || 0;
      result.segments = [
        { name: 'RawCustom Payload', description: `Custom payload with application-defined encryption (${payload.length} bytes)`, startByte: off, endByte: off + payload.length - 1, value: raw },
      ];
    }
    return result;
  }
}
