// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { MeshCorePacketDecoder, PayloadType, AckPayload, PathPayload } from '../src';

const ACK_PACKET = '0D04B891647EBB40BA70';
const PATH_PACKET = '2105F464C77E411279399EFE1942B8A3FFA10F54D9C602FF2C8CF4';
const MULTIBYTE_ACK_PACKET = '0E41AABB11223344';
const MULTIBYTE_PATH_PACKET = '210042AABBCCDDEEFF00';

describe('Ack/Path Packet Decoding', () => {
  describe('Ack Packet', () => {
    it('should decode Ack packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(ACK_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Ack);
      expect(result.pathLength).toBe(4);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Ack) {
        const ackPayload = result.payload.decoded as AckPayload;
        
        expect(ackPayload.isValid).toBe(true);
        
        // Validate Ack payload structure with hex breakdown
        expect(ackPayload.checksum).toBe('BB40BA70'); // Bytes 0-3: CRC checksum as hex
      } else {
        fail('Ack payload not decoded correctly');
      }
    });

    it('should decode packet-level multi-byte paths correctly', () => {
      const result = MeshCorePacketDecoder.decode(MULTIBYTE_ACK_PACKET);

      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Ack);
      expect(result.pathLength).toBe(1);
      expect(result.pathHashSize).toBe(2);
      expect(result.path).toEqual(['AABB']);

      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Ack) {
        const ackPayload = result.payload.decoded as AckPayload;
        expect(ackPayload.isValid).toBe(true);
        expect(ackPayload.checksum).toBe('11223344');
      } else {
        fail('Ack payload not decoded correctly');
      }
    });
  });

  describe('Path Packet', () => {
    it('should decode Path packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(PATH_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Path);
      expect(result.pathLength).toBe(5); // 5 bytes in packet-level path
      expect(result.path).toEqual(['F4', '64', 'C7', '7E', '41']); // Packet-level path data
      expect(result.messageHash).toBe('A574CE1D');
      expect(result.totalBytes).toBe(27);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Path) {
        const pathPayload = result.payload.decoded as PathPayload;

        expect(pathPayload.isValid).toBe(true);

        // Path shares the encrypted envelope of Request/Response/TextMessage
        // (docs/payloads.md): dest(1) + src(1) + MAC(2) + ciphertext. The
        // returned path itself is INSIDE the ciphertext.
        expect(pathPayload.destinationHash).toBe('12');
        expect(pathPayload.sourceHash).toBe('79');
        expect(pathPayload.cipherMac).toBe('399E');
        expect(pathPayload.ciphertext).toBe('FE1942B8A3FFA10F54D9C602FF2C8CF4');
        expect(pathPayload.ciphertextLength).toBe(16);
      } else {
        fail('Path payload not decoded correctly');
      }
    });

    it('decodes the envelope of a multi-byte-path packet payload', () => {
      const result = MeshCorePacketDecoder.decode(MULTIBYTE_PATH_PACKET);

      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Path);
      expect(result.pathLength).toBe(0);
      expect(result.path).toBeNull();

      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Path) {
        const pathPayload = result.payload.decoded as PathPayload;

        expect(pathPayload.isValid).toBe(true);
        expect(pathPayload.destinationHash).toBe('42');
        expect(pathPayload.sourceHash).toBe('AA');
        expect(pathPayload.cipherMac).toBe('BBCC');
        expect(pathPayload.ciphertext).toBe('DDEEFF00');
      } else {
        fail('Path payload not decoded correctly');
      }
    });

    it('decodes a real-world Path packet as the encrypted envelope it is', () => {
      // Captured off the air. The old decoder read the destination hash (0xAE)
      // as a plaintext path-length byte (hash size 3, 46 hops) and failed with
      // "Path payload too short (need 140 bytes …)".
      const result = MeshCorePacketDecoder.decode('21020f36ae381fe3df7ab1689592abf42586dfbf1040beca');

      expect(result.isValid).toBe(true);
      expect(result.path).toEqual(['0F', '36']);

      const pathPayload = result.payload.decoded as PathPayload;
      expect(pathPayload.isValid).toBe(true);
      expect(pathPayload.errors).toBeUndefined();
      expect(pathPayload.destinationHash).toBe('AE');
      expect(pathPayload.sourceHash).toBe('38');
      expect(pathPayload.cipherMac).toBe('1FE3');
      expect(pathPayload.ciphertext).toBe('DF7AB1689592ABF42586DFBF1040BECA');
      expect(pathPayload.ciphertextLength).toBe(16);
    });

    it('flags a Path payload shorter than the 4-byte envelope', () => {
      const result = MeshCorePacketDecoder.decode('2100AABB');
      const pathPayload = result.payload.decoded as PathPayload;
      expect(pathPayload.isValid).toBe(false);
      expect(pathPayload.errors?.[0]).toMatch(/minimum 4 bytes/);
    });
  });
});
