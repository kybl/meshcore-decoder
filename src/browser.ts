// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License
//
// Lean browser entry for bundling into a web app: packet decoding only.
// Excludes the CLI, auth-token helpers and the orlp/ed25519 WASM key-derivation
// blob, so the bundle depends only on the tiny @noble packages. GroupText
// channel decryption (public channel built in) and advert signature
// verification are included.

export { MeshCorePacketDecoder as MeshCoreDecoder } from './decoder/packet-decoder';
export {
  RouteType,
  PayloadType,
  PayloadVersion,
  DeviceRole,
  AdvertFlags,
  RequestType,
  ControlSubType,
} from './types/enums';

import * as EnumUtils from './utils/enum-names';
import * as HexUtils from './utils/hex';

export const Utils = {
  ...EnumUtils,
  ...HexUtils,
};
