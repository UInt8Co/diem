// The standalone runtime's link worker. Applications build their own from
// device-link-session.js with their WASM's `init` and their protocol.
import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';
import {diemLinkProtocol} from './device-link-protocol.js';
import {linkInstanceFactory, serveLinkWorker} from './device-link-session.js';

export const createLinkInstance = linkInstanceFactory(init, diemLinkProtocol);
serveLinkWorker(createLinkInstance, diemLinkProtocol);
