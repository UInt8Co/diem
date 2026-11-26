// The standalone runtime: DiemWeb's BridgeJS exports and nothing else.
import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';
import {diemClient} from './client.js';

/** Works in Window, DedicatedWorker and SharedWorker; no DOM or global callbacks. */
export async function createDiem(wasmURL = new URL('./diem.wasm', import.meta.url)) {
  const {exports} = await init({module: fetch(wasmURL), getImports: () => ({})});
  return diemClient(exports, wasmURL);
}
