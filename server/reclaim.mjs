import { Worker } from "node:worker_threads";
import { SafeError, MAX_ACTIVE_VERIFICATIONS } from "./constants.mjs";
const activeWorkers = new Set();
function isolatedCall(data) {
  if (activeWorkers.size >= MAX_ACTIVE_VERIFICATIONS)
    return Promise.reject(new SafeError(503, "TRY_LATER"));
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      new URL("./reclaim-worker.mjs", import.meta.url),
      {
        workerData: data,
        stdout: true,
        stderr: true,
        resourceLimits: { maxOldGenerationSizeMb: 192 },
      },
    );
    activeWorkers.add(worker);
    // The SDK can print provider errors containing proof fields. These streams are never forwarded or retained.
    worker.stdout.resume();
    worker.stderr.resume();
    const timer = setTimeout(() => {
      void worker.terminate();
      reject(new SafeError(503, "VERIFICATION_UNAVAILABLE"));
    }, 90000);
    worker.once("message", (m) => {
      clearTimeout(timer);
      void worker.terminate();
      m.ok ? resolve(m.value) : reject(new SafeError(422, "INVALID_PROOF"));
    });
    worker.once("error", () => {
      clearTimeout(timer);
      reject(new SafeError(503, "VERIFICATION_UNAVAILABLE"));
    });
    worker.once("exit", (code) => {
      activeWorkers.delete(worker);
      clearTimeout(timer);
      if (code !== 0) reject(new SafeError(503, "VERIFICATION_UNAVAILABLE"));
    });
  });
}
export const reclaim = {
  initialize: (input) => isolatedCall({ operation: "init", ...input }),
  verify: (proofs, providerVersion) =>
    isolatedCall({ operation: "verify", proofs, providerVersion }),
};
