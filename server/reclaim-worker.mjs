import { parentPort, workerData } from "node:worker_threads";
import { ReclaimProofRequest } from "@reclaimprotocol/js-sdk";
import { PROVIDER_ID } from "./constants.mjs";
import { verifyMyGate } from "./verify.mjs";
import { verificationFailure } from './verification-errors.mjs';
try {
  if (workerData.operation === "init") {
    const { appId, appSecret, callbackUrl, sessionId, contextMessage } =
      workerData;
    const request = await ReclaimProofRequest.init(
      appId,
      appSecret,
      PROVIDER_ID,
      { log: false },
    );
    request.setAppCallbackUrl(callbackUrl, true);
    request.setContext(sessionId, contextMessage);
    const version = request.getProviderVersion();
    if (
      version.providerId !== PROVIDER_ID ||
      !/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(version.providerVersion)
    )
      throw new Error("Version unavailable");
    parentPort.postMessage({
      ok: true,
      value: {
        config: request.toJsonString(),
        reclaimId: request.getSessionId(),
        providerVersion: version.providerVersion,
      },
    });
  } else {
    const data = await verifyMyGate(
      workerData.proofs,
      workerData.providerVersion,
    );
    // Only signature- and provider-validated fields leave this worker. No raw SDK error is exposed.
    parentPort.postMessage({ ok: true, value: data });
  }
} catch (error) {
  parentPort.postMessage({ ok: false, code: verificationFailure(error).code });
}
