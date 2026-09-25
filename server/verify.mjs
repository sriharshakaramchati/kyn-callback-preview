import {
  fetchProviderConfigs,
  getProviderHashRequirementsFromSpec,
  verifyProof,
} from "@reclaimprotocol/js-sdk";
import { PROVIDER_ID, requireCondition } from "./constants.mjs";
import { verificationFailure } from './verification-errors.mjs';
const ACCOUNT_URL = "https://app.mygate.in/user/v3/info";

// The 1.0.8 portal sends this POST body and includes it in the signed claim,
// while its published provider spec still declares bodySniff disabled. Accept
// only the portal's exact body shape and bind its userid to the verified reply.
function accountBodyUserId(raw) {
  requireCondition(typeof raw === "string" && raw.length <= 4096, 422, "PROVIDER_CONTENT_MISMATCH");
  let body;
  try { body = JSON.parse(raw); } catch { /* Rejected below. */ }
  requireCondition(
    body && !Array.isArray(body) &&
      typeof body.deviceid === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.deviceid) &&
      typeof body.userid === "string" && body.userid.length > 0 && body.userid.length <= 256,
    422, "PROVIDER_CONTENT_MISMATCH",
  );
  const expected = JSON.stringify({
    appversion: "7.37.0",
    carrier_name: "T-Mobile",
    deviceid: body.deviceid,
    model: "sdk_gphone64_arm64",
    osversion: 33,
    permissions: ["READ_CONTACTS", "NOTIFICATION", "CAMERA"],
    showallflats: "1",
    type: "N",
    userid: body.userid,
    version: "6",
  });
  requireCondition(raw === expected, 422, "PROVIDER_CONTENT_MISMATCH");
  return body.userid;
}
// SDK 5.8.2 hashes urlType=REGEX URLs literally. Resolve only URLs matching the
// trusted provider's regex, then let the SDK verify signatures AND all content hashes.
// No proof-supplied hash, publicData, hasNoPii bypass, or disabled validation is used.
export async function verifyMyGate(proofs, providerVersion) {
  const response = await fetchProviderConfigs(PROVIDER_ID, providerVersion, []);
  const configs = (response.providers || []).filter((c) => {
    const v = c.version;
    return (
      `${v?.major}.${v?.minor}.${v?.patch}${v?.prereleaseTag ? "-" + v.prereleaseTag + (v.prereleaseNumber != null ? "." + v.prereleaseNumber : "") : ""}` ===
      providerVersion
    );
  });
  requireCondition(configs.length === 1, 422, "PROVIDER_VERSION_UNAVAILABLE");
  const config = configs[0];
  const params = proofs.map((p) => {
    try {
      return JSON.parse(p.claimData.parameters);
    } catch {
      return null;
    }
  });
  const urls = params.map((p) => p?.url);
  const accountBodyUsers = new Map();
  const requests = [];
  for (const spec of [
    ...(config.requestData || []),
    ...(config.allowedInjectedRequestData || []),
  ]) {
    requireCondition(
      !spec.templateParams?.length,
      422,
      "PROVIDER_SCHEMA_CHANGED",
    );
    if (spec.urlType === "REGEX") {
      const regex = new RegExp(spec.url);
      const matches = [
        ...new Set(
          urls.filter(
            (u) => typeof u === "string" && u.length < 4096 && regex.test(u),
          ),
        ),
      ];
      requireCondition(
        matches.length > 0 || spec.required === false,
        422,
        "INCOMPLETE_PROOF",
      );
      for (const url of matches)
        requests.push({ ...spec, url, urlType: "CONSTANT" });
    } else {
      requireCondition(
        !spec.urlType || spec.urlType === "CONSTANT",
        422,
        "PROVIDER_SCHEMA_CHANGED",
      );
      if (
        providerVersion === "1.0.8" && spec.url === ACCOUNT_URL &&
        spec.method === "POST" && spec.bodySniff?.enabled === false
      ) {
        const indices = params.flatMap((p, i) => p?.url === ACCOUNT_URL ? [i] : []);
        requireCondition(indices.length === 1, 422, "PROVIDER_CONTENT_MISMATCH");
        const index = indices[0], body = params[index]?.body;
        if (body) {
          accountBodyUsers.set(index, accountBodyUserId(body));
          requests.push({ ...spec, bodySniff: { enabled: true, template: body } });
        } else requests.push(spec);
      } else requests.push(spec);
    }
  }
  requireCondition(requests.length > 0, 422, "PROVIDER_SCHEMA_CHANGED");
  const requirements = getProviderHashRequirementsFromSpec({ requests });
  const verified = await verifyProof(proofs, {
    ...requirements,
    hasNoPii: false,
  });
  if (verified.isVerified !== true) throw verificationFailure(verified.error);
  for (const [index, userId] of accountBodyUsers)
    requireCondition(verified.data[index]?.extractedParameters?.userid === userId,
      422, "PROVIDER_CONTENT_MISMATCH");
  return verified.data;
}
