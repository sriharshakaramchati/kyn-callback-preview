import {
  fetchProviderConfigs,
  getProviderHashRequirementsFromSpec,
  verifyProof,
} from "@reclaimprotocol/js-sdk";
import { PROVIDER_ID, requireCondition } from "./constants.mjs";
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
  const urls = proofs.map((p) => {
    try {
      return JSON.parse(p.claimData.parameters).url;
    } catch {
      return "";
    }
  });
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
      requests.push(spec);
    }
  }
  requireCondition(requests.length > 0, 422, "PROVIDER_SCHEMA_CHANGED");
  const requirements = getProviderHashRequirementsFromSpec({ requests });
  const verified = await verifyProof(proofs, {
    ...requirements,
    hasNoPii: false,
  });
  requireCondition(verified.isVerified === true, 422, "INVALID_PROOF");
  return verified.data;
}
