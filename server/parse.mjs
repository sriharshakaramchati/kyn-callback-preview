import { createHash } from "node:crypto";
import { requireCondition } from "./constants.mjs";
const text = (o, keys, max = 160) => {
  for (const k of keys) {
    const v = o?.[k];
    if ((typeof v === "string" || typeof v === "number") && String(v).trim())
      return String(v).trim().slice(0, max);
  }
  return "";
};
const decode = (v) => {
  try {
    return typeof v === "string" ? JSON.parse(v) : v;
  } catch {
    return null;
  }
};
// Only SDK-verified context extractions from this provider are accepted. publicData and
// extractedParameterValues are deliberately never used: the SDK does not authenticate them.
export function parseResidents(proofs, trusted) {
  requireCondition(proofs.length === trusted.length, 422, "INVALID_PROOF");
  const accounts = [];
  const directories = [];
  for (let i = 0; i < proofs.length; i++) {
    let params;
    try {
      params = JSON.parse(proofs[i].claimData.parameters);
    } catch {
      requireCondition(false, 422, "INVALID_PROOF");
    }
    let url;
    try {
      url = new URL(params.url);
    } catch {
      requireCondition(false, 422, "INVALID_PROOF");
    }
    requireCondition(
      url.origin === "https://app.mygate.in",
      422,
      "WRONG_PROVIDER",
    );
    const fields = trusted[i].extractedParameters;
    if (url.pathname === "/user/v3/info" && params.method === "POST") {
      const userId = text(fields, ["userid"], 256),
        name = text(fields, ["account_name"]),
        society = text(fields, ["society_name"]);
      requireCondition(
        userId &&
          name &&
          society &&
          Array.isArray(decode(fields.account_flats)),
        422,
        "ACCOUNT_PROOF_REQUIRED",
      );
      accounts.push({ userId, name, society });
    } else if (
      url.pathname === "/society/v3/residentinfo" &&
      params.method === "GET"
    ) {
      const flats = decode(fields.resident_flats);
      requireCondition(
        Array.isArray(flats),
        422,
        "RESIDENT_SCHEMA_UNSUPPORTED",
      );
      directories.push({ userId: url.searchParams.get("userid"), flats });
    } else requireCondition(false, 422, "WRONG_PROVIDER");
  }
  requireCondition(
    accounts.length > 0 && directories.length > 0,
    422,
    "INCOMPLETE_PROOF",
  );
  const account = accounts[0];
  requireCondition(
    accounts.every(
      (a) => a.userId === account.userId && a.society === account.society,
    ),
    422,
    "MIXED_ACCOUNTS",
  );
  requireCondition(
    directories.every((d) => d.userId === account.userId),
    422,
    "MIXED_ACCOUNTS",
  );
  const residents = new Map();
  for (const directory of directories)
    for (const flat of directory.flats) {
      requireCondition(
        flat && typeof flat === "object" && !Array.isArray(flat),
        422,
        "RESIDENT_SCHEMA_UNSUPPORTED",
      );
      const unit = text(flat, [
        "flatname",
        "flatName",
        "flat_name",
        "flatnumber",
        "flatNumber",
        "fname",
        "unit",
        "unit_name",
        "unitName",
      ]);
      const block = text(flat, [
        "buildingname",
        "buildingName",
        "building_name",
        "bname",
        "blockname",
        "blockName",
        "block",
        "tower",
      ]);
      const members =
        flat.residents ?? flat.users ?? flat.members ?? flat.residentlist;
      // Flat-level person records are supported only when the same record has a unit.
      const people = Array.isArray(members)
        ? members
        : unit && text(flat, ["name", "residentname", "residentName"])
          ? [flat]
          : null;
      requireCondition(people !== null, 422, "RESIDENT_SCHEMA_UNSUPPORTED");
      for (const person of people) {
        const name = text(person, [
          "name",
          "residentname",
          "residentName",
          "fullName",
          "full_name",
          "rname",
        ]);
        requireCondition(name, 422, "RESIDENT_SCHEMA_UNSUPPORTED");
        const personUnit =
          text(person, ["flatname", "flatName", "unit"]) || unit;
        const personBlock =
          text(person, ["buildingname", "buildingName", "block"]) || block;
        const identity =
          text(person, ["userid", "userId", "residentid", "residentId", "rid", "r_user_id"], 256) ||
          name;
        const id = createHash("sha256")
          .update(
            JSON.stringify([account.userId, personBlock, personUnit, identity]),
          )
          .digest("hex")
          .slice(0, 24);
        residents.set(id, { id, name, unit: personUnit, block: personBlock });
        requireCondition(residents.size <= 25000, 422, "COMMUNITY_TOO_LARGE");
      }
    }
  requireCondition(residents.size > 0, 422, "NO_RESIDENTS");
  return { account, residents: [...residents.values()] };
}
