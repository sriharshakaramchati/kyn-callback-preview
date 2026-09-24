import {
  createHash,
  createHmac,
  randomBytes,
  webcrypto,
  timingSafeEqual,
} from "node:crypto";
import { requireCondition } from "./constants.mjs";
const { subtle } = webcrypto;
export const digest = (value) =>
  createHash("sha256").update(value).digest("hex");
export const secret = () => randomBytes(32).toString("base64url");
export const ownerKey = (key, userId) =>
  createHmac("sha256", key)
    .update("mygate-user-v1\0" + userId)
    .digest("hex");
export function tokenMatches(token, expected) {
  return (
    typeof token === "string" &&
    token.length <= 200 &&
    typeof expected === "string" &&
    timingSafeEqual(Buffer.from(digest(token)), Buffer.from(expected))
  );
}
export async function validatePublicKey(jwk) {
  requireCondition(
    jwk &&
      jwk.kty === "RSA" &&
      typeof jwk.n === "string" &&
      jwk.e === "AQAB" &&
      !jwk.d &&
      !jwk.p &&
      !jwk.q &&
      !jwk.oth,
    400,
    "INVALID_KEY",
  );
  requireCondition(
    Buffer.from(jwk.n, "base64url").length === 384,
    400,
    "RSA_3072_REQUIRED",
  );
  const clean = {
    kty: "RSA",
    n: jwk.n,
    e: jwk.e,
    alg: "RSA-OAEP-256",
    ext: true,
  };
  await subtle.importKey(
    "jwk",
    clean,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["wrapKey"],
  );
  return clean;
}
export const fingerprint = (jwk) =>
  digest(JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n }));
export async function seal(dataset, jwk, sessionId) {
  const publicKey = await subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["wrapKey"],
  );
  const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
  ]);
  const iv = randomBytes(12),
    aad = Buffer.from(`community-map:v1:${sessionId}`);
  const bytes = Buffer.from(JSON.stringify(dataset));
  try {
    const ciphertext = await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      bytes,
    );
    const wrappedKey = await subtle.wrapKey("raw", key, publicKey, {
      name: "RSA-OAEP",
    });
    return {
      version: 1,
      sessionId,
      algorithm: "RSA-OAEP-256+A256GCM",
      iv: iv.toString("base64"),
      wrappedKey: Buffer.from(wrappedKey).toString("base64"),
      ciphertext: Buffer.from(ciphertext).toString("base64"),
    };
  } finally {
    bytes.fill(0);
  }
}
