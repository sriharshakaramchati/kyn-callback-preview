import { randomUUID } from "node:crypto";
import { SafeError, requireCondition } from "./constants.mjs";
import {
  secret,
  digest,
  tokenMatches,
  validatePublicKey,
  seal,
} from "./crypto.mjs";
const clean = (value) =>
  typeof value === "string"
    ? value
        .normalize("NFKC")
        .replace(/[\u0000-\u001f<>"\\]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 120)
    : "";
export function researchQuery(input) {
  requireCondition(
    input &&
      typeof input === "object" &&
      !Array.isArray(input) &&
      Object.values(input).every(
        (v) => typeof v === "string" && v.length <= 120,
      ) &&
      Object.keys(input).every((k) =>
        ["name", "city", "community", "company", "university"].includes(k),
      ),
    400,
    "INVALID_RESEARCH_INPUT",
  );
  const name = clean(input.name);
  requireCondition(
    name.length >= 2 &&
      /\p{L}/u.test(name) &&
      !/@|https?:|\d{5}/i.test(Object.values(input).join(" ")),
    400,
    "INVALID_RESEARCH_INPUT",
  );
  // Never accept arbitrary URLs, credentials, contact emails, phone numbers or unit fields.
  return [
    `"${name}"`,
    ...["company", "university", "city", "community"]
      .map((k) => clean(input[k]))
      .filter(Boolean),
  ]
    .join(" ")
    .slice(0, 450);
}
export function tavilySearch({ apiKey, request = fetch }) {
  if (!apiKey) return null;
  return async (input) => {
    const query = researchQuery(input),
      headers = {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      };
    async function call(path, body) {
      let r;
      try {
        r = await request("https://api.tavily.com/" + path, {
          method: body ? "POST" : "GET",
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(25000),
          redirect: "error",
        });
      } catch {
        throw new SafeError(503, "RESEARCH_UNAVAILABLE");
      }
      if ([429, 432, 433].includes(r.status))
        throw new SafeError(429, "RESEARCH_LIMIT");
      if (!r.ok) throw new SafeError(503, "RESEARCH_UNAVAILABLE");
      try {
        return await r.json();
      } catch {
        throw new SafeError(503, "RESEARCH_UNAVAILABLE");
      }
    }
    const usage = await call("usage");
    const a = usage.account,
      k = usage.key;
    // Free accounts report an unset paygo limit as null. Also require a
    // provider-enforced key cap: no unlimited key can run this queue.
    requireCondition(
      a &&
        /^(researcher|free)$/i.test(a.current_plan) &&
        (a.paygo_limit === 0 || a.paygo_limit === null) &&
        a.paygo_usage === 0 &&
        Number.isFinite(k?.limit) && k.limit > 0 && k.limit <= 1000,
      503,
      "FREE_PLAN_REQUIRED",
    );
    requireCondition(
      Number.isFinite(a.plan_usage) &&
        Number.isFinite(a.plan_limit) &&
        a.plan_usage < Math.min(a.plan_limit, 1000) &&
        Number.isFinite(k.usage) && k.usage < k.limit,
      429,
      "RESEARCH_LIMIT",
    );
    const result = await call("search", {
      query,
      search_depth: "basic",
      auto_parameters: false,
      topic: "general",
      max_results: 6,
      include_answer: false,
      include_raw_content: false,
      include_images: false,
      include_usage: true,
    });
    // Return only evidence used by the matcher; do not retain provider tracking or raw HTML.
    return {
      results: (Array.isArray(result.results) ? result.results : [])
        .slice(0, 6)
        .map((r) => ({
          title: String(r.title || "").slice(0, 400),
          url: String(r.url || "").slice(0, 1000),
          content: String(r.content || "").slice(0, 2400),
        })),
    };
  };
}
export function researchService({ search, now = Date.now }) {
  const sessions = new Map();
  let active = 0;
  function prune() {
    for (const [id, s] of sessions)
      if (s.expiresAt < now()) sessions.delete(id);
  }
  function authorize(id, token) {
    prune();
    const s = sessions.get(id);
    requireCondition(
      s && tokenMatches(token, s.tokenHash),
      404,
      "RESEARCH_SESSION_EXPIRED",
    );
    return s;
  }
  return {
    available: !!search,
    async create(publicKey) {
      requireCondition(search, 503, "RESEARCH_NOT_CONFIGURED");
      prune();
      requireCondition(sessions.size < 1000, 503, "RESEARCH_BUSY");
      const key = await validatePublicKey(publicKey),
        id = randomUUID(),
        token = secret(),
        expiresAt = now() + 4 * 60 * 60 * 1000;
      sessions.set(id, {
        key,
        tokenHash: digest(token),
        expiresAt,
        nextAt: 0,
        results: new Map(),
        count: 0,
        busy: false,
      });
      return { id, token, expiresAt };
    },
    async run(id, token, body) {
      const s = authorize(id, token);
      requireCondition(
        body &&
          Object.keys(body).every((k) => ["requestId", "input"].includes(k)) &&
          /^[a-f0-9-]{36}$/.test(body.requestId || ""),
        400,
        "INVALID_RESEARCH_INPUT",
      );
      const query = researchQuery(body.input),
        hash = digest(query),
        old = s.results.get(body.requestId);
      if (old) {
        requireCondition(old.hash === hash, 409, "RESEARCH_REQUEST_CHANGED");
        return old.envelope;
      }
      requireCondition(
        !s.busy && active < 2 && s.nextAt <= now(),
        429,
        "RESEARCH_BUSY",
      );
      requireCondition(s.count < 1000, 429, "RESEARCH_LIMIT");
      s.busy = true;
      active++;
      s.count++;
      s.nextAt = now() + 1000;
      try {
        const evidence = await search(body.input);
        const envelope = await seal(
          { kind: "research", requestId: body.requestId, ...evidence },
          s.key,
          `${id}:${body.requestId}`,
        );
        s.results.set(body.requestId, { hash, envelope });
        // Bounded, encrypted replay buffer. No query, name or plaintext result is stored.
        if (s.results.size > 32)
          s.results.delete(s.results.keys().next().value);
        return envelope;
      } finally {
        s.busy = false;
        active--;
      }
    },
    remove(id, token) {
      authorize(id, token);
      sessions.delete(id);
    },
  };
}
