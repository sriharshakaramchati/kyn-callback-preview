import {researchService} from './research.mjs';
import express from "express";
import {callbackDiagnostics} from "./callback-diagnostics.mjs";
import { randomUUID } from "node:crypto";
import {
  BODY_LIMIT,
  SESSION_TTL,
  RESULT_TTL,
  MAX_PROOFS,
  MAX_ACTIVE_VERIFICATIONS,
  SafeError,
  requireCondition,
} from "./constants.mjs";
import {
  digest,
  secret,
  ownerKey,
  tokenMatches,
  validatePublicKey,
  fingerprint,
  seal,
} from "./crypto.mjs";
import { parseResidents } from "./parse.mjs";
export function createApp({
  store,
  reclaim,
  appId,
  appSecret,
  ownerSecret,
  publicOrigin,
  allowedOrigins,
  now = Date.now,
  authenticateGoogle,
  searchPublicWeb,
  recordCallback = () => {},
}) {
  const app = express();
  app.disable("x-powered-by");
  requireCondition(ownerSecret?.length >= 32, 500, "SERVER_CONFIGURATION");
  let activeVerifications = 0;
  const buckets = new Map();
  app.use((req, res, next) => {
    res.set({
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin))
      res.set({
        "Access-Control-Allow-Origin": origin,
        Vary: "Origin",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      });
    // Reclaim callbacks can originate outside the static site's origin. Their authorization is cryptographic.
    if (
      !req.path.startsWith("/v1/callback/") &&
      req.path !== "/health" &&
      origin &&
      !allowedOrigins.includes(origin)
    )
      return res.status(403).json({ error: "ORIGIN_NOT_ALLOWED" });
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
  app.get("/health", (_req, res) => res.json({ ok: true }));
  const rateLimit = (req, res, next) => {
    const t = now(),
      key = req.socket.remoteAddress || "unknown";
    for (const [k, v] of buckets) if (v.until < t) buckets.delete(k);
    const bucket = buckets.get(key) || { count: 0, until: t + 60000 };
    bucket.count++;
    buckets.set(key, bucket);
    if (bucket.count > 12) return res.status(429).json({ error: "TRY_LATER" });
    next();
  };
  const research=researchService({search:searchPublicWeb,now});
  app.get('/v1/research/status',(_req,res)=>res.json({available:research.available,provider:'Tavily',monthlySearchLimit:1000}));
  const researchOrigin=(req,_res,next)=>{requireCondition(allowedOrigins.includes(req.headers.origin),403,'ORIGIN_NOT_ALLOWED');next();};
  app.post('/v1/research/sessions',researchOrigin,rateLimit,express.json({limit:'8kb',strict:true,inflate:false}),async(req,res)=>{
    requireCondition(req.body&&Object.keys(req.body).length===1,400,'INVALID_RESEARCH_INPUT');
    res.status(201).json(await research.create(req.body.publicKey));
  });
  app.post('/v1/research/sessions/:id',researchOrigin,express.json({limit:'3kb',strict:true,inflate:false}),async(req,res)=>{
    res.json(await research.run(req.params.id,req.headers.authorization?.replace(/^Bearer /,''),req.body));
  });
  app.delete('/v1/research/sessions/:id',researchOrigin,(req,res)=>{
    research.remove(req.params.id,req.headers.authorization?.replace(/^Bearer /,''));res.sendStatus(204);
  });
  app.post('/v1/auth/google', rateLimit, express.json({limit:'16kb',strict:true,inflate:false}), async (req,res) => {
    requireCondition(allowedOrigins.includes(req.headers.origin),403,'ORIGIN_NOT_ALLOWED');
    requireCondition(authenticateGoogle,503,'GOOGLE_NOT_CONFIGURED');
    requireCondition(req.body && Object.keys(req.body).every(k=>['credential','nonce'].includes(k)),400,'INVALID_REQUEST');
    res.json(await authenticateGoogle(req.body));
  });
  app.post(
    "/v1/sessions",
    rateLimit,
    express.json({ limit: "8kb", strict: true, inflate: false }),
    async (req, res) => {
      requireCondition(appId && appSecret, 503, "RECLAIM_NOT_CONFIGURED");
      requireCondition(
        req.body && Object.keys(req.body).length === 1,
        400,
        "INVALID_REQUEST",
      );
      let publicKey;
      try {
        publicKey = await validatePublicKey(req.body.publicKey);
      } catch {
        throw new SafeError(400, "INVALID_KEY");
      }
      store.prune(now());
      requireCondition(store.count() < 2000, 503, "TRY_LATER");
      const id = randomUUID(),
        token = secret(),
        createdAt = now(),
        expiresAt = createdAt + SESSION_TTL;
      const contextMessage = JSON.stringify({
        purpose: "private-community-map:v1",
        sessionId: id,
        nonce: secret(),
        key: fingerprint(publicKey),
      });
      store.create({
        id,
        tokenHash: digest(token),
        publicKey,
        contextMessage,
        createdAt,
        expiresAt,
      });
      try {
        const config = await reclaim.initialize({
          appId,
          appSecret,
          sessionId: id,
          contextMessage,
          callbackUrl: `${publicOrigin}/v1/callback/${id}`,
        });
        requireCondition(
          config.reclaimId &&
            /^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(config.providerVersion),
          503,
          "VERIFICATION_UNAVAILABLE",
        );
        store.configure(id, config.reclaimId, config.providerVersion);
        res
          .status(201)
          .json({ sessionId: id, token, expiresAt, config: config.config });
      } catch {
        store.remove(id);
        throw new SafeError(503, "VERIFICATION_UNAVAILABLE");
      }
    },
  );
  function authorize(req) {
    const s = store.get(req.params.id);
    const token = req.headers.authorization?.replace(/^Bearer /, "");
    requireCondition(s && tokenMatches(token, s.tokenHash), 404, "NOT_FOUND");
    requireCondition(s.expiresAt >= now(), 410, "SESSION_EXPIRED");
    return s;
  }
  app.get("/v1/sessions/:id", (req, res) => {
    const s = authorize(req);
    res.json({ status: s.status, expiresAt: s.expiresAt });
  });
  app.get("/v1/sessions/:id/result", (req, res) => {
    const s = authorize(req);
    requireCondition(s.status === "ready", 409, "NOT_READY");
    res.json(s.ciphertext);
  });
  app.delete("/v1/sessions/:id", (req, res) => {
    authorize(req);
    store.remove(req.params.id);
    res.sendStatus(204);
  });
  const callbackAdmission = (req, res, next) => {
    const session = store.get(req.params.id);
    if (!session || session.expiresAt < now())
      return res.status(410).json({ error: "SESSION_EXPIRED" });
    if (session.status !== "pending")
      return res.status(409).json({ error: "SESSION_ALREADY_USED" });
    if (activeVerifications >= MAX_ACTIVE_VERIFICATIONS)
      return res.status(503).json({ error: "TRY_LATER" });
    activeVerifications++;
    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        activeVerifications--;
      }
    };
    res.once("finish", release);
    res.once("close", release);
    next();
  };
  app.post(
    "/v1/callback/:id",
    callbackDiagnostics(recordCallback),
    callbackAdmission,
    express.json({ limit: BODY_LIMIT, strict: true, inflate: false }),
    async (req, res) => {
      requireCondition(req.is("application/json"), 415, "JSON_REQUIRED");
      const session = store.get(req.params.id);
      requireCondition(
        session && store.acquire(session.id),
        409,
        "SESSION_ALREADY_USED",
      );
      try {
        const proofs = Array.isArray(req.body) ? req.body : [req.body];
        requireCondition(
          proofs.length > 0 && proofs.length <= MAX_PROOFS,
          422,
          "INVALID_PROOF",
        );
        requireCondition(
          proofs.every(
            (p) =>
              p?.claimData &&
              typeof p.claimData.context === "string" &&
              typeof p.claimData.parameters === "string" &&
              Array.isArray(p.signatures) &&
              p.signatures.length > 0,
          ),
          422,
          "INVALID_PROOF",
        );
        const trusted = await reclaim.verify(proofs, session.providerVersion);
        requireCondition(
          Array.isArray(trusted) && trusted.length === proofs.length,
          422,
          "INVALID_PROOF",
        );
        const hashes = [];
        for (let i = 0; i < proofs.length; i++) {
          const c = trusted[i].context,
            claim = proofs[i].claimData;
          requireCondition(claim.provider === "http", 422, "WRONG_PROVIDER");
          requireCondition(
            c.contextAddress === session.id &&
              c.contextMessage === session.contextMessage &&
              c.reclaimSessionId === session.reclaimId,
            422,
            "WRONG_SESSION",
          );
          requireCondition(
            typeof claim.owner === "string" &&
              Number.isFinite(claim.timestampS) &&
              claim.timestampS * 1000 >= session.createdAt - 60000 &&
              claim.timestampS * 1000 <= now() + 60000,
            422,
            "STALE_PROOF",
          );
          requireCondition(
            typeof claim.identifier === "string" && claim.identifier.length > 0,
            422,
            "INVALID_PROOF",
          );
          hashes.push(digest(claim.identifier));
        }
        requireCondition(
          new Set(hashes).size === hashes.length,
          422,
          "MIXED_OR_REPLAYED_PROOFS",
        );
        const parsed = parseResidents(proofs, trusted);
        const dataset = {
          version: 1,
          source: "MYGATE",
          displayName: parsed.account.name,
          community: parsed.account.society,
          importedAt: new Date(now()).toISOString(),
          residents: parsed.residents,
        };
        const payload = await seal(dataset, session.publicKey, session.id);
        requireCondition(session.expiresAt >= now(), 410, "SESSION_EXPIRED");
        try {
          store.complete(
            session.id,
            ownerKey(ownerSecret, parsed.account.userId),
            payload,
            hashes,
            now() + RESULT_TTL,
          );
        } catch {
          throw new SafeError(409, "MIXED_OR_REPLAYED_PROOFS");
        }
        res.json({ accepted: true });
      } finally {
        store.release(session.id);
      }
    },
  );
  // No error strings, request bodies, proof payloads, URLs, tokens, or SDK errors are logged.
  app.use((error, _req, res, _next) => {
    const status =
      error.type === "entity.too.large"
        ? 413
        : error.type === "encoding.unsupported"
          ? 415
          : error.type === "entity.parse.failed"
            ? 400
            : error instanceof SafeError
              ? error.status
              : 500;
    const code =
      status === 413
        ? "PROOF_EXCEEDS_25_MB"
        : status === 415
          ? "JSON_REQUIRED"
          : status === 400
            ? "INVALID_JSON"
            : error instanceof SafeError
              ? error.code
              : "REQUEST_FAILED";
    res.status(status).json({ error: code });
  });
  return app;
}
