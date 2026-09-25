import { SessionStore } from "./store.mjs";
import { createApp } from "./app.mjs";
import { googleAuthenticator, GOOGLE_CLIENT_ID } from "./google-auth.mjs";
import { reclaim } from "./reclaim.mjs";
const {
  PUBLIC_ORIGIN: configuredOrigin,
  ALLOWED_ORIGINS,
  RECLAIM_APP_ID,
  RECLAIM_APP_SECRET,
  OWNER_HMAC_SECRET,
} = process.env;
const PUBLIC_ORIGIN = configuredOrigin || process.env.RENDER_EXTERNAL_URL;
if (!PUBLIC_ORIGIN || !ALLOWED_ORIGINS || !OWNER_HMAC_SECRET)
  throw new Error("Required server configuration is missing.");
const publicURL = new URL(PUBLIC_ORIGIN);
if (
  publicURL.protocol !== "https:" &&
  !(
    process.env.NODE_ENV !== "production" &&
    ["localhost", "127.0.0.1"].includes(publicURL.hostname)
  )
)
  throw new Error("The callback origin must use HTTPS.");
const store = new SessionStore(
  process.env.DATABASE_PATH || "./data/sessions.sqlite",
);
const app = createApp({
  store,
  reclaim,
  authenticateGoogle: googleAuthenticator({ownerSecret: OWNER_HMAC_SECRET, clientId: process.env.GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID}),
  appId: RECLAIM_APP_ID,
  appSecret: RECLAIM_APP_SECRET,
  ownerSecret: OWNER_HMAC_SECRET,
  publicOrigin: publicURL.origin,
  allowedOrigins: ALLOWED_ORIGINS.split(",").map((s) => s.trim()),
});
const timer = setInterval(() => store.prune(Date.now()), 60000);
timer.unref();
const server = app.listen(Number(process.env.PORT || 8788), "0.0.0.0");
server.requestTimeout = 120000;
server.headersTimeout = 15000;
for (const signal of ["SIGTERM", "SIGINT"])
  process.on(signal, () =>
    server.close(() => {
      clearInterval(timer);
      store.close();
      process.exit(0);
    }),
  );
