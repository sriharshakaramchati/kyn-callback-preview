# KYN staging callback

Data-free server deployment for the personal network-map preview. Source review: https://github.com/sriharshakaramchati/orbit-tscaa4pj2uu0/pull/2

Render Free only; no paid disk/database or payment method. Node 24, one instance, 25 MiB JSON limit. Secrets are supplied privately through host environment settings. Only encrypted results and transient session metadata are stored. Completed maps remain encrypted in each visitor's browser. Pending imports must restart after host restarts.

Build: `npm ci --omit=dev`. Start: `node --max-old-space-size=128 server/main.mjs`.

Automatic public-profile research uses a private `TAVILY_API_KEY` on the free Researcher plan only, with pay-as-you-go disabled. Search inputs transit memory; replies and short-lived replay buffers are encrypted to each requesting browser. No plaintext query/evidence logging or database writes. The shared free allowance stops research at 1,000 queries/month.
