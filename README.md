# www.325appraisal.com

Static site for **325 Appraisal** — California residential appraisals by Brian Ward (License AR036053).
Sister site of [Brian Ward Appraisal](https://www.brianward.com) with original copy, its own design and its own request form.

- Pure static HTML/CSS/JS on Cloudflare Pages (no build step; output directory `/`).
- 14 service pages, 73 community pages (San Diego + Riverside Counties), 15 statewide county pages.
- Quote form → `functions/api/contact.js` (Pages Function) → Resend → `brian@brianward.com` (direct). Published email `contact@325appraisal.com` → ImprovMX catch-all → 325appraisal@brianward.com.
- Env vars: `RESEND_API_KEY`, `RESEND_FROM`, `RESEND_TO`, `FORM_SECRET`, `TURNSTILE_SECRET_KEY`.
- No phone number is published anywhere on the site.
- Source generator, copy and image prompts live in the iCloud project folder `www.325appraisal.com/_tools/` (not deployed).
