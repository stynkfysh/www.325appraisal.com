// /api/contact — quote-request handler for www.325appraisal.com (Cloudflare Pages Function).
//
// Adapted from the shared Brian Ward Appraisal endpoint. Same layered spam defence
// (honeypot, signed form token, dwell time, Cloudflare Turnstile, content scoring),
// rebranded for 325 Appraisal, same-origin only, and no phone number anywhere.
//
// Environment variables (Pages project > Settings > Variables and Secrets):
//   RESEND_API_KEY        (secret)  Resend API key
//   RESEND_FROM                     verified sender, e.g. "325 Appraisal <contact@brianward.com>"
//   RESEND_TO                       lead destination (brian@brianward.com — direct, not via the catch-all)
//   FORM_SECRET           (secret)  HMAC key for the form token
//   TURNSTILE_SECRET_KEY  (secret)  secret for the 325 Appraisal Turnstile widget

const SOURCE = "325appraisal.com";
const DEFAULT_FROM = "325 Appraisal <contact@brianward.com>";
const DEFAULT_TO = "brian@brianward.com";
const REPLY_TO_CLIENT = "brian@brianward.com";

const CLEAN = "clean";
const SUSPECT = "suspect";
const SPAM = "spam";
const DROP_AT = 90;
const FLAG_AT = 50;

const BAD_EMAIL_DOMAINS = [
  "bk.ru", "mail.ru", "list.ru", "inbox.ru", "rambler.ru", "yandex.ru",
  "internet.ru", "bigpind.com", "outllook.com",
];
const JUNK_PLACES = [
  "leo", "tro", "mtskheta", "lilongwe", "porsgrunn", "shekhupura",
  "lac la biche", "tbilisi", "kralupy", "gujranwala",
];
const VALID_PURPOSES = [
  "date-of-death", "estate", "divorce", "bankruptcy", "prop-19", "tax",
  "before-buying", "before-selling", "family-transaction", "insurance-dispute",
  "pmi-removal", "bonds", "litigation", "appraisal-review", "other",
];

function scoreSubmission(f) {
  const reasons = [];
  let score = 0;
  const add = (n, why) => { score += n; reasons.push(`${why} (+${n})`); };

  const name = (f.name || "").trim();
  const email = (f.email || "").trim();
  const phone = (f.phone || "").trim();
  const street = (f.street || "").trim();
  const city = (f.city || "").trim();
  const zip = (f.zip || "").trim();
  const message = (f.message || "").trim();
  const purpose = (f.purpose || "").trim();
  const all = [name, email, phone, street, city, zip, message].join(" ");

  if (f.honeypot) add(100, "hidden honeypot field was filled");

  if (f.turnstile === "failed") add(60, "failed Cloudflare Turnstile");
  if (f.turnstile === "passed") { score -= 40; reasons.push("passed Cloudflare Turnstile (-40)"); }

  // Token and Turnstile both depend on JavaScript; never charge for both at once.
  if (!f.tokenValid && f.turnstile !== "passed" && f.turnstile !== "failed") {
    add(40, "no valid form token (posted directly to the API)");
  }
  if (f.dwellMs != null && f.dwellMs < 3000) add(40, "submitted under 3s after page load");

  if (/[Ѐ-ӿ؀-ۿ一-鿿]/.test(all)) add(50, "non-Latin script");

  const digits = phone.replace(/\D/g, "");
  if (digits.length === 11 && digits[0] !== "1") add(35, "phone is 11 digits not starting with 1");
  else if (digits.length > 11) add(25, "phone has more than 11 digits");

  const domain = (email.split("@")[1] || "").toLowerCase();
  if (BAD_EMAIL_DOMAINS.includes(domain)) add(40, `email domain ${domain}`);
  if (name && !/\s/.test(name) && name.length >= 8) add(25, "single-token name");

  if (street && city && street.toLowerCase() === city.toLowerCase()) add(30, "street and city are identical");
  if (street && !/\d/.test(street)) add(25, "street address contains no number");
  if (JUNK_PLACES.includes(city.toLowerCase()) || JUNK_PLACES.includes(street.toLowerCase())) {
    add(30, "known placeholder locality");
  }
  if (zip && !/^\d{5}(-\d{4})?$/.test(zip)) add(20, "zip is not a US 5-digit code");

  if (/https?:\/\/|www\.|\[url|\[link|<a\s/i.test(message)) add(35, "message contains a link");
  if (purpose && !VALID_PURPOSES.includes(purpose.toLowerCase().replace(/\s+/g, "-"))) {
    add(20, "appraisal purpose is not one of the form options");
  }

  if (score < 0) score = 0;
  let verdict = CLEAN;
  if (score >= DROP_AT) verdict = SPAM;
  else if (score >= FLAG_AT) verdict = SUSPECT;
  return { score, verdict, reasons };
}

// Dormant until TURNSTILE_SECRET_KEY exists; a failure is scored, never fatal.
async function verifyTurnstile(token, ip, env) {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) return "unconfigured";
  if (!token) return "failed";
  try {
    const body = new FormData();
    body.append("secret", secret);
    body.append("response", token);
    if (ip) body.append("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    const d = await r.json();
    return d.success ? "passed" : "failed";
  } catch (e) {
    console.error("Turnstile verify error:", e.message);
    return "unconfigured";
  }
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function formSecret(env) {
  return env.FORM_SECRET || env.RESEND_API_KEY || "fallback-secret";
}

async function verifyToken(token, env) {
  if (!token || typeof token !== "string") return { valid: false, dwellMs: null };
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, dwellMs: null };
  const [ts, nonce, sig] = parts;
  const expected = await hmac(formSecret(env), `${ts}.${nonce}`);
  if (sig !== expected) return { valid: false, dwellMs: null };
  const age = Date.now() - Number(ts);
  if (!(age >= 0 && age < 7200000)) return { valid: false, dwellMs: age };
  return { valid: true, dwellMs: age };
}

// Same-origin form: always return to this host's /contact page.
function returnUrl(request, status) {
  return new URL(`/contact?status=${status}#request`, request.url).toString();
}

async function sendMail(env, payload) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const fd = await request.formData();
  const get = (k) => (fd.get(k) || "").toString();

  const name = get("name");
  const email = get("email");
  const phone = get("phone");
  const streetAddress = get("street-address");
  const city = get("city");
  const zipcode = get("zipcode");
  const appraisalPurpose = get("appraisal-purpose");
  const appraisalType = get("appraisal-type");
  const dateOfDeath = get("date-of-death");
  const effectiveDate = get("effective-date");
  const message = get("message");
  const honeypot = get("website") || get("company_url") || get("fax");

  const fullAddress = [streetAddress, city, zipcode].filter(Boolean).join(", ");

  if (!name || !email || !appraisalPurpose) return Response.redirect(returnUrl(request, "error"), 303);
  if (appraisalPurpose === "date-of-death" && !dateOfDeath) return Response.redirect(returnUrl(request, "error"), 303);

  const dodLabel = dateOfDeath ? formatDate(dateOfDeath) : "";
  const effLabel = effectiveDate ? formatDate(effectiveDate) : "";

  const turnstile = await verifyTurnstile(fd.get("cf-turnstile-response"), request.headers.get("CF-Connecting-IP"), env);
  const { valid: tokenValid, dwellMs } = await verifyToken(fd.get("form_token"), env);
  const { score, verdict, reasons } = scoreSubmission({
    name, email, phone, street: streetAddress, city, zip: zipcode, message,
    purpose: appraisalPurpose, honeypot, tokenValid, dwellMs, turnstile,
  });

  if (verdict === SPAM) {
    console.log(JSON.stringify({ blocked: true, source: SOURCE, name, email, score, reasons }));
    return Response.redirect(returnUrl(request, "success"), 303);
  }
  const flagged = verdict === SUSPECT;

  const rows = [
    ["Source Website", SOURCE],
    ["Name", name],
    ["Email", email],
    ["Phone", phone || "Not provided"],
    ["Property Address", fullAddress || "Not provided"],
    ["Appraisal Purpose", appraisalPurpose],
    ...(dodLabel ? [["Date of Death", dodLabel]] : []),
    ...(effLabel ? [["Requested Effective Date", effLabel]] : []),
    ["Appraisal Type", appraisalType || "Not selected"],
    ["Message", message || "None"],
  ];

  const text = [
    `New Appraisal Inquiry${flagged ? " [POSSIBLE SPAM]" : ""}`,
    "",
    `SUBMITTED FROM WEBSITE: ${SOURCE}`,
    flagged ? `\nFLAGGED AS POSSIBLE SPAM (score ${score}): ${reasons.join("; ")}\n` : "",
    ...rows.map(([k, v]) => `${k}: ${v}`),
  ].join("\n").trim();

  const flagBanner = flagged
    ? `<p style="font-size:14px;background:#fbe9e7;border:1px solid #d32f2f;color:#c62828;padding:10px 14px;border-radius:4px;font-family:Arial,sans-serif;margin:0 0 14px;"><strong>Possible spam (score ${score}).</strong> Delivered so you can judge it yourself. No confirmation email was sent to the submitter.<br><span style="font-size:12px;">${escapeHtml(reasons.join("; "))}</span></p>`
    : "";
  const html = `<h2 style="font-family:Arial,sans-serif;">New Appraisal Inquiry</h2>
${flagBanner}
<p style="font-size:15px;background:#2c3a47;color:#fff;padding:10px 14px;border-radius:4px;font-family:Arial,sans-serif;margin:0 0 14px;">Submitted from website: <strong>${SOURCE}</strong></p>
<table style="border-collapse:collapse;font-family:Arial,sans-serif;">
${rows.map(([k, v], i) => `<tr${i % 2 ? "" : ' style="background:#f5f5f5;"'}><td style="padding:6px 12px;font-weight:bold;">${escapeHtml(k)}</td><td style="padding:6px 12px;">${k === "Email" ? `<a href="mailto:${escapeHtml(v)}">${escapeHtml(v)}</a>` : escapeHtml(v)}</td></tr>`).join("\n")}
</table>`;

  const from = env.RESEND_FROM || DEFAULT_FROM;
  try {
    await sendMail(env, {
      from,
      to: [env.RESEND_TO || DEFAULT_TO],
      reply_to: email,
      subject: `${flagged ? "[POSSIBLE SPAM] " : ""}[${SOURCE}] New Appraisal Inquiry – ${appraisalPurpose}${dodLabel ? ` (${dodLabel})` : ""} – ${name}`,
      text,
      html,
    });
  } catch (err) {
    console.error("Resend error:", err.message);
    return Response.redirect(returnUrl(request, "error"), 303);
  }

  // Confirmation only for clean submissions (spam uses harvested addresses).
  if (verdict === CLEAN) {
    try {
      await sendMail(env, {
        from,
        to: [email],
        reply_to: REPLY_TO_CLIENT,
        subject: "We received your appraisal request — 325 Appraisal",
        text: autoReplyText({ name, email, phone, fullAddress, appraisalPurpose, dodLabel, effLabel, appraisalType, message }),
        html: autoReplyHtml({ name, email, phone, fullAddress, appraisalPurpose, dodLabel, effLabel, appraisalType, message }),
      });
    } catch (err) {
      console.error("Auto-reply failed (inquiry still received):", err.message);
    }
  }

  return Response.redirect(returnUrl(request, "success"), 303);
}

function autoReplyText(d) {
  return `Hi ${d.name},

Thank you for requesting an appraisal quote from 325 Appraisal. Your request has
been received, and you will hear back by email — usually within one business day —
with a written quote and the delivery date.

If anything changes in the meantime, simply reply to this email.

WHAT YOU SENT
Name: ${d.name}
Email: ${d.email}
Phone: ${d.phone || "Not provided"}
Property Address: ${d.fullAddress || "Not provided"}
Appraisal Purpose: ${d.appraisalPurpose}${d.dodLabel ? `\nDate of Death: ${d.dodLabel}` : ""}${d.effLabel ? `\nRequested Effective Date: ${d.effLabel}` : ""}
Appraisal Type: ${d.appraisalType || "Not selected"}
Message: ${d.message || "None"}

Thank you,
Brian Ward
325 Appraisal
California Certified Residential Real Estate Appraiser
https://www.325appraisal.com

This is an automatic confirmation. You do not need to submit the form again.`;
}

function autoReplyHtml(d) {
  const row = (label, value) => value
    ? `<tr><td style="padding:6px 12px;font-weight:600;width:170px;vertical-align:top;">${escapeHtml(label)}</td><td style="padding:6px 12px;">${escapeHtml(value)}</td></tr>`
    : "";
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:0 auto;padding:20px;color:#1f2328;">
<h2 style="color:#2c3a47;border-bottom:3px solid #d4882b;padding-bottom:10px;">Your appraisal request was received</h2>
<p>Hi ${escapeHtml(d.name)},</p>
<p>Thank you for requesting an appraisal quote from <strong>325 Appraisal</strong>. You will hear back by email — usually within <strong>one business day</strong> — with a written quote and the delivery date.</p>
<p>If anything changes in the meantime, simply reply to this email.</p>
<h3 style="color:#59616b;margin-top:24px;">What you sent</h3>
<table style="width:100%;border-collapse:collapse;background:#f6f4ef;border-radius:6px;">
${row("Name", d.name)}${row("Email", d.email)}${row("Phone", d.phone)}${row("Property Address", d.fullAddress)}${row("Appraisal Purpose", d.appraisalPurpose)}${row("Date of Death", d.dodLabel)}${row("Requested Effective Date", d.effLabel)}${row("Appraisal Type", d.appraisalType)}${row("Message", d.message)}
</table>
<p style="margin-top:24px;">Thank you,<br><strong>Brian Ward</strong><br>325 Appraisal<br>California Certified Residential Real Estate Appraiser<br><a href="https://www.325appraisal.com" style="color:#2c3a47;">www.325appraisal.com</a></p>
<p style="margin-top:28px;padding-top:14px;border-top:1px solid #ddd;font-size:13px;color:#888;">This is an automatic confirmation. You do not need to submit the form again.</p>
</body></html>`;
}

function formatDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value).trim());
  if (!m) return String(value);
  const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  const month = months[Number(m[2]) - 1];
  return month ? `${month} ${Number(m[3])}, ${m[1]}` : String(value);
}

function escapeHtml(str) {
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
