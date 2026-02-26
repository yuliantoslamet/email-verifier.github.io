/**
 * ============================================================
 * EMAIL VERIFICATION ENGINE — Multi-Layer v2.0
 * ============================================================
 * Layer 1: RFC 5322 Syntax Validation
 * Layer 2: Domain & MX Validation (via DNS-over-HTTPS)
 * Layer 3: Behavior & Heuristic Scoring
 * ============================================================
 * Author: Email Verifier Pro
 * License: MIT
 * Note: All DNS lookups use Cloudflare DNS-over-HTTPS.
 *       No SMTP connections are made.
 * ============================================================
 */

'use strict';

// ─────────────────────────────────────────────────────────────
// LAYER 1 — SYNTAX VALIDATION
// ─────────────────────────────────────────────────────────────

/**
 * Validate email syntax against RFC 5322 rules.
 * Checks format, length limits, local-part rules, and TLD presence.
 * @param {string} email
 * @returns {{ status: 'valid_format'|'invalid_format', reason: string }}
 */
function validateSyntax(email) {
  if (!email || typeof email !== 'string') {
    return { status: 'invalid_format', reason: 'Input is empty or not a string' };
  }

  const trimmed = email.trim().toLowerCase();

  // Overall length limit (RFC 5321)
  if (trimmed.length > 254) {
    return { status: 'invalid_format', reason: 'Email exceeds 254 character limit' };
  }

  // Must contain exactly one @
  const atCount = (trimmed.match(/@/g) || []).length;
  if (atCount !== 1) {
    return { status: 'invalid_format', reason: atCount === 0 ? 'Missing @ symbol' : 'Multiple @ symbols found' };
  }

  const [local, domain] = trimmed.split('@');

  // Local part checks
  if (!local || local.length === 0) {
    return { status: 'invalid_format', reason: 'Local part (before @) is empty' };
  }
  if (local.length > 64) {
    return { status: 'invalid_format', reason: 'Local part exceeds 64 character limit' };
  }
  if (local.startsWith('.') || local.endsWith('.')) {
    return { status: 'invalid_format', reason: 'Local part cannot start or end with a period' };
  }
  if (local.includes('..')) {
    return { status: 'invalid_format', reason: 'Local part contains consecutive periods' };
  }

  // RFC 5321 allowed characters in local part
  if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) {
    return { status: 'invalid_format', reason: 'Local part contains invalid characters' };
  }

  // Domain checks
  if (!domain || domain.length === 0) {
    return { status: 'invalid_format', reason: 'Domain part (after @) is empty' };
  }
  if (!domain.includes('.')) {
    return { status: 'invalid_format', reason: 'Domain missing TLD (no period found)' };
  }
  if (domain.startsWith('.') || domain.endsWith('.')) {
    return { status: 'invalid_format', reason: 'Domain cannot start or end with a period' };
  }
  if (domain.startsWith('-') || domain.endsWith('-')) {
    return { status: 'invalid_format', reason: 'Domain cannot start or end with a hyphen' };
  }
  if (domain.includes('..')) {
    return { status: 'invalid_format', reason: 'Domain contains consecutive periods' };
  }

  const tld = domain.split('.').pop();
  if (tld.length < 2) {
    return { status: 'invalid_format', reason: 'TLD too short (minimum 2 characters)' };
  }
  if (!/^[a-zA-Z]{2,}$/.test(tld)) {
    return { status: 'invalid_format', reason: 'TLD contains invalid characters' };
  }

  // Full RFC 5322 regex (simplified, covers 99.9% of real emails)
  const rfc5322 = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  if (!rfc5322.test(trimmed)) {
    return { status: 'invalid_format', reason: 'Does not match RFC 5322 pattern' };
  }

  return { status: 'valid_format', reason: 'Syntax is valid' };
}


// ─────────────────────────────────────────────────────────────
// LAYER 2 — DOMAIN & MX VALIDATION
// ─────────────────────────────────────────────────────────────

/** Disposable email provider domains — internal list */
const DISPOSABLE_DOMAINS = new Set([
  // Classic disposable
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
  'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.info',
  'tempmail.com', 'temp-mail.org', 'temp-mail.io', '10minutemail.com',
  '10minutemail.net', 'throwaway.email', 'fakeinbox.com', 'sharklasers.com',
  'yopmail.com', 'yopmail.fr', 'trashmail.com', 'trashmail.me', 'trashmail.net',
  'dispostable.com', 'mailnull.com', 'spamgourmet.com', 'spamgourmet.net',
  'tempr.email', 'discard.email', 'spam4.me', 'maildrop.cc', 'wegwerfmail.de',
  'spamthisplease.com', 'tempinbox.com', 'filzmail.com', 'throwam.com',
  'zeroknow.com', 'binkmail.com', 'bob.email', 'clrmail.com',
  'mailmetrash.com', 'getairmail.com', 'jetable.fr.nf', 'notsharingmy.info',
  'objectmail.com', 'ownmail.net', 'pecinan.com', 'speed.1s.fr',
  'supergreatmail.com', 'suremail.info', 'thisisnotmyrealemail.com',
  'thismail.net', 'throwam.com', 'tradermail.info', 'uggsrock.com',
  'upliftnow.com', 'uroid.com', 'veryrealemail.com', 'wilemail.com',
  'willhackforfood.biz', 'wuzupmail.net', 'xagloo.com', 'xemaps.com',
  'xents.com', 'xmaily.com', 'xoxy.net', 'ypmail.webarnak.fr.eu.org',
  'yuurok.com', 'z1p.biz', 'za.com', 'zehnminuten.de', 'zehnminutenmail.de',
  'zoemail.net', 'zomg.info', 'inoutmail.net', 'insorg.org',
  'mailexpire.com', 'mailfreeonline.com', 'mailinater.com',
  'mailismagic.com', 'mailme.lv', 'mailnew.com', 'mailscrap.com',
  // Additional
  'emailondeck.com', 'tempsky.com', 'tempomail.fr', 'temporaryemail.net',
  'temporaryinbox.com', 'thankyou2010.com', 'thecloudindex.com',
  'tranceversal.com', 'trash2009.com', 'trashdevil.com', 'trashdevil.net',
  'trash-mail.at', 'spamevader.net', 'mailboxy.fun', 'guerrillamail.biz'
]);

/** Well-known legitimate domains — skip DNS for speed */
const KNOWN_VALID_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.id',
  'yahoo.co.jp', 'yahoo.fr', 'yahoo.de', 'yahoo.es', 'yahoo.it',
  'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'live.com', 'live.co.uk',
  'msn.com', 'icloud.com', 'me.com', 'mac.com',
  'protonmail.com', 'proton.me', 'pm.me',
  'zoho.com', 'aol.com', 'mail.com', 'gmx.com', 'gmx.de', 'gmx.net',
  'fastmail.com', 'fastmail.fm', 'fastmail.net',
  'yandex.com', 'yandex.ru', 'tutanota.com', 'tutamail.com',
  'mailbox.org', 'hey.com', 'basecamp.com',
  'web.de', 'freenet.de', 'libero.it', 'virgilio.it',
  'orange.fr', 'free.fr', 'sfr.fr', 'laposte.net', 'wanadoo.fr',
  'rambler.ru', 'mail.ru', 'inbox.ru', 'bk.ru', 'list.ru',
  'naver.com', 'daum.net', 'hanmail.net',
  'qq.com', '163.com', '126.com', 'sina.com', 'sohu.com',
  'rediffmail.com', 'indiatimes.com',
  'inbox.com', 'lycos.com', 'excite.com',
]);

/**
 * Perform DNS-over-HTTPS MX lookup via Cloudflare.
 * Falls back to A record if no MX found.
 * @param {string} domain
 * @returns {Promise<{ hasMX: boolean, hasA: boolean, error: string|null }>}
 */
async function lookupDomain(domain) {
  const base = 'https://cloudflare-dns.com/dns-query';
  const headers = { 'Accept': 'application/dns-json' };

  try {
    // MX lookup
    const mxRes = await fetch(`${base}?name=${encodeURIComponent(domain)}&type=MX`, { headers });
    const mxData = await mxRes.json();
    const hasMX = mxData.Status === 0 && Array.isArray(mxData.Answer) && mxData.Answer.length > 0;

    if (hasMX) return { hasMX: true, hasA: true, error: null };

    // Fallback: A record
    const aRes = await fetch(`${base}?name=${encodeURIComponent(domain)}&type=A`, { headers });
    const aData = await aRes.json();
    const hasA = aData.Status === 0 && Array.isArray(aData.Answer) && aData.Answer.length > 0;

    return { hasMX: false, hasA, error: null };
  } catch (err) {
    return { hasMX: false, hasA: false, error: err.message };
  }
}

/**
 * Validate domain and MX records for an email address.
 * Uses a fast-path for known-good and disposable domains.
 * @param {string} email
 * @param {object} options
 * @param {boolean} [options.skipDNS=false] — skip live DNS lookup (for offline/batch use)
 * @returns {Promise<{ status: string, reason: string, mx: boolean|null }>}
 */
async function validateDomain(email, options = {}) {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return { status: 'invalid_domain', reason: 'Cannot extract domain', mx: null };

  // Fast path: disposable
  if (DISPOSABLE_DOMAINS.has(domain)) {
    return { status: 'disposable_domain', reason: `Known disposable provider: ${domain}`, mx: null };
  }

  // Fast path: well-known valid
  if (KNOWN_VALID_DOMAINS.has(domain)) {
    return { status: 'valid_domain', reason: 'Known legitimate email provider', mx: true };
  }

  // Skip DNS if requested (e.g., offline/test mode)
  if (options.skipDNS) {
    return { status: 'unknown_domain', reason: 'DNS lookup skipped (offline mode)', mx: null };
  }

  // Live DNS lookup
  try {
    const { hasMX, hasA, error } = await lookupDomain(domain);

    if (error) {
      return { status: 'unknown_domain', reason: `DNS lookup failed: ${error}`, mx: null };
    }
    if (hasMX) {
      return { status: 'valid_domain', reason: 'MX record found', mx: true };
    }
    if (hasA) {
      return { status: 'valid_domain', reason: 'A record found (no MX, but domain exists)', mx: false };
    }
    return { status: 'invalid_domain', reason: 'No MX or A record found — domain likely does not exist', mx: false };
  } catch (_) {
    return { status: 'unknown_domain', reason: 'DNS resolution error', mx: null };
  }
}


// ─────────────────────────────────────────────────────────────
// LAYER 3 — BEHAVIOR & HEURISTIC SCORING
// ─────────────────────────────────────────────────────────────

/** Common typo-domain map: wrong → correct */
const TYPO_DOMAINS = {
  'gamil.com': 'gmail.com',  'gmai.com': 'gmail.com',  'gmial.com': 'gmail.com',
  'gnail.com': 'gmail.com',  'gmaill.com': 'gmail.com', 'gmail.co': 'gmail.com',
  'gmail.cm': 'gmail.com',   'gmail.con': 'gmail.com',  'gmaill.co': 'gmail.com',
  'yaho.com': 'yahoo.com',   'yahooo.com': 'yahoo.com', 'yhoo.com': 'yahoo.com',
  'yahoo.co': 'yahoo.com',   'yahoo.cm': 'yahoo.com',   'yaho.co': 'yahoo.com',
  'yaoo.com': 'yahoo.com',
  'hotmai.com': 'hotmail.com', 'hotmial.com': 'hotmail.com', 'homail.com': 'hotmail.com',
  'hotmil.com': 'hotmail.com', 'hotmaill.com': 'hotmail.com',
  'outlok.com': 'outlook.com', 'outloook.com': 'outlook.com', 'outlookk.com': 'outlook.com',
  'outllok.com': 'outlook.com',
  'iclod.com': 'icloud.com',  'icould.com': 'icloud.com',
  'protonmial.com': 'protonmail.com', 'protonmal.com': 'protonmail.com',
};

/** Role-based email local parts */
const ROLE_BASED = new Set([
  'admin', 'administrator', 'webmaster', 'postmaster', 'hostmaster',
  'info', 'information', 'contact', 'hello', 'hi', 'hey',
  'support', 'help', 'helpdesk', 'service', 'customerservice',
  'sales', 'marketing', 'billing', 'finance', 'accounting',
  'noreply', 'no-reply', 'donotreply', 'do-not-reply',
  'abuse', 'spam', 'security', 'privacy',
  'hr', 'careers', 'jobs', 'recruitment',
  'press', 'media', 'pr', 'news',
  'legal', 'compliance', 'gdpr',
  'root', 'sysadmin', 'devops', 'ops',
  'team', 'staff', 'office', 'mail', 'email',
  'newsletter', 'updates', 'notifications', 'alerts', 'mailinglist',
  'dev', 'api', 'bot', 'daemon', 'system', 'mailer',
]);

/** Keyboard walk patterns */
const KEYBOARD_PATTERNS = [
  'qwerty', 'qwertyuiop', 'asdf', 'asdfgh', 'asdfghjkl',
  'zxcv', 'zxcvbn', 'zxcvbnm', '1234', '12345', '123456',
  '1234567', '12345678', '123456789', '1234567890',
  'abcd', 'abcde', 'abcdef', 'abc123', 'password', 'pass',
  'qazwsx', 'edcrfv', 'tgbyhn', 'poiuyt', 'lkjhgf',
  'mnbvcx', 'qazxsw', 'wsxedc',
];

/**
 * Calculate heuristic quality score for an email address.
 * Returns a score 0–100, risk level, and a list of flags.
 * @param {string} email
 * @param {object} layer2Result — output from validateDomain()
 * @returns {{ quality_score: number, risk_level: 'low'|'medium'|'high', flags: string[] }}
 */
function scoreHeuristics(email, layer2Result = {}) {
  const flags = [];
  let deductions = 0;

  const trimmed = email.trim().toLowerCase();
  const [local, domain] = trimmed.split('@');

  // ── LOCAL PART CHECKS ──

  // Very short username (≤ 2 chars)
  if (local.length <= 2) {
    flags.push('very_short_username');
    deductions += 20;
  } else if (local.length <= 4) {
    flags.push('short_username');
    deductions += 8;
  }

  // Excessive numbers (more than 4 digits)
  const digits = (local.match(/\d/g) || []).length;
  const digitRatio = digits / local.length;
  if (digits > 6) {
    flags.push('excessive_numbers');
    deductions += 18;
  } else if (digits > 4) {
    flags.push('many_numbers');
    deductions += 8;
  }
  if (digitRatio > 0.6 && local.length > 4) {
    flags.push('high_digit_ratio');
    deductions += 12;
  }

  // Random character sequence detection
  // Measure "randomness" via character entropy / consecutive consonant clusters
  const consonantClusters = (local.replace(/[0-9._+-]/g, '').match(/[bcdfghjklmnpqrstvwxyz]{4,}/gi) || []);
  if (consonantClusters.length >= 2) {
    flags.push('random_character_pattern');
    deductions += 20;
  } else if (consonantClusters.some(c => c.length >= 5)) {
    flags.push('suspicious_consonant_cluster');
    deductions += 12;
  }

  // Keyboard walk pattern
  const localAlpha = local.replace(/[0-9._+-]/g, '');
  for (const pattern of KEYBOARD_PATTERNS) {
    if (localAlpha.includes(pattern)) {
      flags.push(`keyboard_pattern_detected:${pattern}`);
      deductions += 22;
      break;
    }
  }

  // Repetitive characters (e.g. aaaa, 1111)
  if (/(.)\1{3,}/.test(local)) {
    flags.push('repetitive_characters');
    deductions += 15;
  }

  // Starts or ends with a number
  if (/^\d/.test(local) && /\d$/.test(local) && local.length < 8) {
    flags.push('numeric_bounded_username');
    deductions += 6;
  }

  // Role-based email detection
  const localBase = local.replace(/[._+-]/g, '');
  if (ROLE_BASED.has(local) || ROLE_BASED.has(localBase)) {
    flags.push('role_based_address');
    deductions += 15;
  }

  // ── DOMAIN CHECKS ──

  // Typo domain
  if (TYPO_DOMAINS[domain]) {
    flags.push(`typo_domain:did_you_mean_${TYPO_DOMAINS[domain]}`);
    deductions += 35;
  }

  // Layer 2 domain status integration
  if (layer2Result.status === 'disposable_domain') {
    flags.push('disposable_provider');
    deductions += 40;
  }
  if (layer2Result.status === 'invalid_domain') {
    flags.push('invalid_domain_no_dns');
    deductions += 45;
  }
  if (layer2Result.status === 'unknown_domain') {
    flags.push('unresolvable_domain');
    deductions += 10;
  }
  if (layer2Result.mx === false && layer2Result.status === 'valid_domain') {
    flags.push('domain_has_no_mx_record');
    deductions += 10;
  }

  // Domain looks fake: random-looking domain label
  const domainLabel = domain.split('.')[0];
  const domainConsonants = (domainLabel.match(/[bcdfghjklmnpqrstvwxyz]{5,}/gi) || []);
  if (domainConsonants.length > 0) {
    flags.push('suspicious_domain_pattern');
    deductions += 10;
  }

  // Excessive domain label length with numbers
  if (/\d{4,}/.test(domainLabel)) {
    flags.push('domain_contains_many_digits');
    deductions += 8;
  }

  // ── SCORE & RISK LEVEL ──

  const quality_score = Math.max(0, Math.min(100, 100 - deductions));

  let risk_level;
  if (quality_score >= 60) risk_level = 'low';
  else if (quality_score >= 40) risk_level = 'medium';
  else risk_level = 'high';

  return { quality_score, risk_level, flags };
}


// ─────────────────────────────────────────────────────────────
// ORCHESTRATOR — Full Verification Pipeline
// ─────────────────────────────────────────────────────────────

/**
 * Run all three verification layers on a single email address.
 * @param {string} email
 * @param {object} options
 * @param {boolean} [options.skipDNS=false]
 * @returns {Promise<VerificationResult>}
 *
 * @typedef {object} VerificationResult
 * @property {string} email
 * @property {'valid_format'|'invalid_format'} layer1_format
 * @property {'valid_domain'|'invalid_domain'|'disposable_domain'|'unknown_domain'|'skipped'} layer2_domain
 * @property {number} layer3_score
 * @property {'low'|'medium'|'high'} risk_level
 * @property {string[]} flags
 * @property {object} _meta
 */
async function verifyEmail(email, options = {}) {
  const normalized = (email || '').trim().toLowerCase();

  // Layer 1
  const l1 = validateSyntax(normalized);

  // If syntax fails, skip further layers
  if (l1.status === 'invalid_format') {
    return {
      email: normalized,
      layer1_format: 'invalid_format',
      layer2_domain: 'skipped',
      layer3_score: 0,
      risk_level: 'high',
      flags: ['invalid_syntax', l1.reason.toLowerCase().replace(/\s+/g, '_')],
      _meta: { l1_reason: l1.reason, l2_reason: null, l3_deductions: null }
    };
  }

  // Layer 2
  const l2 = await validateDomain(normalized, options);

  // Layer 3
  const l3 = scoreHeuristics(normalized, l2);

  return {
    email: normalized,
    layer1_format: 'valid_format',
    layer2_domain: l2.status,
    layer3_score: l3.quality_score,
    risk_level: l3.risk_level,
    flags: l3.flags,
    _meta: {
      l1_reason: l1.reason,
      l2_reason: l2.reason,
      l3_deductions: 100 - l3.quality_score
    }
  };
}

/**
 * Batch-verify an array of email addresses with concurrency control.
 * @param {string[]} emails
 * @param {object} options
 * @param {number} [options.concurrency=10]
 * @param {boolean} [options.skipDNS=false]
 * @param {boolean} [options.deduplicate=true]
 * @param {function} [options.onProgress] — callback(processed, total, result)
 * @returns {Promise<VerificationResult[]>}
 */
async function verifyBatch(emails, options = {}) {
  const {
    concurrency = 10,
    skipDNS = false,
    deduplicate = true,
    onProgress = null
  } = options;

  let list = emails.map(e => (e || '').trim().toLowerCase()).filter(Boolean);

  // Deduplicate
  if (deduplicate) {
    list = [...new Set(list)];
  }

  const results = [];
  const total = list.length;
  let processed = 0;

  // Process in chunks of `concurrency`
  for (let i = 0; i < total; i += concurrency) {
    const chunk = list.slice(i, i + concurrency);
    const chunkResults = await Promise.all(
      chunk.map(email => verifyEmail(email, { skipDNS }))
    );
    for (const r of chunkResults) {
      results.push(r);
      processed++;
      if (typeof onProgress === 'function') {
        onProgress(processed, total, r);
      }
    }
  }

  return results;
}


// ─────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────

// CommonJS / Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    verifyEmail,
    verifyBatch,
    validateSyntax,
    validateDomain,
    scoreHeuristics,
    DISPOSABLE_DOMAINS,
    KNOWN_VALID_DOMAINS,
    TYPO_DOMAINS,
    ROLE_BASED,
  };
}

// Browser global
if (typeof window !== 'undefined') {
  window.EmailVerifier = {
    verifyEmail,
    verifyBatch,
    validateSyntax,
    validateDomain,
    scoreHeuristics,
  };
}


// ─────────────────────────────────────────────────────────────
// EXAMPLE USAGE
// ─────────────────────────────────────────────────────────────
/*

// ── Single email ──
const result = await verifyEmail('john.doe@gmail.com');
console.log(JSON.stringify(result, null, 2));
// {
//   "email": "john.doe@gmail.com",
//   "layer1_format": "valid_format",
//   "layer2_domain": "valid_domain",
//   "layer3_score": 92,
//   "risk_level": "low",
//   "flags": [],
//   "_meta": { "l1_reason": "Syntax is valid", "l2_reason": "Known legitimate email provider", ... }
// }

// ── Batch with progress ──
const emails = [
  'user@gmail.com',
  'admin@company.com',
  'test@mailinator.com',
  'notanemail',
  'typo@gmial.com',
  'x@fake-random-abc123xyz.com',
  'info@example.org',
  'a2b3c4d5e6f7@random.net',
];

const batchResults = await verifyBatch(emails, {
  concurrency: 5,
  skipDNS: false,
  deduplicate: true,
  onProgress: (done, total, r) => {
    console.log(`[${done}/${total}] ${r.email} → ${r.risk_level} (score: ${r.layer3_score})`);
  }
});

// Filter by risk
const highRisk  = batchResults.filter(r => r.risk_level === 'high');
const validOnly = batchResults.filter(r =>
  r.layer1_format === 'valid_format' &&
  r.layer2_domain === 'valid_domain' &&
  r.risk_level === 'low'
);

// ── Offline / no-DNS mode ──
const offlineResult = await verifyEmail('user@example.com', { skipDNS: true });

// ── Access individual layers ──
const syntaxOnly   = validateSyntax('bad@@email.com');
const domainOnly   = await validateDomain('user@gmail.com');
const heuristicsOnly = scoreHeuristics('admin@gamil.com', { status: 'valid_domain' });

*/
