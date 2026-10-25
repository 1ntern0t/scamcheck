/*
 * scamcheck engine: offline heuristic risk scoring for text, URLs and
 * crypto addresses. Heuristic only; it is not a guarantee of safety.
 * Works in Node (CommonJS) and in the browser (global `Scamcheck`).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./primitives.js'));
  } else {
    root.Scamcheck = factory(root.ScamcheckPrimitives);
  }
})(typeof self !== 'undefined' ? self : this, function (P) {
  'use strict';

  const VERSION = '0.1.0';
  const DISCLAIMER = 'Heuristic result only. A low score does not mean something is safe; ' +
    'a high score does not prove fraud. No live threat feeds are consulted.';

  // ------------------------------------------------------------- Data sets
  // Brands commonly impersonated. `official` lists registrable domains we
  // treat as legitimate. `fuzzy: false` disables edit-distance matching for
  // names that collide with ordinary words (e.g. steam/stream, apple/apply).
  const BRANDS = [
    { name: 'paypal', official: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
    { name: 'google', official: ['google.com', 'googleusercontent.com', 'youtube.com', 'gmail.com', 'goo.gl'] },
    { name: 'microsoft', official: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com', 'azure.com'] },
    { name: 'outlook', official: ['outlook.com', 'live.com', 'microsoft.com', 'office.com'] },
    { name: 'office365', official: ['office.com', 'microsoft.com', 'office365.com'] },
    { name: 'amazon', official: ['amazon.com', 'amazonaws.com', 'amazon.jobs', 'amzn.to'] },
    { name: 'apple', official: ['apple.com', 'icloud.com', 'apple.co'], fuzzy: false },
    { name: 'icloud', official: ['icloud.com', 'apple.com'] },
    { name: 'netflix', official: ['netflix.com', 'nflxext.com'] },
    { name: 'facebook', official: ['facebook.com', 'fb.com', 'fb.me', 'meta.com'] },
    { name: 'instagram', official: ['instagram.com'] },
    { name: 'whatsapp', official: ['whatsapp.com', 'wa.me'] },
    { name: 'telegram', official: ['telegram.org', 't.me', 'telegram.me'] },
    { name: 'discord', official: ['discord.com', 'discord.gg', 'discordapp.com'] },
    { name: 'twitter', official: ['twitter.com', 'x.com', 't.co'] },
    { name: 'linkedin', official: ['linkedin.com', 'lnkd.in'] },
    { name: 'github', official: ['github.com', 'github.io', 'githubusercontent.com'] },
    { name: 'dropbox', official: ['dropbox.com'] },
    { name: 'docusign', official: ['docusign.com', 'docusign.net'] },
    { name: 'coinbase', official: ['coinbase.com'] },
    { name: 'binance', official: ['binance.com', 'binance.us'] },
    { name: 'kraken', official: ['kraken.com'], fuzzy: false },
    { name: 'metamask', official: ['metamask.io'] },
    { name: 'phantom', official: ['phantom.app', 'phantom.com'], fuzzy: false },
    { name: 'solana', official: ['solana.com', 'solana.org'] },
    { name: 'ledger', official: ['ledger.com'], fuzzy: false },
    { name: 'trezor', official: ['trezor.io'] },
    { name: 'opensea', official: ['opensea.io'] },
    { name: 'uniswap', official: ['uniswap.org'] },
    { name: 'chase', official: ['chase.com', 'jpmorganchase.com'], fuzzy: false },
    { name: 'wellsfargo', official: ['wellsfargo.com'] },
    { name: 'bankofamerica', official: ['bankofamerica.com', 'bofa.com'] },
    { name: 'venmo', official: ['venmo.com'] },
    { name: 'cashapp', official: ['cash.app', 'cashapp.com', 'squareup.com'] },
    { name: 'zelle', official: ['zellepay.com', 'zelle.com'], fuzzy: false },
    { name: 'usps', official: ['usps.com', 'usps.gov'], fuzzy: false },
    { name: 'fedex', official: ['fedex.com'], fuzzy: false },
    { name: 'dhl', official: ['dhl.com', 'dhl.de'], fuzzy: false },
    { name: 'steam', official: ['steampowered.com', 'steamcommunity.com'], fuzzy: false },
    { name: 'steampowered', official: ['steampowered.com'] },
    { name: 'steamcommunity', official: ['steamcommunity.com'] },
    { name: 'walmart', official: ['walmart.com'] },
    { name: 'ebay', official: ['ebay.com'], fuzzy: false },
    { name: 'irs', official: ['irs.gov'], fuzzy: false }
  ];

  // Generic gTLDs that a brand name on an unofficial domain is suspicious on.
  // Country-code TLDs are skipped for exact-name matches because large brands
  // legitimately own many of them (amazon.de, google.co.uk, ...).
  const SUSPICIOUS_TLDS = new Set([
    'zip', 'mov', 'xyz', 'top', 'click', 'link', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'support',
    'rest', 'fit', 'loan', 'cam', 'icu', 'buzz', 'monster', 'cyou', 'sbs', 'quest', 'country',
    'kim', 'men', 'date', 'review', 'stream', 'download', 'racing', 'win', 'bid', 'party', 'cfd',
    'bond', 'lat', 'beauty', 'hair', 'skin', 'mom'
  ]);

  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly',
    'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 's.id', 'bl.ink', 'v.gd', 'qr.ae', 'shorte.st',
    'adf.ly', 'lnkd.in', 'trib.al', 'tinylink.net', 'short.io', 'clck.ru'
  ]);

  // TLDs accepted when detecting bare domains (no scheme) in free text.
  const BARE_TLDS = new Set([
    'com', 'net', 'org', 'io', 'co', 'app', 'dev', 'info', 'biz', 'me', 'us', 'uk', 'de', 'ru', 'cn',
    'ai', 'gov', 'edu', 'live', 'online', 'site', 'shop', 'store', 'help', 'club', 'pro', 'tv',
    'cc', 'ly', 'gg', 'to', 'so', 'in', 'ca', 'au', 'fr', 'es', 'it', 'nl', 'br', 'jp', 'xyz',
    'top', 'click', 'link', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'support', 'icu', 'buzz',
    'cam', 'sbs', 'cyou', 'rest', 'fit', 'loan', 'work', 'monster', 'finance', 'money', 'wallet',
    'exchange', 'network', 'cloud', 'tech', 'space', 'website', 'page', 'world', 'today', 'news',
    'cfd', 'bond', 'lat', 'win', 'vip', 'id', 'at'
  ]);

  // Work caps so a message stuffed with thousands of links/addresses stays
  // fast. Everything beyond the cap is still extracted but not scored.
  const MAX_URLS = 300;
  const MAX_ADDRESSES = 200;
  const MAX_LINK_PAIRS = 300;
  const MAX_NAME_LENGTH = 512;

  const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go']);

  // Brand-adjacent words used to build phishing hostnames: paypal-login, appleid-verify.
  const LURE_WORDS = [
    'login', 'signin', 'secure', 'security', 'verify', 'verification', 'account', 'accounts',
    'support', 'help', 'update', 'service', 'services', 'wallet', 'id', 'auth', 'billing',
    'refund', 'claim', 'reward', 'rewards', 'airdrop', 'bonus', 'official', 'team', 'online',
    'web', 'app', 'portal', 'recovery', 'unlock', 'validate', 'sync', 'connect', 'gift', 'promo'
  ];

  // Characters commonly substituted to imitate letters.
  const ASCII_HOMOGLYPHS = [
    [/rn/g, 'm'], [/vv/g, 'w'], [/0/g, 'o'], [/1/g, 'l'], [/3/g, 'e'], [/4/g, 'a'],
    [/5/g, 's'], [/7/g, 't'], [/8/g, 'b'], [/9/g, 'g'], [/\$/g, 's'], [/@/g, 'a']
  ];
  const UNICODE_CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
    'ԁ': 'd', 'ѕ': 's', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g', 'ո': 'n', 'ս': 'u',
    'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'κ': 'k', 'ι': 'i', 'ε': 'e', 'υ': 'u',
    'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'é': 'e', 'è': 'e', 'ê': 'e',
    'ë': 'e', 'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o',
    'õ': 'o', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c', 'ñ': 'n', 'ı': 'i', 'ł': 'l'
  };

  // ------------------------------------------------------------- Helpers
  // Convert any input to a string without throwing (null-prototype objects,
  // symbols and objects whose toString throws would otherwise crash String()).
  function toText(v) {
    if (typeof v === 'string') return v;
    if (v === null || v === undefined) return '';
    try {
      return String(v);
    } catch (e) {
      return '';
    }
  }

  function toList(v) {
    if (v === null || v === undefined) return [];
    if (Array.isArray(v)) return v;
    if (typeof v === 'string') return v.split(',').map((x) => x.trim()).filter(Boolean);
    return [];
  }

  function safeDecode(s) {
    try {
      return decodeURIComponent(s);
    } catch (e) {
      return s;
    }
  }

  function makeReason(id, category, weight, message, evidence) {
    const r = { id, category, weight, message };
    if (evidence !== undefined && evidence !== null && evidence !== '') r.evidence = toText(evidence).slice(0, 200);
    return r;
  }

  function registrableDomain(host) {
    const labels = host.split('.').filter(Boolean);
    if (labels.length <= 2) return labels.join('.');
    const tld = labels[labels.length - 1];
    const sld = labels[labels.length - 2];
    if (tld.length === 2 && SECOND_LEVEL.has(sld)) return labels.slice(-3).join('.');
    return labels.slice(-2).join('.');
  }

  function isIPv4(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) && host.split('.').every((n) => Number(n) <= 255);
  }

  function skeleton(str) {
    let out = '';
    for (const ch of str.toLowerCase()) out += UNICODE_CONFUSABLES[ch] || ch;
    for (const [re, rep] of ASCII_HOMOGLYPHS) out = out.replace(re, rep);
    return out;
  }

  function scriptsIn(str) {
    const s = new Set();
    for (const ch of str) {
      if (/[a-z]/i.test(ch)) s.add('latin');
      else if (/[\u0400-\u04FF\u0500-\u052F]/.test(ch)) s.add('cyrillic');
      else if (/[\u0370-\u03FF]/.test(ch)) s.add('greek');
      else if (/[\u0530-\u058F]/.test(ch)) s.add('armenian');
      else if (/[\u00C0-\u024F]/.test(ch)) s.add('latin');
      else if (ch.charCodeAt(0) > 127 && /\p{L}/u.test(ch)) s.add('other');
    }
    return s;
  }

  function isOfficial(brand, regDomain) {
    return brand.official.includes(regDomain);
  }

  function tokenMatchesBrand(token, brandName) {
    if (token === brandName) return true;
    for (const w of LURE_WORDS) {
      if (token === brandName + w || token === w + brandName) return true;
    }
    return false;
  }

  // Classify how a registrable label relates to a brand name.
  // Returns 'homoglyph' | 'embedded' | 'typo' | null.
  function classifyLabel(label, tokens, brand) {
    const b = brand.name;
    const candidates = tokens.length > 1 ? tokens.concat([label.replace(/-/g, '')]) : [label];
    for (const t of candidates) {
      const sk = skeleton(t);
      if (sk !== t && (sk === b || tokenMatchesBrand(sk, b))) return 'homoglyph';
    }
    for (const t of candidates) {
      if (t !== label || tokens.length === 1) {
        if (tokenMatchesBrand(t, b) && t !== label) return 'embedded';
        if (t === label && t !== b && tokenMatchesBrand(t, b)) return 'embedded';
      }
    }
    if (tokens.length > 1 && tokens.includes(b)) return 'embedded';
    if (brand.fuzzy !== false && b.length >= 5) {
      const limit = b.length >= 9 ? 2 : 1;
      for (const t of candidates) {
        if (t === b) continue;
        if (Math.abs(t.length - b.length) > limit) continue;
        if (Math.min(P.editDistance(t, b), P.editDistance(skeleton(t), b)) <= limit) return 'typo';
      }
    }
    return null;
  }

  // ------------------------------------------------------------ URL checks
  function normalizeUrlInput(raw) {
    let s = toText(raw).trim();
    s = s.replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.');
    if (/^(javascript|data|vbscript):/i.test(s)) return { scheme: s.split(':')[0].toLowerCase(), raw: s };
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
    return { raw: s };
  }

  function rawHostOf(urlString) {
    const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(urlString);
    if (!m) return '';
    let authority = m[1];
    const at = authority.lastIndexOf('@');
    if (at >= 0) authority = authority.slice(at + 1);
    return authority.replace(/:\d+$/, '');
  }

  function analyzeUrl(input, opts) {
    const options = opts || {};
    const reasons = [];
    const norm = normalizeUrlInput(input);
    const result = { input: toText(input), reasons, score: 0 };

    if (norm.scheme) {
      reasons.push(makeReason('url.script_scheme', 'url', 40,
        'Link uses a "' + norm.scheme + ':" scheme, which can run code or hide content instead of opening a web page.', input));
      result.score = 40;
      return result;
    }

    let u;
    try {
      u = new URL(norm.raw);
    } catch (e) {
      result.error = 'unparseable URL';
      return result;
    }

    const host = u.hostname.replace(/\.$/, '').toLowerCase();
    const rawHost = rawHostOf(norm.raw);
    const unicodeHost = P.punycodeDecodeHost(host);
    const reg = registrableDomain(host);
    const labels = host.split('.');
    const tld = labels[labels.length - 1];
    result.host = host;
    if (unicodeHost !== host) result.displayHost = unicodeHost;
    result.registrableDomain = reg;

    // DNS names are at most 253 characters; anything longer is malformed.
    if (host.length > 253) {
      reasons.push(makeReason('url.overlong_host', 'url', 20,
        'Host name is longer than DNS allows (' + host.length + ' characters), so the link is malformed or obfuscated.', host.slice(0, 60)));
      result.score = 20;
      return result;
    }

    // Userinfo trick: https://paypal.com@evil.example/
    if (u.username || u.password) {
      const userinfo = safeDecode(u.username + (u.password ? ':' + u.password : ''));
      const looksLikeDomain = /[a-z0-9-]+\.[a-z]{2,}/i.test(userinfo);
      reasons.push(makeReason('url.userinfo', 'url', looksLikeDomain ? 45 : 30,
        'Text before "@" in the link (' + userinfo + ') is not where it goes; the real destination is ' + host + '.', input));
    }

    // IP-literal hosts.
    if (host.startsWith('[') || isIPv4(host)) {
      reasons.push(makeReason('url.ip_host', 'url', 25,
        'Link points to a raw IP address (' + host + ') instead of a named website.', input));
      if (/^(0x[0-9a-f]+|\d{8,}|0\d+)(\.|$)/i.test(rawHost)) {
        reasons.push(makeReason('url.ip_obfuscated', 'url', 15,
          'The IP address is written in an unusual numeric form (' + rawHost + ') to disguise it.', input));
      }
      result.score = sumWeights(reasons);
      return result;
    }

    // Punycode / homograph.
    const hasPunycode = labels.some((l) => l.startsWith('xn--'));
    let homographHit = null;
    if (hasPunycode) {
      const scripts = scriptsIn(unicodeHost.replace(/[.\-0-9]/g, ''));
      const sk = skeleton(unicodeHost);
      for (const brand of BRANDS) {
        const skReg = registrableDomain(sk);
        const skLabel = skReg.split('.')[0];
        if (skLabel === brand.name || sk.split('.').some((l) => l === brand.name)) {
          if (!isOfficial(brand, reg)) homographHit = brand;
          break;
        }
      }
      if (homographHit) {
        reasons.push(makeReason('url.homograph_brand', 'url', 55,
          'Domain "' + unicodeHost + '" uses look-alike characters to imitate ' + homographHit.name + '.', host));
      } else if (scripts.size > 1) {
        reasons.push(makeReason('url.mixed_script', 'url', 35,
          'Domain mixes alphabets (' + Array.from(scripts).join(', ') + '): "' + unicodeHost + '". This is a common homograph trick.', host));
      } else {
        reasons.push(makeReason('url.punycode', 'url', 10,
          'Domain uses internationalized (punycode) characters: "' + unicodeHost + '". Often legitimate, but check carefully.', host));
      }
    }

    // Brand look-alikes.
    if (!homographHit) {
      const regLabel = reg.split('.')[0];
      const subLabels = labels.slice(0, labels.length - reg.split('.').length).filter((l) => l !== 'www');
      let brandHit = false;
      for (const brand of BRANDS) {
        if (isOfficial(brand, reg)) { brandHit = true; break; }
      }
      if (!brandHit) {
        const regTokens = regLabel.split('-').filter(Boolean);
        for (const brand of BRANDS) {
          const b = brand.name;
          // Exact brand name on a non-official registrable domain.
          if (regLabel === b) {
            const cc = tld.length === 2 || SECOND_LEVEL.has(reg.split('.')[1]);
            if (!cc || SUSPICIOUS_TLDS.has(tld)) {
              reasons.push(makeReason('url.brand_unofficial_tld', 'url', 30,
                'Uses the name "' + b + '" on ' + reg + ', which is not a known official ' + b + ' domain.', host));
              break;
            }
            continue;
          }
          const hit = classifyLabel(regLabel, regTokens, brand);
          if (hit === 'homoglyph') {
            reasons.push(makeReason('url.lookalike_homoglyph', 'url', 50,
              'Domain ' + reg + ' imitates "' + b + '" using look-alike characters.', host));
            break;
          }
          if (hit === 'embedded') {
            reasons.push(makeReason('url.brand_embedded', 'url', 40,
              'Domain ' + reg + ' combines "' + b + '" with other words but is not an official ' + b + ' domain.', host));
            break;
          }
          if (hit === 'typo') {
            reasons.push(makeReason('url.lookalike_typo', 'url', 40,
              'Domain ' + reg + ' is one or two characters away from "' + b + '" (possible typosquat).', host));
            break;
          }
          // Brand in the subdomain: paypal.com.account-check.xyz
          if (subLabels.some((l) => {
            const t = l.split('-').filter(Boolean);
            return t.some((x) => tokenMatchesBrand(x, b) || tokenMatchesBrand(skeleton(x), b));
          })) {
            reasons.push(makeReason('url.brand_in_subdomain', 'url', 40,
              'The name "' + b + '" appears only in the subdomain; the real site is ' + reg + '.', host));
            break;
          }
        }
      }
    }

    // Excessive subdomains.
    const subCount = labels.length - reg.split('.').length - (labels[0] === 'www' ? 1 : 0);
    if (subCount >= 4) {
      reasons.push(makeReason('url.many_subdomains', 'url', subCount >= 6 ? 20 : 12,
        'Link has ' + subCount + ' levels of subdomains, which can bury the real domain.', host));
    }

    // Suspicious TLD.
    if (SUSPICIOUS_TLDS.has(tld)) {
      reasons.push(makeReason('url.suspicious_tld', 'url', 12,
        'Top-level domain ".' + tld + '" is cheap and shows up a lot in abuse reports.', host));
    }

    // URL shorteners.
    if (SHORTENERS.has(reg) || SHORTENERS.has(host)) {
      reasons.push(makeReason('url.shortener', 'url', 15,
        'Link shortener (' + host + ') hides the real destination.', host));
    }

    // Plain http (minor signal).
    if (u.protocol === 'http:' && options.explicitScheme) {
      reasons.push(makeReason('url.no_tls', 'url', 5, 'Link does not use HTTPS.', host));
    }

    // Credential-ish path combined with any other URL signal.
    if (reasons.some((r) => r.id !== 'url.no_tls') && /(login|signin|verify|wallet|seed|recover|unlock|validate|connect)/i.test(u.pathname + u.search)) {
      reasons.push(makeReason('url.credential_path', 'url', 8,
        'Path contains a login/wallet keyword on an already suspicious domain.', u.pathname));
    }

    result.score = Math.min(100, sumWeights(reasons));
    return result;
  }

  function sumWeights(reasons) {
    return reasons.reduce((a, r) => a + r.weight, 0);
  }

  // --------------------------------------------------------- URL extraction
  function extractUrls(input) {
    const text = toText(input);
    const found = [];
    // Per-character coverage map: overlap checks cost O(match length)
    // instead of O(number of matches so far).
    const covered = new Uint8Array(text.length + 1);
    const overlaps = (s, e) => {
      for (let i = s; i < e; i++) if (covered[i]) return true;
      return false;
    };
    const push = (value, start, explicit) => {
      value = value.replace(/[.,;:!?'")\]}>]+$/, '');
      const end = start + value.length;
      if (overlaps(start, end)) return;
      covered.fill(1, start, end);
      found.push({ value, start, end, explicitScheme: explicit });
    };
    let m;
    const reScheme = /\b(?:https?|hxxps?|ftp):\/\/[^\s<>"'`\[\]]+/gi;
    while ((m = reScheme.exec(text))) push(m[0], m.index, true);
    const reScript = /\b(?:javascript|data|vbscript):[^\s<>"'`]+/gi;
    while ((m = reScript.exec(text))) push(m[0], m.index, true);
    const reWww = /\bwww\.[^\s<>"'`\[\]]+/gi;
    while ((m = reWww.exec(text))) push(m[0], m.index, false);
    // The lookbehind includes non-ASCII letters so a match can only start at a
    // real token boundary (otherwise every Cyrillic letter is a new start and
    // the scan goes quadratic); label count is capped at the DNS maximum.
    const reBare = /(?<![@\w.\-/\u00a1-\uffff])((?:[a-z0-9\u00a1-\uffff](?:[a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?\.){1,127}([a-z]{2,24}|xn--[a-z0-9-]+))(?::\d{2,5})?(?:\/[^\s<>"'`\[\]]*)?/giu;
    while ((m = reBare.exec(text))) {
      const tld = m[2].toLowerCase();
      if (!BARE_TLDS.has(tld) && !tld.startsWith('xn--')) continue;
      // Skip "e.g", file names and version numbers.
      if (/^\d+(\.\d+)+$/.test(m[1])) continue;
      push(m[0], m.index, false);
    }
    return found;
  }

  // Display text vs real link (markdown and HTML anchors).
  function findLinkMismatches(text) {
    const reasons = [];
    const pairs = [];
    let m;
    // Bounded, and the href may not contain brackets/parens, so text like
    // "[a]([a]([a](..." cannot make each "[" rescan the rest of the input.
    const reMd = /\[([^\[\]]{1,200})\]\(\s*([^()\[\]\s]{1,2048})\s*\)/g;
    while ((m = reMd.exec(text))) pairs.push({ display: m[1], href: m[2] });
    // HTML anchors are found with indexOf and bounded windows instead of one
    // backtracking regex (the old pattern took >20s on 100KB of '<a href="').
    const reOpen = /<a\b/gi;
    while ((m = reOpen.exec(text))) {
      const close = text.indexOf('>', m.index);
      if (close < 0) break;
      if (close - m.index > 2000) continue;
      const href = /\bhref\s*=\s*["']([^"']+)["']/i.exec(text.slice(m.index + 2, close));
      if (!href) continue;
      const after = text.slice(close + 1, close + 1 + 306);
      const end = /<\/a>/i.exec(after);
      if (!end || end.index > 300) continue;
      pairs.push({ display: after.slice(0, end.index).replace(/<[^>]{0,2000}>/g, ''), href: href[1] });
      reOpen.lastIndex = close + 1;
    }
    for (const p of pairs.slice(0, MAX_LINK_PAIRS)) {
      const shown = extractUrls(p.display)[0];
      if (!shown) continue;
      let shownHost, realHost;
      try {
        shownHost = new URL(normalizeUrlInput(shown.value).raw).hostname.toLowerCase();
        realHost = new URL(normalizeUrlInput(p.href).raw).hostname.toLowerCase();
      } catch (e) {
        if (/^(javascript|data|vbscript):/i.test(p.href)) {
          reasons.push(makeReason('url.display_mismatch', 'url', 45,
            'Link text shows "' + shown.value + '" but actually runs a ' + p.href.split(':')[0] + ': link.', p.href));
        }
        continue;
      }
      if (registrableDomain(shownHost) !== registrableDomain(realHost)) {
        reasons.push(makeReason('url.display_mismatch', 'url', 45,
          'Link text shows "' + shownHost + '" but actually goes to "' + realHost + '".', p.href));
      }
    }
    return reasons;
  }

  // ------------------------------------------------------- Crypto addresses
  function checkEthChecksum(address) {
    const hex = address.slice(2);
    if (!/^[0-9a-fA-F]{40}$/.test(hex)) return { valid: false, reason: 'not 40 hex characters' };
    if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) {
      return { valid: true, checksummed: false };
    }
    const hash = P.toHex(P.keccak256(hex.toLowerCase()));
    for (let i = 0; i < 40; i++) {
      const c = hex[i];
      if (/[a-f]/.test(c) && parseInt(hash[i], 16) >= 8) return { valid: false, checksummed: true };
      if (/[A-F]/.test(c) && parseInt(hash[i], 16) < 8) return { valid: false, checksummed: true };
    }
    return { valid: true, checksummed: true };
  }

  function toEthChecksum(address) {
    const hex = address.slice(2).toLowerCase();
    const hash = P.toHex(P.keccak256(hex));
    let out = '0x';
    for (let i = 0; i < 40; i++) out += parseInt(hash[i], 16) >= 8 ? hex[i].toUpperCase() : hex[i];
    return out;
  }

  function checkBase58Check(str) {
    const bytes = P.base58Decode(str);
    if (!bytes || bytes.length < 5) return null;
    const payload = bytes.slice(0, -4);
    const check = bytes.slice(-4);
    const h = P.sha256(P.sha256(payload));
    const ok = h[0] === check[0] && h[1] === check[1] && h[2] === check[2] && h[3] === check[3];
    return { ok, version: payload[0], length: bytes.length };
  }

  function analyzeAddress(addr) {
    const a = toText(addr).trim();
    // Ethereum / EVM
    if (/^0x[0-9a-fA-F]+$/.test(a)) {
      if (a.length !== 42) {
        return { input: a, chain: 'evm', valid: false, note: 'EVM addresses are 0x + 40 hex characters; this has ' + (a.length - 2) + '.' };
      }
      const r = checkEthChecksum(a);
      if (!r.valid) {
        return { input: a, chain: 'evm', valid: false, checksummed: true, note: 'EIP-55 checksum does not match. The address may contain a typo or have been altered.', expected: toEthChecksum(a) };
      }
      return { input: a, chain: 'evm', valid: true, checksummed: r.checksummed, note: r.checksummed ? 'Valid EIP-55 checksum.' : 'Valid format, but no checksum (all one case), so typos cannot be detected.' };
    }
    // Bitcoin bech32 / bech32m
    if (/^(bc1|tb1)/i.test(a)) {
      const d = P.bech32Decode(a);
      if (!d || (d.hrp !== 'bc' && d.hrp !== 'tb') || d.data.length < 1) {
        return { input: a, chain: 'bitcoin', valid: false, note: 'Bech32 checksum or format invalid.' };
      }
      const ver = d.data[0];
      const prog = P.convertBits(d.data.slice(1), 5, 8, false);
      const okEnc = (ver === 0 && d.encoding === 'bech32') || (ver > 0 && d.encoding === 'bech32m');
      const okLen = prog && prog.length >= 2 && prog.length <= 40 && (ver !== 0 || prog.length === 20 || prog.length === 32);
      if (!okEnc || !okLen || ver > 16) {
        return { input: a, chain: 'bitcoin', valid: false, note: 'Bech32 address has an invalid witness version/program.' };
      }
      return { input: a, chain: 'bitcoin', valid: true, network: d.hrp === 'bc' ? 'mainnet' : 'testnet', note: 'Valid ' + d.encoding + ' (SegWit v' + ver + ') address.' };
    }
    // Base58: Bitcoin legacy/P2SH or Solana
    if (/^[1-9A-HJ-NP-Za-km-z]{25,44}$/.test(a)) {
      const bytes = P.base58Decode(a);
      if (bytes && bytes.length === 25) {
        const c = checkBase58Check(a);
        if (c && c.ok && (c.version === 0x00 || c.version === 0x05)) {
          return { input: a, chain: 'bitcoin', valid: true, network: 'mainnet', note: c.version === 0 ? 'Valid legacy (P2PKH) address.' : 'Valid P2SH address.' };
        }
        if (c && c.ok && (c.version === 0x6f || c.version === 0xc4)) {
          return { input: a, chain: 'bitcoin', valid: true, network: 'testnet', note: 'Valid testnet address.' };
        }
        if (/^[13]/.test(a)) {
          return { input: a, chain: 'bitcoin', valid: false, note: 'Looks like a Bitcoin address but the Base58Check checksum fails (typo or altered).' };
        }
        return null;
      }
      if (bytes && bytes.length === 32 && a.length >= 32) {
        return { input: a, chain: 'solana', valid: true, note: 'Valid Solana address format (32-byte base58). Format only: this does not show who owns it.' };
      }
    }
    return null;
  }

  // `max` limits how many candidates are validated (each costs a hash).
  function extractAddresses(input, max) {
    const text = toText(input);
    const limit = typeof max === 'number' && max >= 0 ? max : Infinity;
    const out = [];
    const seen = new Set();
    const add = (cand) => {
      if (seen.has(cand)) return;
      seen.add(cand);
      const r = analyzeAddress(cand);
      if (r) out.push(r);
    };
    let m;
    const reEth = /(?<![0-9a-zA-Z])0x[0-9a-fA-F]{36,44}(?![0-9a-zA-Z])/g;
    while (seen.size < limit && (m = reEth.exec(text))) add(m[0]);
    const reBech = /(?<![0-9a-zA-Z])(?:bc1|tb1)[02-9ac-hj-np-z]{6,87}(?![0-9a-zA-Z])/gi;
    while (seen.size < limit && (m = reBech.exec(text))) add(m[0]);
    const reB58 = /(?<![0-9a-zA-Z])[1-9A-HJ-NP-Za-km-z]{25,44}(?![0-9a-zA-Z])/g;
    while (seen.size < limit && (m = reB58.exec(text))) {
      if (/^(bc1|tb1)/i.test(m[0])) continue;
      if (!/[0-9]/.test(m[0]) && !/[A-Z]/.test(m[0].slice(1))) continue; // plain words
      add(m[0]);
    }
    if (seen.size >= limit) out.truncated = true;
    return out;
  }

  // ------------------------------------------------------- Message patterns
  // `negatable` patterns are ignored when preceded (same sentence) by
  // words like "never" / "do not", so safety advice is not flagged.
  const PATTERNS = [
    {
      id: 'msg.seed_phrase', category: 'credential-theft', weight: 50, negatable: true, critical: true,
      message: 'Asks for a wallet seed/recovery phrase or private key. Legitimate services never ask for these.',
      re: /\b(seed\s*phrase|recovery\s*phrase|secret\s*(recovery\s*)?phrase|mnemonic(\s*phrase)?|private\s*key|(12|24)[-\s]*words?(\s*phrase)?|wallet\s*phrase|backup\s*phrase)\b/i
    },
    {
      id: 'msg.wallet_validation', category: 'credential-theft', weight: 25, negatable: true,
      message: 'Asks you to "validate", "sync", "rectify" or "connect" your wallet, a common wallet-drainer lure.',
      re: /\b(validate|verify|sync(hroni[sz]e)?|rectify|restore|connect|unlock|re-?activate)\s+(your\s+)?(wallet|metamask|phantom|trust\s*wallet|ledger)\b/i
    },
    {
      id: 'msg.otp_request', category: 'credential-theft', weight: 30, negatable: true,
      message: 'Asks you to share a one-time / verification code. Those codes are only for you.',
      re: /\b(send|share|give|tell|read|forward|text)\s+(me|us|back)?\s*(the|your|that)?\s*(\d-digit\s*)?(verification|security|one[-\s]?time|login|2fa|otp|auth(entication)?|confirmation)\s*(code|pin|passcode)\b/i
    },
    {
      id: 'msg.password_request', category: 'credential-theft', weight: 35, negatable: true, critical: true,
      message: 'Asks for your password or login credentials.',
      re: /\b(send|share|give|confirm|provide|enter|dm|tell)\s+(me\s+|us\s+)?(your\s+)(password|passcode|login\s*details|credentials|pin)\b|\bwhat('?s|\s+is)\s+your\s+(password|passcode|login\s+password|pin)\b/i
    },
    {
      id: 'msg.secret_request', category: 'credential-theft', weight: 50, negatable: true, critical: true,
      message: 'Asks for a webhook URL, bearer token, API key, access token or similar secret. Never send these in a message.',
      re: /\b(send|share|paste|give|dm|post|provide|drop|forward|need|want|what('|\s+i)s)\s+(me|us|over|here)?\s*(your|the|ur|a|that)?\s*(slack\s+|discord\s+|github\s+|openai\s+|bot\s+|admin\s+)?(webhook(\s*url)?|bearer(\s*(token|key))?|api[\s_-]*keys?|access[\s_-]*tokens?|auth(entication)?[\s_-]*tokens?|secret[\s_-]*keys?|client[\s_-]*secret|session\s*(token|cookie)|xox[abp]-?\w*|tokens?)\b|\b(webhook\s*url|bearer\s*(token|key)|api[\s_-]*key|access[\s_-]*token|secret[\s_-]*key)\b[^.!?\n]{0,40}\b(dm|send|paste|share|give)\s+(it\s+)?(to\s+)?(me|us|here|over)\b/i
    },
    {
      id: 'msg.double_crypto', category: 'crypto-giveaway', weight: 45, negatable: true,
      message: 'Promises to double or multiply crypto you send. This is a classic giveaway scam.',
      re: /\b(double|triple|2x|3x|10x)\s+(your|any|the)?\s*(crypto|btc|bitcoin|eth|ether|ethereum|sol|solana|usdt|usdc|money|coins?|tokens?|investment|deposit)\b|\b(send|deposit)\b[^.!?\n]{0,60}\b(receive|get)\b[^.!?\n]{0,30}\b(double|twice|2x|back\s+\d+x)\b/i
    },
    {
      id: 'msg.send_to_receive', category: 'crypto-giveaway', weight: 40, negatable: true,
      message: 'Asks you to send crypto first in order to receive more (or to "unlock" a reward).',
      re: /\b(send|deposit|transfer)\s+(\d[\d.,]*\s*)?(btc|bitcoin|eth|ether|sol|usdt|usdc|bnb|crypto|coins?|tokens?)\b[^.!?\n]{0,80}\b(to\s+)?(receive|get|claim|unlock|qualify|participate|activate)\b/i
    },
    {
      id: 'msg.giveaway', category: 'crypto-giveaway', weight: 20,
      message: 'Mentions a giveaway, airdrop or free crypto reward.',
      re: /\b(airdrop|give-?away|free\s+(crypto|btc|bitcoin|eth|sol|nft|tokens?)|claim\s+(your\s+)?(reward|tokens?|airdrop|nft|bonus|allocation))\b/i
    },
    {
      id: 'msg.guaranteed_returns', category: 'investment-fraud', weight: 30, negatable: true,
      message: 'Promises guaranteed or unrealistic investment returns.',
      re: /\b(guaranteed\s+(profit|returns?|income)|risk[-\s]?free\s+(profit|returns?|investment)|\d{2,4}\s*%\s*(daily|weekly|per\s+day|a\s+day|per\s+week|roi)|(daily|weekly)\s+(roi|returns?)\s+of\s+\d+)/i
    },
    {
      id: 'msg.urgency', category: 'pressure', weight: 15,
      message: 'Creates time pressure ("act now", "within 24 hours").',
      re: /\b(act\s+now|urgent(ly)?|immediately|right\s+away|within\s+\d+\s*(hours?|hrs?|minutes?|mins?)|final\s+(notice|warning|reminder)|last\s+chance|expires?\s+(today|tonight|soon|in\s+\d+)|limited\s+time|only\s+\d+\s+(spots|slots|left)|(reply|respond|answer|confirm|dm\s+me)\s+(back\s+)?(fast|quick(ly)?|asap|now|right\s+now|in\s+the\s+next\s+\d+|within\s+\d+|before\s+(it'?s\s+gone|someone\s+else|the\s+deadline)))\b/i
    },
    {
      id: 'msg.account_threat', category: 'pressure', weight: 15,
      message: 'Threatens account suspension/closure or claims "unusual activity".',
      re: /\b(account|wallet|card|access)\s+(has\s+been\s+|will\s+be\s+|is\s+)?(suspended|locked|closed|disabled|restricted|frozen|terminated|compromised)\b|\bunusual\s+(sign-?in\s+)?activity\b|\bsuspicious\s+(login|activity)\s+(was\s+)?detected\b/i
    },
    {
      id: 'msg.verify_account', category: 'phishing', weight: 15,
      message: 'Asks you to verify/confirm/update your account or payment details via a link.',
      re: /\b(verify|confirm|update|re-?validate)\s+(your\s+)?(account|identity|billing|payment\s+(details|information|method)|card\s+details|information)\b/i
    },
    {
      id: 'msg.support_impersonation', category: 'impersonation', weight: 25, negatable: true,
      message: 'Claims to be support/help desk while steering you to a private chat, phone number, or DM.',
      re: /\b(support|help\s*desk|helpdesk|customer\s+care|customer\s+service|admin|moderator|security\s+team|refund\s+(department|team))\b[^.!?\n]{0,80}\b(whatsapp|telegram|dm\s+(me|us)|direct\s+message|message\s+(me|us)\s+privately|call\s+(us|now|this|the)|contact\s+(me|us)\s+(on|via|at))\b|\b(dm|message|contact)\s+(me|us)\b[^.!?\n]{0,40}\b(support|help|assist|resolve|fix)\b/i
    },
    {
      id: 'msg.fake_invoice', category: 'invoice-fraud', weight: 25,
      message: 'Unexpected invoice/renewal charge with a "call to cancel" or "if you did not authorize" hook.',
      re: /\b(subscription|membership|order|plan|invoice|payment)\b[^.!?\n]{0,60}\b(renewed|auto-?renew(al|ed)?|charged|has\s+been\s+processed|will\s+be\s+(charged|debited|deducted))\b[\s\S]{0,200}\b(did\s*n[o']?t\s+(authori[sz]e|make|order|request)|not\s+(you|authori[sz]ed)|to\s+cancel|cancel(lation)?\s+(call|contact)|call\s+(us|our|the))\b/i
    },
    {
      id: 'msg.tech_support_brand', category: 'invoice-fraud', weight: 10,
      message: 'Mentions brands frequently used in fake renewal/tech-support scams.',
      re: /\b(geek\s*squad|norton\s*(360|lifelock)?|mcafee|best\s*buy\s*protection)\b[^.!?\n]{0,80}\b(renew|charged|invoice|subscription)\b/i
    },
    {
      id: 'msg.prize', category: 'prize-lottery', weight: 25,
      message: 'Says you have won a prize/lottery or have been "selected".',
      re: /\b(you('ve|\s+have)?\s+(won|been\s+selected|been\s+chosen)|congratulations[^.!?\n]{0,40}\b(winner|won|selected|prize)|lottery|sweepstakes?|jackpot|claim\s+your\s+(prize|winnings))\b/i
    },
    {
      id: 'msg.advance_fee', category: 'advance-fee', weight: 30,
      message: 'Advance-fee pattern: large sum or inheritance, unlocked by paying a fee first.',
      re: /\b(inheritance|next\s+of\s+kin|beneficiary|barrister|diplomat(ic)?\s+(bag|courier)|unclaimed\s+(funds|fund|estate)|(release|transfer)\s+(of\s+)?(the|your)\s+funds|(processing|clearance|transfer|customs|release|activation|withdrawal|unlock|gas)\s+fee|\d+(\.\d+)?\s*(million|m)\s*(usd|dollars|euros|gbp))\b/i
    },
    {
      id: 'msg.untraceable_payment', category: 'payment-method', weight: 30,
      message: 'Asks for payment by gift cards, Bitcoin ATM, wire, or similar hard-to-reverse methods.',
      re: /\b(gift\s*cards?|itunes\s*cards?|apple\s*cards?|google\s*play\s*cards?|steam\s*cards?|bitcoin\s*atm|crypto\s*atm|western\s*union|moneygram|send\s+the\s+card\s+numbers?|scratch\s+off\s+the\s+back)\b/i
    },
    {
      id: 'msg.secrecy', category: 'pressure', weight: 10,
      message: 'Asks you to keep it secret / not tell anyone (including your bank).',
      re: /\b(do\s*n[o']?t|don't|do\s+not)\s+(tell|inform|share\s+this\s+with)\s+(anyone|anybody|your\s+(bank|family|friends))|keep\s+(this|it)\s+(confidential|secret|between\s+us)\b/i
    },
    {
      id: 'msg.remote_access', category: 'impersonation', weight: 25, negatable: true,
      message: 'Asks you to install remote-access software (AnyDesk, TeamViewer...).',
      re: /\b(install|download|open|run)\b[^.!?\n]{0,40}\b(anydesk|teamviewer|ultraviewer|rustdesk|supremo|quick\s*assist|screenconnect)\b/i
    }
  ];

  // Swarm / team-chat DM ruleset, enabled with { swarm: true } or when sender
  // metadata is supplied. Targets spoofed DMs in Slack-style workspaces.
  const SWARM_PATTERNS = [
    {
      id: 'swarm.private_offer', category: 'swarm-dm', weight: 35,
      message: 'Offers to steal, pass, keep or reverse a task/reward/points and asks you to handle it privately.',
      re: /\b(steal|pass|keep|reverse|transfer|swap|flip|split)\b[^.!?\n]{0,60}\b(task|bounty|reward|points?|payout|claim|slot|credit|allocation)s?\b[^\n]{0,120}\b(privately|in\s+private|in\s+(a\s+)?dm|via\s+dm|dm\s+me|quietly|off[-\s]?channel|off\s+the\s+record|between\s+us|don'?t\s+(post|mention|tell)|outside\s+(the\s+)?(channel|thread))\b|\b(privately|dm\s+me|between\s+us|quietly)\b[^\n]{0,120}\b(steal|pass|keep|reverse)\b[^.!?\n]{0,60}\b(task|bounty|reward|points?|payout|claim|slot)s?\b/i
    },
    {
      id: 'swarm.authority_claim', category: 'impersonation', weight: 15,
      message: 'Message claims to come from the Mothership/admin/support team. Confirm through the official channel.',
      re: /\b(this\s+is|from|i'?m|i\s+am|on\s+behalf\s+of|message\s+from)\s+(the\s+)?(mothership|admin(istrator)?s?|support(\s+team)?|mod(erator)?s?|swarm\s+(lead|admin|ops)|ops\s+team|security\s+team)\b/i
    },
    {
      id: 'swarm.bypass_channel', category: 'swarm-dm', weight: 15,
      message: 'Asks you to skip the normal channel/thread or not verify with others.',
      re: /\b(don'?t|do\s+not|no\s+need\s+to)\s+(post|reply|announce|mention|check|verify|confirm)\s+(this\s+)?(in|on|with)\s+(the\s+)?(channel|thread|#\w+|team|others|admins?|mothership)\b/i
    }
  ];

  const DEFAULT_PROTECTED_NAMES = ['mothership', 'admin', 'support', 'moderator', 'swarmlead'];

  function normName(s) {
    return skeleton(toText(s).normalize('NFKC')).replace(/[^a-z0-9]/g, '');
  }

  // Sender checks. Nothing is hardcoded: the caller supplies verifiedIds
  // (member IDs allowed to use protected names) and optionally protectedNames.
  function checkSender(sender, options) {
    const reasons = [];
    if (!sender || typeof sender !== 'object') return reasons;
    options = options || {};
    const name = toText(sender.displayName || sender.name || '').slice(0, MAX_NAME_LENGTH);
    const id = toText(sender.memberId || sender.id || '');
    const verifiedIds = toList(options.verifiedIds).map(toText);
    const pn = options.protectedNames === undefined || options.protectedNames === null
      ? DEFAULT_PROTECTED_NAMES : toList(options.protectedNames);
    const protectedNames = pn.map((n) => normName(n)).filter(Boolean);
    const isVerified = id && verifiedIds.includes(String(id));
    // Fold l/i so "Adm1n" (skeleton "admln") and "mothershlp" compare equal.
    const fold = (x) => x.replace(/l/g, 'i');
    const n = fold(normName(name));
    if (!n || isVerified) return reasons;
    for (const p0 of protectedNames) {
      const p = fold(p0);
      let kind = null;
      if (n === p) kind = 'exact';
      else if (n.includes(p) || (p.length >= 6 && P.editDistance(n, p) <= (p.length >= 9 ? 2 : 1))) kind = 'lookalike';
      else if (p.length >= 6) {
        // e.g. "mothershipswarm" vs "mothership": prefix/suffix padding
        const core = n.replace(/(swarm|team|official|hq|bot|support|admin|help|real|the)+/g, '');
        if (core && P.editDistance(core, p) <= 1) kind = 'lookalike';
      }
      if (kind) {
        const unknownIds = verifiedIds.length === 0;
        const weight = unknownIds ? 20 : (kind === 'exact' ? 45 : 50);
        const msg = unknownIds
          ? 'Sender name "' + name + '" resembles protected name "' + p0 + '", and no verified-ID list was supplied, so it cannot be confirmed.'
          : 'Sender "' + name + '"' + (id ? ' (' + id + ')' : '') + ' uses or imitates protected name "' + p + '" but its member ID is not in the verified list.';
        reasons.push(makeReason('swarm.sender_impersonation', 'impersonation', weight, msg, name));
        break;
      }
    }
    return reasons;
  }

  const NEGATION_RE = /\b(never|not|don't|dont|do\s+not|won't|will\s+not|nobody|no\s+one|no\s+legitimate|beware|warning|avoid|scam(mers?)?\s+(will|may|often|might))\b/i;

  function sentenceBefore(text, index) {
    const start = Math.max(0, index - 80);
    const chunk = text.slice(start, index);
    const parts = chunk.split(/[.!?\n]/);
    return parts[parts.length - 1];
  }

  function matchPatterns(text, list) {
    const reasons = [];
    for (const p of list || PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
      let m;
      let hit = null;
      while ((m = re.exec(text))) {
        if (p.negatable && NEGATION_RE.test(sentenceBefore(text, m.index))) continue;
        hit = m;
        break;
      }
      if (hit) {
        const r = makeReason(p.id, p.category, p.weight, p.message, hit[0].trim());
        if (p.critical) r.critical = true;
        reasons.push(r);
      }
    }
    return reasons;
  }

  // ------------------------------------------------------------- Analyze
  function levelFor(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }

  function analyze(input, opts) {
    const options = opts || {};
    const text = toText(input).slice(0, options.maxLength || 100000);
    const reasons = [];

    // URLs
    const urlHits = extractUrls(text);
    const urls = urlHits.slice(0, MAX_URLS).map((h) => {
      const r = analyzeUrl(h.value, { explicitScheme: h.explicitScheme });
      for (const reason of r.reasons) reasons.push(reason);
      return r;
    });
    for (const r of findLinkMismatches(text)) reasons.push(r);

    // Addresses (scan text with URLs removed to avoid path fragments)
    // Built in one pass; rebuilding the string per URL was O(n * urls).
    const parts = [];
    let pos = 0;
    for (const h of urlHits.slice().sort((a, b) => a.start - b.start)) {
      if (h.start < pos) continue;
      parts.push(text.slice(pos, h.start), ' '.repeat(h.end - h.start));
      pos = h.end;
    }
    parts.push(text.slice(pos));
    const scrubbed = parts.join('');
    const addressCandidates = extractAddresses(scrubbed, MAX_ADDRESSES);
    const addresses = addressCandidates.slice();
    for (const a of addresses) {
      if (!a.valid) {
        reasons.push(makeReason('crypto.invalid_address', 'crypto', 15,
          'Crypto address fails validation: ' + a.note, a.input));
      }
    }

    // Message patterns
    for (const r of matchPatterns(text)) reasons.push(r);

    // Swarm / team-chat DM ruleset
    const swarm = !!(options.swarm || options.sender);
    if (swarm) {
      for (const r of matchPatterns(text, SWARM_PATTERNS)) reasons.push(r);
      for (const r of checkSender(options.sender, options)) reasons.push(r);
      const known = toList(options.knownAddresses).map((a) => toText(a).toLowerCase());
      for (const a of addresses) {
        if (!known.includes(a.input.toLowerCase())) {
          reasons.push(makeReason('swarm.unknown_address', 'crypto', 10,
            'Wallet address in a DM is not in your known-addresses list. Verify it through an official channel.', a.input));
        }
      }
    }

    // Funds request: an address plus an instruction to send.
    const sendRe = /\b(send|transfer|deposit|pay|wire|forward)\b[^.!?\n]{0,120}/i;
    const sendMatch = sendRe.exec(text);
    if (addresses.length && sendMatch && !NEGATION_RE.test(sentenceBefore(text, sendMatch.index))) {
      reasons.push(makeReason('crypto.funds_request', 'crypto', 25,
        'Asks you to send funds to a crypto address. Crypto transfers are generally irreversible.', sendMatch[0].trim()));
    }

    // Deduplicate by id+evidence and score.
    const seen = new Set();
    const unique = [];
    for (const r of reasons) {
      const k = r.id + '|' + (r.evidence || '');
      if (seen.has(k)) continue;
      seen.add(k);
      unique.push(r);
    }

    // Per-id cap: the same rule firing on several URLs counts once at full
    // weight and then at half weight.
    const byId = {};
    let score = 0;
    for (const r of unique.slice().sort((a, b) => b.weight - a.weight)) {
      byId[r.id] = (byId[r.id] || 0) + 1;
      score += byId[r.id] === 1 ? r.weight : Math.ceil(r.weight / 2);
    }
    const categories = new Set(unique.map((r) => r.category));
    if (categories.size >= 3) {
      score += 10;
      unique.push(makeReason('combo.multiple_categories', 'combination', 10,
        'Several independent warning signs appear together (' + Array.from(categories).join(', ') + ').'));
    }
    const critical = unique.some((r) => r.critical);
    if (critical) score = Math.max(score, 90);
    score = Math.max(0, Math.min(100, score));
    unique.sort((a, b) => (b.critical ? 1 : 0) - (a.critical ? 1 : 0) || b.weight - a.weight);

    const result = {
      score,
      level: levelFor(score),
      critical,
      ruleset: swarm ? 'default+swarm-dm' : 'default',
      reasons: unique,
      urls,
      addresses,
      engine: 'scamcheck/' + VERSION,
      disclaimer: DISCLAIMER
    };
    // Present only when a work cap was hit; the score then covers only the
    // first MAX_URLS links / MAX_ADDRESSES address candidates.
    if (urlHits.length > MAX_URLS || addressCandidates.truncated) {
      result.truncated = { urlsFound: urlHits.length, urlsAnalyzed: urls.length, addressLimitHit: !!addressCandidates.truncated };
    }
    return result;
  }

  return {
    VERSION,
    DISCLAIMER,
    analyze,
    analyzeUrl,
    analyzeAddress,
    checkEthChecksum,
    toEthChecksum,
    extractUrls,
    extractAddresses,
    registrableDomain,
    levelFor,
    checkSender,
    LIMITS: { MAX_URLS, MAX_ADDRESSES, MAX_LINK_PAIRS, MAX_NAME_LENGTH },
    DEFAULT_PROTECTED_NAMES,
    BRANDS,
    SHORTENERS,
    SUSPICIOUS_TLDS
  };
});
