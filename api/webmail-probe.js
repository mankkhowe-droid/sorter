// api/webmail-probe.js: Vercel serverless function that fingerprints the webmail platform of a domain.
// Optional: set an env var PROBE_TOKEN in Vercel and put "/api/webmail-probe?k=YOURSECRET" in the page's URL box.
const dns = require('dns');
const https = require('https');
const http = require('http');

const SIGS = {
  'Microsoft 365 (OWA)': ['login.microsoftonline.com', 'outlook.office.com', 'outlook.office365.com'],
  'Google Workspace': ['accounts.google.com'],
  'OWA (Exchange)': ['/owa/auth', 'x-owa-version', 'outlook web app', 'outlook on the web'],
  'GroupWise WebAccess': ['groupwise webaccess', '/gw/webacc', 'novell webaccess'],
  'Roundcube': ['rcmloginuser', 'roundcube', 'rcube_webmail'],
  'SquirrelMail': ['squirrelmail'],
  'Horde': ['horde_login', 'horde webmail', 'imp webmail'],
  'Zimbra': ['zimbra web client', 'zimbra collaboration'],
  'SOGo': ['sogo.js', '/sogo/so', '<title>sogo'],
  'cPanel Webmail': ['cpanel, inc', 'login to webmail', 'webmaillogin', 'cpsess'],
  'SnappyMail': ['snappymail'],
  'RainLoop': ['rainloop'],
  'AfterLogic': ['afterlogic'],
  'IceWarp': ['icewarp'],
  'Kerio Connect': ['kerio connect', 'kerio webmail'],
  'MDaemon WorldClient': ['worldclient', 'mdaemon'],
  'MailEnable': ['mailenable'],
  'Titan Webmail': ['titan.email'],
};

function isPublic(ip) {  // public IPv4 only (blocks SSRF to private/reserved ranges)
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !(n >= 0 && n <= 255))) return false;
  const [a, b] = p;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)));
}

function fetchOnce(u) {
  return new Promise(resolve => {
    let done = false;
    const fin = v => { if (!done) { done = true; resolve(v); } };
    const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    if (!['http:', 'https:'].includes(u.protocol) || ![80, 443, 2096, 8080, 8443].includes(port)) return fin(null);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: u.hostname, port, path: u.pathname + u.search, method: 'GET',
      rejectUnauthorized: false, timeout: 3000,
      headers: { 'user-agent': 'Mozilla/5.0 (webmail-probe)', accept: 'text/html,*/*' },
      lookup: (h, o, cb) => dns.lookup(h, { family: 4 }, (e, addr) => {  // pinned + validated, so DNS rebinding can't reach private IPs
        if (e || !isPublic(addr)) return cb(e || new Error('blocked'));
        return o && o.all ? cb(null, [{ address: addr, family: 4 }]) : cb(null, addr, 4);
      }),
    }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', c => { body += c; if (body.length > 200000) res.destroy(); });
      res.on('error', () => fin(null));
      res.on('close', () => fin({ code: res.statusCode, head: JSON.stringify(res.headers), body, location: res.headers.location || '' }));
    });
    req.on('timeout', () => { req.destroy(); fin(null); });
    req.on('error', () => fin(null));
    req.end();
  });
}

async function get(url) {
  let seen = url;
  for (let i = 0; i < 3; i++) {
    let u; try { u = new URL(url); } catch (e) { return null; }
    const r = await fetchOnce(u);
    if (!r) return null;
    if (r.code >= 300 && r.code < 400 && r.location) {
      try { url = new URL(r.location, u).toString(); } catch (e) { return null; }
      seen += ' ' + url;
      continue;
    }
    return { urls: seen, head: r.head, body: r.body };
  }
  return null;
}

function detect(r) {
  const t = (r.urls + ' ' + r.head + ' ' + r.body).toLowerCase();
  for (const [name, needles] of Object.entries(SIGS)) if (needles.some(n => t.includes(n))) return name;
  return '';
}

module.exports = async (req, res) => {
  const token = process.env.PROBE_TOKEN;
  if (token && req.query.k !== token) return res.status(403).json({ error: 'forbidden' });
  const d = String(req.query.d || '').trim().toLowerCase();
  if (!/^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$/.test(d)) return res.status(400).json({ error: 'bad domain' });
  const urls = [`https://webmail.${d}/`, `https://mail.${d}/`, `https://${d}/webmail/`, `https://${d}/owa/`, `https://${d}:2096/`];
  const results = await Promise.all(urls.map(get));  // parallel, to stay inside Vercel's function time limit
  res.setHeader('Cache-Control', 's-maxage=86400');
  for (let i = 0; i < urls.length; i++) {
    const name = results[i] && detect(results[i]);
    if (name) return res.json({ platform: name, url: urls[i] });
  }
  return res.json({ platform: '' });
};
