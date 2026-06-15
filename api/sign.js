// api/sign.js — Vercel Serverless Function
// Holds your Storj credentials securely as environment variables.
// The frontend calls this to get presigned URLs and signed request headers.

const crypto = require('crypto');

const CONFIG = {
  accessKey: process.env.STORJ_ACCESS_KEY,
  secretKey: process.env.STORJ_SECRET_KEY,
  bucket:    process.env.STORJ_BUCKET,
  endpoint:  process.env.STORJ_ENDPOINT || 'https://gateway.storjshare.io',
  region:    'us-east-1',
};

// ── CORS helper ───────────────────────────────────────────────────────────────
function cors(res) {
  const origin = process.env.ALLOWED_ORIGIN || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
res.setHeader(
  'Access-Control-Allow-Headers',
  'Content-Type, x-admin-password'
);
}

function requireAdmin(req) {
  const password = req.headers['x-admin-password'];

  return (
    password &&
    password === process.env.ADMIN_PASSWORD
  );
}

// ── AWS Signature V4 helpers ──────────────────────────────────────────────────
function sha256hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function getDateStrings() {
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const date = `${now.getUTCFullYear()}${pad(now.getUTCMonth()+1)}${pad(now.getUTCDate())}`;
  const datetime = `${date}T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;
  return { date, datetime };
}

function encodeKey(key) {
  return key.split('/').map(s => encodeURIComponent(s)).join('/');
}

function getSigningKey(secretKey, date) {
  const kDate    = hmac('AWS4' + secretKey, date);
  const kRegion  = hmac(kDate, CONFIG.region);
  const kService = hmac(kRegion, 's3');
  return hmac(kService, 'aws4_request');
}

// ── Action: presigned GET URL (for download & share links) ───────────────────
function presignedGet(key, expiresIn = 3600 * 24 * 7) {
  const { date, datetime } = getDateStrings();
  const host = new URL(CONFIG.endpoint).host;
  const canonicalUri = `/${CONFIG.bucket}/${encodeKey(key)}`;
  const credentialScope = `${date}/${CONFIG.region}/s3/aws4_request`;

  const queryParams = new URLSearchParams({
    'X-Amz-Algorithm':     'AWS4-HMAC-SHA256',
    'X-Amz-Credential':    `${CONFIG.accessKey}/${credentialScope}`,
    'X-Amz-Date':          datetime,
    'X-Amz-Expires':       String(expiresIn),
    'X-Amz-SignedHeaders': 'host',
  });
  // Must be sorted
  queryParams.sort();
  const sortedQuery = queryParams.toString();

  const canonicalRequest = [
    'GET',
    canonicalUri,
    sortedQuery,
    `host:${host}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    datetime,
    credentialScope,
    sha256hex(canonicalRequest),
  ].join('\n');

  const signature = hmac(getSigningKey(CONFIG.secretKey, date), stringToSign).toString('hex');
  return `${CONFIG.endpoint}/${CONFIG.bucket}/${encodeKey(key)}?${sortedQuery}&X-Amz-Signature=${signature}`;
}

// ── Action: signed headers for PUT / DELETE / LIST ───────────────────────────
function signedHeaders({ method, key, contentType, payloadHash, extraQuery = {} }) {
  const { date, datetime } = getDateStrings();
  const host = new URL(CONFIG.endpoint).host;

  // For LIST (key is empty, request goes to bucket root)
  const canonicalUri = key ? `/${CONFIG.bucket}/${encodeKey(key)}` : `/${CONFIG.bucket}/`;

  const sortedQueryEntries = Object.entries(extraQuery)
    .sort(([a], [b]) => a.localeCompare(b));
  const sortedQuery = sortedQueryEntries
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');

  const hash = payloadHash || sha256hex('');

  const headersObj = {
    'host':                 host,
    'x-amz-content-sha256': hash,
    'x-amz-date':           datetime,
    ...(contentType ? { 'content-type': contentType } : {}),
  };
  const sortedHeaderKeys = Object.keys(headersObj).sort();
  const canonicalHeaders  = sortedHeaderKeys.map(k => `${k}:${headersObj[k]}`).join('\n') + '\n';
  const signedHeadersList = sortedHeaderKeys.join(';');

  const canonicalRequest = [method, canonicalUri, sortedQuery, canonicalHeaders, signedHeadersList, hash].join('\n');

  const credentialScope = `${date}/${CONFIG.region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', datetime, credentialScope, sha256hex(canonicalRequest)].join('\n');
  const signature = hmac(getSigningKey(CONFIG.secretKey, date), stringToSign).toString('hex');

  const authorization = `AWS4-HMAC-SHA256 Credential=${CONFIG.accessKey}/${credentialScope}, SignedHeaders=${signedHeadersList}, Signature=${signature}`;

  // Return everything the browser needs to make the actual request
  const responseHeaders = {
    'x-amz-content-sha256': hash,
    'x-amz-date':           datetime,
    'authorization':        authorization,
    ...(contentType ? { 'content-type': contentType } : {}),
  };

  const url = `${CONFIG.endpoint}/${CONFIG.bucket}/${key ? encodeKey(key) : ''}${sortedQuery ? '?' + sortedQuery : ''}`;
  return { url, headers: responseHeaders };
}

// ── Main handler ──────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!CONFIG.accessKey || !CONFIG.secretKey || !CONFIG.bucket) {
    return res.status(500).json({ error: 'Server credentials not configured' });
  }

  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  const { action, key, contentType, payloadHash, query: extraQuery, expiresIn } = body;

  try {
    switch (action) {
      // Frontend wants a presigned download URL
      case 'presign-get': {
        if (!key) return res.status(400).json({ error: 'key required' });
        const url = presignedGet(key, expiresIn);
        return res.status(200).json({ url });
      }

      // Frontend wants signed headers for a PUT upload
      case 'sign-put': {
        if (!key) return res.status(400).json({ error: 'key required' });
        const result = signedHeaders({ method: 'PUT', key, contentType, payloadHash });
        return res.status(200).json(result);
      }

      // Frontend wants signed headers for a DELETE
      case 'sign-delete': {
        if (!key) return res.status(400).json({ error: 'key required' });
        const result = signedHeaders({ method: 'DELETE', key, payloadHash: sha256hex('') });
        return res.status(200).json(result);
      }

      // Frontend wants signed headers for a LIST
      case 'sign-list': {
        const result = signedHeaders({ method: 'GET', key: '', extraQuery: extraQuery || {} });
        return res.status(200).json(result);
      }

      // Frontend wants signed headers to initiate multipart upload
      case 'sign-multipart-init': {
        if (!key) return res.status(400).json({ error: 'key required' });
        const result = signedHeaders({ method: 'POST', key, contentType, extraQuery: { uploads: '' } });
        return res.status(200).json(result);
      }

      // Frontend wants signed headers for a multipart part PUT
      case 'sign-multipart-part': {
        if (!key || !body.partNumber || !body.uploadId) return res.status(400).json({ error: 'key, partNumber, uploadId required' });
        const result = signedHeaders({ method: 'PUT', key, payloadHash, extraQuery: { partNumber: String(body.partNumber), uploadId: body.uploadId } });
        return res.status(200).json(result);
      }

      // Frontend wants signed headers to complete multipart upload
      case 'sign-multipart-complete': {
        if (!key || !body.uploadId) return res.status(400).json({ error: 'key, uploadId required' });
        const result = signedHeaders({ method: 'POST', key, contentType: 'application/xml', extraQuery: { uploadId: body.uploadId } });
        return res.status(200).json(result);
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
};
