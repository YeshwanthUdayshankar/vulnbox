// Zero-edit Node.js outbound HTTP/HTTPS preload hook for air-gapped mocking.
// Loaded via NODE_OPTIONS="--import=/workspace/.vulnbox_http_mock_preload.mjs"
// only when VULNBOX_MOCK_URL is set. Routes non-loopback fetch/http/https calls
// to 127.0.0.1:<mock_port> with X-VulnBox-Target-Host & X-VulnBox-Target-Path.

import http from 'node:http';
import https from 'node:https';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const mockUrlRaw = process.env.VULNBOX_MOCK_URL;

if (mockUrlRaw) {
  const mockUrl = new URL(mockUrlRaw);
  const mockHost = mockUrl.hostname || '127.0.0.1';
  const mockPort = Number(mockUrl.port || 18080);

  // 1. Hook globalThis.fetch
  if (typeof globalThis.fetch === 'function') {
    const origFetch = globalThis.fetch.bind(globalThis);
    globalThis.fetch = async (input, init = undefined) => {
      try {
        const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input?.url;
        if (raw && (raw.startsWith('http://') || raw.startsWith('https://'))) {
          const parsed = new URL(raw);
          if (!LOOPBACK.has(parsed.hostname.toLowerCase())) {
            const targetPath = `${parsed.pathname || '/'}${parsed.search || ''}`;
            const nextHeaders = new Headers(
              init?.headers || (typeof input === 'object' && input?.headers ? input.headers : undefined)
            );
            nextHeaders.set('X-VulnBox-Target-Host', parsed.host);
            nextHeaders.set('X-VulnBox-Target-Path', targetPath);
            const rerouted = `http://${mockHost}:${mockPort}${targetPath}`;
            return origFetch(rerouted, { ...(init || {}), headers: nextHeaders });
          }
        }
      } catch {
        // Fall through to original fetch on malformed URLs
      }
      return origFetch(input, init);
    };
  }

  // 2. Hook http.request / http.get / https.request / https.get
  const origHttpRequest = http.request.bind(http);
  const origHttpsRequest = https.request.bind(https);

  function normalizeArgs(urlOrOpts, maybeOpts, maybeCb) {
    let opts = {};
    let cb = maybeCb;
    if (typeof urlOrOpts === 'string' || urlOrOpts instanceof URL) {
      const parsed = new URL(String(urlOrOpts));
      opts = {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || undefined,
        path: `${parsed.pathname || '/'}${parsed.search || ''}`,
      };
      if (typeof maybeOpts === 'function') {
        cb = maybeOpts;
      } else if (maybeOpts && typeof maybeOpts === 'object') {
        opts = { ...opts, ...maybeOpts };
      }
    } else if (urlOrOpts && typeof urlOrOpts === 'object') {
      opts = { ...urlOrOpts };
      if (typeof maybeOpts === 'function') {
        cb = maybeOpts;
      }
    }
    return { opts, cb };
  }

  function wrapRequest(origFn, defaultMethod) {
    return function patchedRequest(urlOrOpts, maybeOpts, maybeCb) {
      const { opts, cb } = normalizeArgs(urlOrOpts, maybeOpts, maybeCb);
      const host = String(opts.hostname || opts.host || '').split(':')[0].toLowerCase();
      if (host && !LOOPBACK.has(host)) {
        const targetPath = opts.path || '/';
        const headers = { ...(opts.headers || {}) };
        headers['X-VulnBox-Target-Host'] = String(opts.host || opts.hostname);
        headers['X-VulnBox-Target-Path'] = targetPath;
        const reroutedOpts = {
          ...opts,
          protocol: 'http:',
          hostname: mockHost,
          host: mockHost,
          port: mockPort,
          path: targetPath,
          method: opts.method || defaultMethod || 'GET',
          headers,
        };
        delete reroutedOpts.agent;
        return origHttpRequest(reroutedOpts, cb);
      }
      return origFn(urlOrOpts, maybeOpts, maybeCb);
    };
  }

  http.request = wrapRequest(origHttpRequest, 'GET');
  http.get = (urlOrOpts, maybeOpts, maybeCb) => {
    const req = http.request(urlOrOpts, maybeOpts, maybeCb);
    req.end();
    return req;
  };
  https.request = wrapRequest(origHttpsRequest, 'GET');
  https.get = (urlOrOpts, maybeOpts, maybeCb) => {
    const req = https.request(urlOrOpts, maybeOpts, maybeCb);
    req.end();
    return req;
  };
}
