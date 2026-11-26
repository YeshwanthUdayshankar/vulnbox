import { EventEmitter } from "node:events";
import http from "node:http";

const responseCache = new Map();
const bus = new EventEmitter();
bus.setMaxListeners(0);

function storeItem(key) {
  const payload = Buffer.alloc(16384, 65);
  responseCache.set(key, payload);
  return responseCache.size;
}

const HANDLERS = {
  store: storeItem,
};

export function dispatchAction(action, key) {
  // Dynamic subscript dispatch — unresolved statically, resolved at runtime via V8 Inspector
  return HANDLERS[action](key);
}

export function registerRequestListener() {
  const payload = Buffer.alloc(16384, 66);
  bus.on("tick", () => payload.length);
  bus.emit("tick");
  return bus.listenerCount("tick");
}

export function createServer() {
  return http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://127.0.0.1");
    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }
    if (url.pathname === "/cache") {
      const k = url.searchParams.get("k") || "default";
      const count = dispatchAction("store", k);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ stored: k, count }));
      return;
    }
    if (url.pathname === "/listen") {
      const listeners = registerRequestListener();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ listeners }));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const host = process.env.HOST || "127.0.0.1";
  const port = Number(process.env.PORT || "8080");
  createServer().listen(port, host);
}
