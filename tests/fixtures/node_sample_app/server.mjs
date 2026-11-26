import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const PUBLIC_DIR = path.join(__dirname, "public");

export const upstreamTlsOptions = {
  rejectUnauthorized: false,
};

export function readPublicFile(name) {
  const target = path.join(PUBLIC_DIR, name);
  return fs.readFileSync(target, "utf8");
}

export function createAppServer() {
  return http.createServer((req, res) => {
    const reqUrl = new URL(req.url || "/", "http://127.0.0.1");

    if (reqUrl.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    if (reqUrl.pathname === "/api/data") {
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ items: ["alpha", "beta"] }));
      return;
    }

    if (reqUrl.pathname === "/files") {
      const name = reqUrl.searchParams.get("name") || "";
      try {
        const body = readPublicFile(name);
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(body);
      } catch (err) {
        const status = String(err?.message || "").includes("escapes") ? 403 : 404;
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: String(err?.message || "not found") }));
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const host = process.env.HOST || "127.0.0.1";
  const port = Number(process.env.PORT || 8081);
  createAppServer().listen(port, host);
}
