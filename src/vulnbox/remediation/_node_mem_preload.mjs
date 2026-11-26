/**
 * Sandbox Node.js memory-probe preload loaded via:
 *   NODE_OPTIONS="--expose-gc --import file:///.../preload.mjs"
 * Responds to SIGUSR1 by forcing V8 GC, sampling HeapProfiler allocations, and
 * atomically writing JSON memory stats to VULNBOX_MEM_SNAP_FILE.
 */

import fs from "node:fs";
import inspector from "node:inspector";
import path from "node:path";
import { fileURLToPath } from "node:url";

const snapFile = process.env.VULNBOX_MEM_SNAP_FILE || "";
const workspace = process.env.VULNBOX_MEM_WORKSPACE || "";

if (snapFile) {
  const wsRoot = workspace ? path.resolve(workspace) : "";
  const session = new inspector.Session();
  session.connect();

  const postSync = (method, params = {}) => {
    let result = null;
    session.post(method, params, (err, res) => {
      if (!err) result = res;
    });
    return result;
  };

  postSync("HeapProfiler.enable");
  postSync("HeapProfiler.startSampling", { samplingInterval: 4096 });

  let seq = 0;
  let baselineByLoc = null;

  const toRel = (url) => {
    if (!url) return "";
    let fsPath = url;
    if (url.startsWith("file://")) {
      try {
        fsPath = fileURLToPath(url);
      } catch {
        return url;
      }
    }
    const resolved = path.resolve(fsPath);
    if (wsRoot && resolved.startsWith(wsRoot + path.sep)) {
      return resolved.slice(wsRoot.length + 1).replace(/\\/g, "/");
    }
    return url;
  };

  const collectAllocByLoc = () => {
    const res = postSync("HeapProfiler.getSamplingProfile");
    const totals = new Map();
    if (!res || !res.profile || !res.profile.head) return totals;

    const visit = (node, chain) => {
      const cf = node.callFrame || {};
      const rel = toRel(cf.url || "");
      const line = (cf.lineNumber || 0) + 1;
      const loc = rel ? `${rel}:${line}` : "";
      const nextChain = loc ? [loc, ...chain.slice(0, 3)] : chain;
      if (node.selfSize > 0 && loc && (!wsRoot || !loc.startsWith("node:"))) {
        const prev = totals.get(loc) || { size: 0, tb: nextChain.join(" <- ") };
        prev.size += node.selfSize;
        totals.set(loc, prev);
      }
      for (const child of node.children || []) {
        visit(child, nextChain);
      }
    };
    visit(res.profile.head, []);
    return totals;
  };

  process.on("SIGUSR1", () => {
    seq += 1;
    if (typeof global.gc === "function") {
      global.gc();
      global.gc();
    }
    const mem = process.memoryUsage();
    const heapBytes = mem.heapUsed + mem.external;
    const allocs = collectAllocByLoc();
    const topAllocations = [];
    let retainerSummary = "";

    if (seq <= 2) {
      // seq=1 warms up HeapProfiler buffers; seq=2 captures clean S0 baseline
      baselineByLoc = allocs;
    } else {
      const diffs = [];
      for (const [loc, info] of allocs.entries()) {
        if (loc.includes(".vulnbox_memprobe")) continue;
        const prev = baselineByLoc.get(loc)?.size || 0;
        const diff = info.size - prev;
        if (diff > 0) {
          diffs.push({
            location: loc,
            size_diff_bytes: diff,
            count_diff: 0,
            traceback_excerpt: info.tb,
          });
        }
      }
      diffs.sort((a, b) => b.size_diff_bytes - a.size_diff_bytes);
      const wsDiffs = diffs.filter((d) => !d.location.includes("://") && !d.location.startsWith("/"));
      const chosen = (wsDiffs.length ? wsDiffs : diffs).slice(0, 5);
      topAllocations.push(...chosen);
      if (chosen.length) {
        retainerSummary = `Top V8 allocation at ${chosen[0].location} (+${(chosen[0].size_diff_bytes / 1024).toFixed(1)} KB)`;
      }
    }

    const payload = {
      seq,
      heap_bytes: heapBytes,
      rss_bytes: mem.rss,
      gc_uncollectable: 0,
      top_allocations: topAllocations,
      retainer_summary: retainerSummary,
    };
    const tmp = `${snapFile}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(payload), "utf-8");
      fs.renameSync(tmp, snapFile);
    } catch {
      // ignore
    }
  });
}
