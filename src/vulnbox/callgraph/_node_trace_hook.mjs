/**
 * Sandbox runtime call-graph hook for Node.js using built-in `node:inspector`.
 * Loaded via NODE_OPTIONS="--import file://..." inside an ephemeral sandbox copy.
 * Captures both V8 CPU profile call edges and 100% deterministic precise function coverage.
 */

import fs from "node:fs";
import inspector from "node:inspector";
import path from "node:path";
import { fileURLToPath } from "node:url";

const workspace = process.env.VULNBOX_TRACE_WORKSPACE || "";
const outFile = process.env.VULNBOX_TRACE_OUT || "";

if (workspace && outFile) {
  const wsRoot = path.resolve(workspace);
  const session = new inspector.Session();
  session.connect();

  let flushed = false;
  const postSync = (method, params = {}) => {
    let result = null;
    session.post(method, params, (err, res) => {
      if (!err) result = res;
    });
    return result;
  };

  postSync("Profiler.enable");
  postSync("Profiler.setSamplingInterval", { interval: 100 });
  postSync("Profiler.startPreciseCoverage", { callCount: true, detailed: false });
  postSync("Profiler.start");

  const toRel = (url) => {
    if (!url) return null;
    let fsPath = url;
    if (url.startsWith("file://")) {
      try {
        fsPath = fileURLToPath(url);
      } catch {
        return null;
      }
    }
    const resolved = path.resolve(fsPath);
    if (resolved.startsWith(wsRoot + path.sep)) {
      const rel = resolved.slice(wsRoot.length + 1).replace(/\\/g, "/");
      if (!rel.startsWith(".vulnbox") && !rel.startsWith("node_modules/")) {
        return rel;
      }
    }
    return null;
  };

  const flush = () => {
    if (flushed) return;
    flushed = true;
    try {
      const covRes = postSync("Profiler.takePreciseCoverage");
      const profRes = postSync("Profiler.stop");
      session.disconnect();

      const nodesMap = new Map();
      const edgesMap = new Map();
      const executedFns = new Set();

      // 1. Collect exact executed workspace functions (zero sampling misses!)
      if (covRes && Array.isArray(covRes.result)) {
        for (const script of covRes.result) {
          const rel = toRel(script.url);
          if (!rel) continue;
          for (const fn of script.functions || []) {
            if (!fn.functionName) continue;
            const ran = (fn.ranges || []).some((r) => r.count > 0);
            if (!ran) continue;
            const nid = `${rel}::${fn.functionName}`;
            nodesMap.set(nid, { node_id: nid, file_path: rel, symbol: fn.functionName, line: 1 });
            executedFns.add(nid);
          }
        }
      }

      // 2. Extract caller -> callee edges from V8 CPU profile tree
      if (profRes && profRes.profile && Array.isArray(profRes.profile.nodes)) {
        const byId = new Map();
        for (const n of profRes.profile.nodes) byId.set(n.id, n);
        for (const parent of profRes.profile.nodes) {
          const pFrame = parent.callFrame || {};
          const pRel = toRel(pFrame.url);
          if (!pRel) continue;
          const pSym = pFrame.functionName || "<module>";
          const pId = `${pRel}::${pSym}`;
          const pLine = (pFrame.lineNumber || 0) + 1;
          nodesMap.set(pId, { node_id: pId, file_path: pRel, symbol: pSym, line: pLine });

          for (const childId of parent.children || []) {
            const child = byId.get(childId);
            if (!child || !child.callFrame) continue;
            const cFrame = child.callFrame;
            const cRel = toRel(cFrame.url);
            const cSym = cFrame.functionName || "<anonymous>";
            if (!cRel) continue;
            const cId = `${cRel}::${cSym}`;
            const cLine = (cFrame.lineNumber || 0) + 1;
            nodesMap.set(cId, { node_id: cId, file_path: cRel, symbol: cSym, line: cLine });
            if (pId !== cId) {
              edgesMap.set(`${pId}->${cId}`, {
                caller: pId,
                callee: cId,
                file_path: pRel,
                line: pLine,
              });
            }
          }
        }
      }

      // Merge with existing dump if multiple node processes ran
      let prevNodes = [];
      let prevEdges = [];
      let prevExec = [];
      if (fs.existsSync(outFile)) {
        try {
          const prev = JSON.parse(fs.readFileSync(outFile, "utf-8"));
          prevNodes = prev.nodes || [];
          prevEdges = prev.edges || [];
          prevExec = prev.executed_functions || [];
        } catch {
          // ignore
        }
      }
      for (const n of prevNodes) if (!nodesMap.has(n.node_id)) nodesMap.set(n.node_id, n);
      for (const e of prevEdges) {
        const k = `${e.caller}->${e.callee}`;
        if (!edgesMap.has(k)) edgesMap.set(k, e);
      }
      for (const fn of prevExec) executedFns.add(fn);

      fs.mkdirSync(path.dirname(outFile), { recursive: true });
      fs.writeFileSync(
        outFile,
        JSON.stringify({
          nodes: Array.from(nodesMap.values()),
          edges: Array.from(edgesMap.values()),
          executed_functions: Array.from(executedFns),
        }),
        "utf-8",
      );
    } catch {
      // Never crash target process on exit
    }
  };

  process.on("beforeExit", flush);
  process.on("exit", flush);
  process.on("SIGTERM", () => {
    flush();
    process.exit(0);
  });
}
