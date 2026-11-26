const csrfMeta = document.querySelector('meta[name="vulnbox-csrf"]');
const CSRF_TOKEN = csrfMeta ? csrfMeta.getAttribute("content") || "" : "";

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (typeof child === "string") node.appendChild(document.createTextNode(child));
    else if (child) node.appendChild(child);
  }
  return node;
}

function setStatus(kind, msg) {
  const box = document.getElementById("global-status");
  if (!msg) {
    box.className = "status-banner hidden";
    box.textContent = "";
    return;
  }
  box.className = `status-banner ${kind}`;
  box.textContent = msg;
}

async function apiPost(path, payload) {
  const resp = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-VulnBox-Token": CSRF_TOKEN,
    },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || `HTTP ${resp.status}`);
  }
  return data;
}

function sevClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical" || s === "high") return "err";
  if (s === "medium") return "warn";
  return "info";
}

function renderDiffPre(diffText) {
  const pre = el("pre");
  for (const line of String(diffText || "").split("\n")) {
    let cls = "diff-line-ctx";
    if (line.startsWith("+") && !line.startsWith("+++")) cls = "diff-line-add";
    else if (line.startsWith("-") && !line.startsWith("---")) cls = "diff-line-del";
    else if (line.startsWith("@@") || line.startsWith("---") || line.startsWith("+++")) cls = "diff-line-hunk";
    pre.appendChild(el("span", { class: cls, text: line }));
  }
  return pre;
}

function renderReportView(container, data) {
  container.replaceChildren();
  const report = data.report;
  const runId = data.run_id;
  const findings = report.findings || [];
  const patches = report.patches || [];
  const verifications = report.verifications || [];
  const guardrails = report.guardrail_events || [];

  const verById = Object.fromEntries(verifications.map((v) => [v.finding_id, v]));
  const patchById = Object.fromEntries(patches.map((p) => [p.finding_id, p]));
  const verifiedCount = verifications.filter((v) => v.verified).length;
  const activeCount = verifications.filter((v) => v.dynamic_confirmed_and_fixed === true).length;
  const blockedCount = guardrails.filter((g) => g.decision === "block").length;

  const summaryCard = el("div", { class: "card" }, [
    el("div", { class: "finding-header" }, [
      el("h2", { text: "Sandbox Report Summary" }),
      el("div", { class: "row-actions mt-0" }, [
        el("a", { class: "btn secondary small", href: `/api/artifact/${runId}/report.md`, download: "report.md", text: "Download report.md" }),
        el("a", { class: "btn secondary small", href: `/api/artifact/${runId}/findings.sarif.json`, download: "findings.sarif.json", text: "Download SARIF 2.1.0" }),
        el("a", { class: "btn secondary small", href: `/api/artifact/${runId}/manifest.json`, download: "manifest.json", text: "Download manifest.json" }),
      ]),
    ]),
    el("div", { class: "kpi-grid" }, [
      el("div", { class: "kpi" }, [el("div", { class: "label", text: "Total Findings" }), el("div", { class: "val", text: String(findings.length) })]),
      el("div", { class: "kpi" }, [el("div", { class: "label", text: "Verified Patches" }), el("div", { class: "val", text: `${verifiedCount} / ${patches.length}` })]),
      el("div", { class: "kpi" }, [el("div", { class: "label", text: "Live curl Confirmed -> Fixed" }), el("div", { class: "val", text: String(activeCount) })]),
      el("div", { class: "kpi" }, [el("div", { class: "label", text: "Secrets Scrubbed" }), el("div", { class: "val", text: String(report.scrub_summary.secrets_redacted || 0) })]),
      el("div", { class: "kpi" }, [el("div", { class: "label", text: "Backend / LLM" }), el("div", { class: "val val-sm", text: report.llm_enabled ? `${report.sandbox_backend} + ${report.llm_model}` : report.sandbox_backend })]),
      el("div", { class: "kpi" }, [el("div", { class: "label", text: "Guardrail Blocks" }), el("div", { class: "val", text: String(blockedCount) })]),
    ]),
  ]);
  container.appendChild(summaryCard);

  if (findings.length === 0) {
    container.appendChild(el("div", { class: "card" }, [el("p", { text: "No vulnerabilities or hygiene issues detected." })]));
    return;
  }

  const detailsWrap = el("div", { class: "card" }, [el("h3", { text: "Findings & Verification Evidence" })]);
  for (const f of findings) {
    const ver = verById[f.finding_id];
    const patch = patchById[f.finding_id];
    const badges = [
      el("span", { class: `pill ${sevClass(f.severity)}`, text: f.severity.toUpperCase() }),
      el("span", { class: "pill", text: `${f.rule_id} (${f.cwe_id})` }),
      el("span", { class: "pill", text: `${f.file_path}:${f.start_line}` }),
      el("span", { class: "pill", text: `reachability: ${f.reachability}` }),
    ];
    if (ver) {
      badges.push(el("span", { class: `pill ${ver.verified ? "ok" : "err"}`, text: ver.verified ? "VERIFIED" : "UNVERIFIED" }));
      if (ver.dynamic_confirmed_and_fixed === true) {
        badges.push(el("span", { class: "pill ok", text: "LIVE CURL: CONFIRMED -> FIXED" }));
      }
    }

    const fCard = el("div", { class: "finding-card" }, [
      el("div", { class: "finding-header" }, [
        el("strong", { text: f.title }),
        el("div", { class: "doctor-bar" }, badges),
      ]),
      el("p", { class: "finding-msg", text: f.message }),
    ]);

    if (f.snippet) {
      fCard.appendChild(el("pre", { text: f.snippet }));
    }

    if (ver && ver.dynamic_probe_before) {
      const before = ver.dynamic_probe_before;
      const after = ver.dynamic_probe_after;
      fCard.appendChild(el("div", { class: "probe-title", text: "Active Loopback curl Verification" }));
      fCard.appendChild(el("pre", { text: before.curl_command }));
      const cmp = el("div", { class: "probe-compare" }, [
        el("div", { class: "probe-box" }, [
          el("div", { class: "pill err", text: `BEFORE PATCH: HTTP ${before.status_code ?? "ERR"} (vulnerable=${before.matched_vulnerable})` }),
          el("pre", { text: before.response_body_excerpt || JSON.stringify(before.response_headers, null, 2) }),
        ]),
      ]);
      if (after) {
        cmp.appendChild(
          el("div", { class: "probe-box" }, [
            el("div", { class: `pill ${after.matched_fixed ? "ok" : "err"}`, text: `AFTER PATCH: HTTP ${after.status_code ?? "ERR"} (fixed=${after.matched_fixed})` }),
            el("pre", { text: after.response_body_excerpt || JSON.stringify(after.response_headers, null, 2) }),
          ])
        );
      }
      fCard.appendChild(cmp);
    }

    if (ver && ver.memory_probe_before) {
      const mb = ver.memory_probe_before;
      const ma = ver.memory_probe_after;
      const mcmp = el("div", { class: "probe-compare" }, [
        el("div", { class: "probe-box" }, [
          el("div", {
            class: `pill ${mb.leak_detected ? "err" : "ok"}`,
            text: `BEFORE PATCH MEM: ${mb.bytes_per_request_slope} B/req (R²=${mb.r_squared}), FD Δ=${mb.fd_delta}`,
          }),
          el("pre", { text: mb.retainer_summary || `Endpoint: ${mb.endpoint}\nHeap growth: ${mb.total_heap_growth_bytes} B` }),
        ]),
      ]);
      if (ma) {
        mcmp.appendChild(
          el("div", { class: "probe-box" }, [
            el("div", {
              class: `pill ${ma.leak_detected ? "err" : "ok"}`,
              text: `AFTER PATCH MEM: ${ma.bytes_per_request_slope} B/req (R²=${ma.r_squared}), FD Δ=${ma.fd_delta}`,
            }),
            el("pre", { text: ma.retainer_summary || `Endpoint: ${ma.endpoint}\nHeap growth: ${ma.total_heap_growth_bytes} B` }),
          ])
        );
      }
      fCard.appendChild(mcmp);
    }

    if (patch) {
      if (patch.root_cause_explanation) {
        fCard.appendChild(el("p", { class: "explain-line", text: `Core Issue: ${patch.root_cause_explanation}` }));
      }
      if (patch.fix_explanation) {
        fCard.appendChild(el("p", { class: "explain-line", text: `Fix: ${patch.fix_explanation}` }));
      }
      fCard.appendChild(
        el("div", { class: "finding-header mt-10" }, [
          el("span", { class: "section-label", text: `Unified Diff (${patch.strategy})` }),
          el("button", {
            class: "btn secondary small",
            type: "button",
            text: "Copy Patch",
            onclick: () => navigator.clipboard && navigator.clipboard.writeText(patch.unified_diff),
          }),
        ])
      );
      fCard.appendChild(renderDiffPre(patch.unified_diff));

      if (patch.regression_test_code) {
        const det = el("details", {}, [
          el("summary", { text: `View Generated Regression Test (${patch.regression_test_path})` }),
          el("pre", { text: patch.regression_test_code }),
        ]);
        fCard.appendChild(det);
      }
    }
    detailsWrap.appendChild(fCard);
  }
  container.appendChild(detailsWrap);

  if (report.call_graph_summary) {
    const cg = report.call_graph_summary;
    const provs = Object.entries(cg.edges_by_provenance || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join(" | ");
    container.appendChild(
      el("div", { class: "card" }, [
        el("h3", { text: "Hybrid Call Graph Coverage" }),
        el("p", {
          class: "mono",
          text: `Nodes: ${cg.total_nodes} | Edges: ${cg.total_edges} (${provs || "none"}) | Runtime-Resolved Dynamic Sites: ${cg.runtime_resolved_count} | Remaining Unresolved: ${(cg.unresolved_sites || []).length}`,
        }),
      ])
    );
  }

  if (guardrails.length > 0) {
    const tbl = el("table", {}, [
      el("thead", {}, [
        el("tr", {}, [
          el("th", { text: "Gate" }),
          el("th", { text: "Decision" }),
          el("th", { text: "Finding" }),
          el("th", { text: "Reason" }),
        ]),
      ]),
      el(
        "tbody",
        {},
        guardrails.map((g) =>
          el("tr", {}, [
            el("td", { class: "mono", text: g.gate }),
            el("td", {}, [
              el("span", {
                class: `pill ${g.decision === "allow" ? "ok" : g.decision === "warn" ? "warn" : "err"}`,
                text: g.decision.toUpperCase(),
              }),
            ]),
            el("td", { class: "mono", text: g.finding_id || "-" }),
            el("td", { text: g.reason }),
          ])
        )
      ),
    ]);
    container.appendChild(el("div", { class: "card" }, [el("h3", { text: "Guardrail Audit Trail" }), tbl]));
  }
}

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.remove("hidden");
    setStatus("", "");
  });
});

document.getElementById("rem-llm-toggle").addEventListener("change", (e) => {
  document.getElementById("rem-llm-opts").classList.toggle("hidden", !e.target.checked);
});

async function loadDoctor() {
  try {
    const resp = await fetch("/api/doctor");
    const doc = await resp.json();
    const bar = document.getElementById("doctor-bar");
    bar.replaceChildren(
      el("span", { class: "pill ok", text: `Python ${doc.python}` }),
      el("span", { class: `pill ${doc.node ? "ok" : "warn"}`, text: doc.node ? "Node OK" : "Node Missing" }),
      el("span", { class: `pill ${doc.curl ? "ok" : "warn"}`, text: doc.curl ? "curl OK" : "urllib Fallback" }),
      el("span", { class: `pill ${doc.docker_ready ? "ok" : "warn"}`, text: doc.docker_ready ? "Docker READY" : "Docker Unavailable" }),
      el("span", { class: "pill ok", text: "Local Sandbox READY" })
    );

    if (doc.samples && doc.samples.length > 0) {
      const sbar = document.getElementById("samples-bar");
      sbar.classList.remove("hidden");
      for (const s of doc.samples) {
        sbar.appendChild(
          el("button", {
            class: "btn secondary small",
            type: "button",
            text: s.label,
            onclick: () => {
              for (const id of ["rem-repo", "scan-repo", "prof-repo", "probe-repo", "ver-repo"]) {
                document.getElementById(id).value = s.path;
              }
              if (s.probe_json) {
                document.getElementById("rem-probe").value = s.probe_json;
                document.getElementById("probe-json").value = s.probe_json;
              } else {
                document.getElementById("rem-probe").value = "";
              }
            },
          })
        );
      }
    }
  } catch (err) {
    setStatus("error", `Failed to load environment status: ${err.message}`);
  }
}

const PROBE_PRESETS = {
  yaml: {
    probe_id: "probe-yaml-tag",
    rule_id: "PY-YAML-001",
    description: "Test POST /parse rejects benign Python YAML tag after safe_load fix",
    method: "POST",
    path: "/parse",
    headers: { "Content-Type": "text/plain" },
    body: "!!python/tuple [1, 2]",
    vulnerable_expectation: { status_codes: [200] },
    fixed_expectation: { status_codes: [400, 422] },
  },
  path: {
    probe_id: "probe-path-boundary",
    rule_id: "PY-PATH-001",
    description: "Test GET /files denies synthetic marker outside public root",
    method: "GET",
    path: "/files?name=../vulnbox_boundary_marker.txt",
    setup_marker_file: "vulnbox_boundary_marker.txt",
    setup_marker_content: "VULNBOX_BOUNDARY_MARKER_9F3A",
    vulnerable_expectation: { status_codes: [200], body_contains: ["VULNBOX_BOUNDARY_MARKER_9F3A"] },
    fixed_expectation: { status_codes: [400, 403, 404], body_not_contains: ["VULNBOX_BOUNDARY_MARKER_9F3A"] },
  },
  cors: {
    probe_id: "probe-cors-origin",
    rule_id: "JS-CORS-001",
    description: "Test GET /api/data does not reflect untrusted Origin with credentials",
    method: "GET",
    path: "/api/data",
    headers: { Origin: "https://untrusted.example" },
    vulnerable_expectation: { status_codes: [200], headers_contain: { "access-control-allow-credentials": "true" } },
    fixed_expectation: { status_codes: [200], headers_not_contain: { "access-control-allow-origin": "https://untrusted.example" } },
  },
};

document.getElementById("probe-json").value = JSON.stringify(PROBE_PRESETS.yaml, null, 2);
document.getElementById("btn-preset-yaml").addEventListener("click", () => {
  document.getElementById("probe-json").value = JSON.stringify(PROBE_PRESETS.yaml, null, 2);
});
document.getElementById("btn-preset-path").addEventListener("click", () => {
  document.getElementById("probe-json").value = JSON.stringify(PROBE_PRESETS.path, null, 2);
});
document.getElementById("btn-preset-cors").addEventListener("click", () => {
  document.getElementById("probe-json").value = JSON.stringify(PROBE_PRESETS.cors, null, 2);
});

document.getElementById("btn-profile").addEventListener("click", async () => {
  setStatus("loading", "Profiling repository...");
  try {
    const data = await apiPost("/api/profile", { repo_path: document.getElementById("prof-repo").value });
    setStatus("", "");
    const out = document.getElementById("profile-results");
    out.replaceChildren(el("div", { class: "card" }, [el("h3", { text: "Detected Profile" }), el("pre", { text: JSON.stringify(data.profile, null, 2) })]));
  } catch (err) {
    setStatus("error", err.message);
  }
});

document.getElementById("btn-scan").addEventListener("click", async () => {
  setStatus("loading", "Scrubbing workspace and running sandboxed analyzers...");
  try {
    const data = await apiPost("/api/scan", {
      repo_path: document.getElementById("scan-repo").value,
      backend: document.getElementById("scan-backend").value,
      advisories_path: document.getElementById("scan-advisories").value,
      deep: document.getElementById("scan-deep-toggle").checked,
      check_leaks: document.getElementById("scan-leaks-toggle").checked,
    });
    setStatus("", "");
    renderReportView(document.getElementById("scan-results"), data);
  } catch (err) {
    setStatus("error", err.message);
  }
});

document.getElementById("btn-remediate").addEventListener("click", async () => {
  setStatus("loading", "Running end-to-end sandbox scan, active curl probing, patching, and dual verification...");
  try {
    const data = await apiPost("/api/remediate", {
      repo_path: document.getElementById("rem-repo").value,
      backend: document.getElementById("rem-backend").value,
      start_cmd: document.getElementById("rem-start").value,
      health_path: document.getElementById("rem-health").value,
      advisories_path: document.getElementById("rem-advisories").value,
      out_dir: document.getElementById("rem-out").value,
      probe_json: document.getElementById("rem-probe").value,
      deep: document.getElementById("rem-deep-toggle").checked,
      check_leaks: document.getElementById("rem-leaks-toggle").checked,
      llm_enabled: document.getElementById("rem-llm-toggle").checked,
      llm_provider: document.getElementById("rem-llm-provider").value,
      llm_model: document.getElementById("rem-llm-model").value,
      llm_base_url: document.getElementById("rem-llm-url").value,
      llm_max_retries: Number(document.getElementById("rem-llm-retries").value || 2),
    });
    setStatus("", "");
    renderReportView(document.getElementById("remediate-results"), data);
  } catch (err) {
    setStatus("error", err.message);
  }
});

document.getElementById("btn-probe").addEventListener("click", async () => {
  setStatus("loading", "Booting target app on 127.0.0.1 inside sandbox and running curl probe...");
  try {
    const data = await apiPost("/api/probe", {
      repo_path: document.getElementById("probe-repo").value,
      start_cmd: document.getElementById("probe-start").value,
      backend: document.getElementById("probe-backend").value,
      probe_json: document.getElementById("probe-json").value,
    });
    setStatus("", "");
    const out = document.getElementById("probe-results");
    out.replaceChildren(
      ...(data.results || []).map((r) =>
        el("div", { class: "card" }, [
          el("div", { class: "finding-header" }, [
            el("strong", { text: `Probe: ${r.probe_id}` }),
            el("div", { class: "doctor-bar" }, [
              el("span", { class: `pill ${r.matched_vulnerable ? "err" : "ok"}`, text: `HTTP ${r.status_code ?? "ERR"}` }),
              el("span", { class: `pill ${r.matched_vulnerable ? "err" : "info"}`, text: `vulnerable=${r.matched_vulnerable}` }),
              el("span", { class: `pill ${r.matched_fixed ? "ok" : "warn"}`, text: `fixed=${r.matched_fixed}` }),
            ]),
          ]),
          el("pre", { text: r.curl_command }),
          el("pre", { text: r.error || r.response_body_excerpt || JSON.stringify(r.response_headers, null, 2) }),
        ])
      )
    );
  } catch (err) {
    setStatus("error", err.message);
  }
});

document.getElementById("btn-verify").addEventListener("click", async () => {
  setStatus("loading", "Applying patch in fresh scrubbed sandbox and running dual verification...");
  try {
    const data = await apiPost("/api/verify-patch", {
      repo_path: document.getElementById("ver-repo").value,
      finding_id: document.getElementById("ver-finding-id").value,
      rule_id: document.getElementById("ver-rule-id").value,
      backend: document.getElementById("ver-backend").value,
      start_cmd: document.getElementById("ver-start").value,
      unified_diff: document.getElementById("ver-diff").value,
      regression_test_path: document.getElementById("ver-reg-path").value,
      regression_test_code: document.getElementById("ver-reg-code").value,
      probe_json: document.getElementById("ver-probe-json").value,
    });
    setStatus("", "");
    const v = data.verification;
    const out = document.getElementById("verify-results");
    out.replaceChildren(
      el("div", { class: "card" }, [
        el("div", { class: "finding-header" }, [
          el("h3", { class: "m-0", text: `Patch Verification: ${v.patch_id}` }),
          el("span", { class: `pill ${v.verified ? "ok" : "err"}`, text: v.verified ? "VERIFIED" : "UNVERIFIED" }),
        ]),
        el("p", { class: "muted-text", text: v.summary }),
        el("pre", { text: JSON.stringify(v, null, 2) }),
      ])
    );
  } catch (err) {
    setStatus("error", err.message);
  }
});

loadDoctor();
