# `vulnbox-go` — Reference Go Security Plugin Pack

Official reference plugin pack demonstrating VulnBox's `importlib.metadata` entry-point extensibility (`[project.entry-points."vulnbox.plugins"]`).

## Install

```bash
pip install -e ./plugins/vulnbox-go
```

Once installed into the same Python environment as `vulnbox`, `vulnbox scan` and `vulnbox remediate` automatically discover and execute `GoSASTPlugin` (`GO-CMD-001`, `GO-SQL-001`, `GO-TLS-001`, `GO-PATH-001`, `GO-SSRF-001`).
