# Recorded tool outputs

These files are **real outputs** produced by the pinned tool images against the
fixtures in `testdata/fixtures` (recorded 2026-11-06). They are used by the
adapter parser tests (`internal/scanners/adapters_test.go`). Nothing here was
written by hand.

To re-record (PowerShell / bash, adjust paths), mount the fixture read-only at `/src`:

| File | Command |
|------|---------|
| `trivy-node-app.json` | `docker run --rm -v <fixtures>/node-app:/src:ro -v <cache>:/cache aquasec/trivy:0.76.2 fs --format json --quiet --scanners vuln,misconfig,secret --offline-scan --skip-db-update --skip-java-db-update --skip-check-update --cache-dir /cache /src` |
| `osv-scanner-node-app.json` | `docker run --rm -v <fixtures>/node-app:/src:ro -v <cache>:/cache -e OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/cache ghcr.io/google/osv-scanner:v2.7.0 scan source -r --format json --verbosity error --offline /src` |
| `gitleaks-python-app.json` | `docker run --rm -v <fixtures>/python-app:/src:ro zricethezav/gitleaks:v8.30.1 dir --report-format json --report-path - --redact=100 --no-banner --exit-code 0 --log-level error /src` |
| `hadolint-node-app.json` | `docker run --rm -v <fixtures>/node-app:/src:ro --entrypoint /bin/hadolint hadolint/hadolint:v2.15.1 --format json --no-fail /src/Dockerfile` |
| `kube-linter-go-app.json` | `docker run --rm -v <fixtures>/go-app:/src:ro --entrypoint /kube-linter stackrox/kube-linter:v0.8.3 lint --format json /src` |
| `checkov-iac.json` | `docker run --rm -v <fixtures>/iac:/src:ro --entrypoint checkov bridgecrew/checkov:3.4.3 -d /src -o json --quiet --compact --skip-download --framework terraform,dockerfile,kubernetes` |
| `semgrep-python-app.json` | `docker run --rm -v <fixtures>/python-app:/src:ro -v <rulesdir>:/out --entrypoint semgrep semgrep/semgrep:1.184.0 scan --json --metrics=off --disable-version-check --quiet --config /out/rules.yml /src` (rules: `internal/scanners/semgrep/rules.yml`) |

Trivy and OSV-Scanner were run once with network access to download their
public databases into the cache, then recorded with `--network none`.
