# Adaptadores de herramientas externas

Todos se ejecutan sin shell, con timeout, salida acotada, entorno mínimo y las variables de
privacidad forzadas. En Docker el proyecto se monta como solo lectura en `/src`.

| Escáner | Aplica si | Invocación (resumen) | Kind/categoría | Notas de red/privacidad |
|---|---|---|---|---|
| `trivy` | siempre | `fs --format json --scanners vuln,misconfig,secret --offline-scan --skip-version-check --disable-telemetry [--skip-db-update --skip-java-db-update --skip-check-update]` | vuln → `vulnerability`; misconfig/secret → `potential-risk` | `--offline-scan` siempre (no envía hashes de JARs); la BD solo se descarga con `--online` |
| `osv-scanner` | hay manifiestos | `scan source -r --format json --allow-no-lockfiles` + `--offline` u (`--offline-vulnerabilities --download-offline-databases --no-resolve`) | `vulnerability` | Nunca envía la lista de dependencias a api.osv.dev; exit 1 = hallazgos, 128 = sin paquetes |
| `gitleaks` | siempre | `dir` (+ `git` si hay `.git` e historial activado) `--report-format json --report-path - --redact=100 --exit-code 0` | `potential-risk`/`secret` | `safe.directory=*` para montajes en Docker |
| `semgrep` | código fuente | `scan --json --metrics=off --disable-version-check --config <reglas embebidas> [--config p/default si --online] [--config usuario]` | `potential-risk`/`sast` (las reglas de secretos/Dockerfile se reclasifican) | `extra.fingerprint` y `lines` requieren login y se ignoran |
| `hadolint` | Dockerfiles | `--format json --no-fail <dockerfiles>` | `potential-risk`/`container` | DL3002→root, DL3006/3007→imagen sin fijar, DL3064→secreto en ENV… |
| `kube-linter` | K8s/Helm | `lint --format json` | `potential-risk`/`iac` | Sin número de línea: se localiza el `name:` del objeto |
| `checkov` | IaC/Dockerfile | `-d /src -o json --quiet --compact --skip-download --skip-results-upload` | `potential-risk` | `CKV_SKIP_PACKAGE_UPDATE_CHECK`, `BC_SKIP_MAPPING`; sin API key no hay severidad (se asume medium) |
| `kics` | IaC (opt-in) | `scan -p /src -o /out --report-formats json --ci --disable-secrets --ignore-on-exit results` | `potential-risk` | Exit 20-60 = hallazgos; comprobación de versión inevitable → desactivado por defecto |
| `bandit` | Python | `-r -f json -q` | `potential-risk`/`sast` | Solo binario local |
| `zap-baseline` | `--allow-active-scan` + URL + autorización | `zap-baseline.py -t URL -J zap.json -m N -I` (docker, `/zap/wrk`) | `potential-risk`/`dast` | Spider + reglas pasivas, sin ataques |

## Formatos parseados (verificados en el código fuente de cada herramienta y con salidas reales)

- **Trivy**:
  - `Results[].{Target, Type, Vulnerabilities[], Misconfigurations[], Secrets[]}`.
  - `CVSS` es un mapa por fuente; se prefiere nvd, después ghsa.
  - Misconfigs: solo `Status=FAIL`, con la línea en `CauseMetadata.StartLine`.
  - Secretos: `Match` ya viene enmascarado; `Code` se descarta.
- **OSV-Scanner**:
  - `results[].source.path`, `packages[].package`, `groups[].{ids,aliases,max_severity}`
    (puntuación en texto), `vulnerabilities[]` (esquema OSV en snake_case).
- **Gitleaks**: array de objetos con claves PascalCase (`RuleID`, `File`, `StartLine`,
  `Secret`, `Commit`, `Match`…).
- **Semgrep**:
  - `results[].{check_id, path, start.line, end.line, extra.{message, severity, metadata}}`.
  - `metadata.cwe` puede ser string o lista.
- **Hadolint**: `[{code, file, level, line, message}]`.
- **kube-linter**: `Reports[].{Check, Remediation, Diagnostic.Message, Object.{Metadata.FilePath, K8sObject.{Name, GroupVersionKind.Kind}}}`.
- **Checkov**: un objeto o una lista de `{check_type, results.failed_checks[]{check_id, check_name, file_path, file_line_range, resource, severity, guideline}}`.
- **KICS**: `queries[]{query_name, query_id, severity, platform, cwe, files[]{file_name, line, expected_value, actual_value}}`.
- **Bandit**: `results[]{filename, line_number, line_range, issue_severity, issue_confidence, issue_text, test_id, issue_cwe.id, more_info}`.
- **ZAP**: `site[].alerts[]{pluginid, alert, riskcode, confidence, desc, solution, reference, cweid, instances[]}`; todos los valores son texto y `desc`/`solution` vienen en HTML.
