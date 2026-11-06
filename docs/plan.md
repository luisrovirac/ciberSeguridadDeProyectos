# Plan por hitos y estado

| # | Hito | Estado | Verificación |
|---|---|---|---|
| M0 | Esqueleto: módulo, Cobra (`scan`, `tools check`, `report merge`, `db`, `version`), Viper (YAML + `SECUREPROJECTS_*`), slog, códigos de salida, Makefile, golangci | ✅ | `go build ./...`, `secureprojects version` |
| M1 | Modelo `Finding`, fingerprint, redactor, detector, `execx`, interfaz `Scanner`, motor con errgroup y límites | ✅ | tests de `finding`, `redact`, `detector`, `fsutil` |
| M2 | Analizadores nativos: secretos, Dockerfile, IaC/K8s/compose/CFN, SAST heurístico, deps sin fijar, reglas YAML | ✅ | `internal/scanners/native` sobre los fixtures |
| M3 | Base OSV nativa: `db update`/`import`, índice, lockfiles (12 formatos), comparadores de versión, matcher | ✅ | registros OSV reales: lodash, PyYAML, requests, x/text |
| M4 | Adaptadores Trivy, OSV-Scanner, Gitleaks, Semgrep (local o docker) | ✅ | parsers contra salidas reales; ejecución real en docker |
| M5 | Dedup entre herramientas, grupos, scoring, ignorados con justificación, falsos positivos conocidos, baseline/diff, caché | ✅ | `dedup`, `policy`, `scoring`, `app` (baseline) |
| M6 | Tabla, JSON v1 (golden), SARIF 2.1.0 (validado con el esquema OASIS), HTML embebido, `report merge`, `--fail-on` | ✅ | `report`, `cli` |
| M7 | Hadolint, kube-linter, Checkov, KICS, Bandit, `--repo`, ZAP opt-in, LLM opt-in | ✅ | parsers con salidas reales; e2e `--repo` |
| M8 | README, SECURITY, LIMITATIONS, docs, Dockerfile, lint limpio | ✅ | `golangci-lint run` = 0 issues |

## Próximos pasos sugeridos

- `trivy image` para escanear imágenes construidas (además de los Dockerfiles).
- Análisis de alcanzabilidad (p. ej. `govulncheck` para Go) para reducir ruido en `vulnerability`.
- Feed CISA KEV/EPSS opcional (descarga explícita) como factor de explotabilidad en la prioridad.
- Firmar los binarios de release y publicar SBOM (Syft) de la propia herramienta.
