# Modelo de hallazgos y priorización

## Modelo (`internal/finding`)

| Campo | Descripción |
|---|---|
| `id`, `fingerprint` | Identidad. El fingerprint es SHA-256 de los campos de identidad y **no incluye la línea** |
| `title`, `description` | Texto (redactado) |
| `kind` | `vulnerability` (BD de vulnerabilidades + versión exacta) o `potential-risk` (heurística o política) |
| `category` | `dependency-vuln`, `secret`, `iac-misconfig`, `container`, `sast`, `dependency-risk`, `dast`, `custom` |
| `severity` | `critical`, `high`, `medium`, `low`, `info`, `unknown` |
| `confidence` | `high`, `medium`, `low` |
| `cvss` | `{version, vector, score, source}` cuando existe |
| `priority` | 0-100 (ver abajo) |
| `tools` | Todas las herramientas que lo reportaron (tras deduplicar) |
| `ruleId`, `ruleFamily` | Regla de origen y familia común entre herramientas |
| `location` | `{path, startLine, endLine, commit, resource}` |
| `package` | `{name, version, ecosystem, purl, fixedVersions, direct}` |
| `cve`, `aliases`, `cwe` | Identificadores |
| `evidence` | Fragmento **siempre redactado** |
| `remediation`, `references` | Cómo arreglarlo |
| `triage` | `{status: open\|ignored\|false-positive\|accepted, justification, expires, source}` |
| `groupId` | Agrupa hallazgos relacionados (p. ej. todas las CVE de `lodash@4.17.15`) |
| `tags`, `aiExplanation`, `isNew` | Extra: `corroborated`, `placeholder`, `git-history`; explicación LLM; resultado de baseline |

### Fingerprint

- **Vulnerabilidades**: `categoría | ecosistema | paquete | versión | ID canónico`. El ID
  canónico es el CVE si existe; si no, GHSA; si no, el menor. Así trivy (`CVE-…`), osv-scanner
  (`GHSA-…` con alias CVE) y el matcher nativo (`GO-…`) producen la misma identidad.
- **Resto**: `categoría | familia (o regla) | ruta | recurso | evidencia normalizada [| commit]`.

## Severidad

1. Si hay **CVSS** (v3.x calculado desde el vector, o el que da la herramienta), la severidad
   sale de la escala cualitativa CVSS v3: ≥9 critical, ≥7 high, ≥4 medium, >0 low.
2. Si no, la etiqueta de la fuente (`database_specific.severity` de GHSA, severidad de la
   herramienta).
3. Si no, `unknown`. El gate trata una CVE `unknown` como `medium`.
4. `MAL-*` (paquetes maliciosos de OSV) → `critical`.

## Prioridad (heurística documentada)

```
base       = CVSS base score si existe, si no peso de severidad
             (critical 9.5, high 7.5, medium 5.0, low 2.5, info 0.5, unknown 5.0)
confianza  = high 1.0 | medium 0.75 | low 0.5
tipo       = vulnerability 1.0 | potential-risk 0.8
exposición = 1.2 dependencia directa, secreto o malware
             1.1 manifiesto desplegable (contenedor/IaC)
             0.7 en tests/fixtures/ejemplos
             1.0 en otro caso
fix        = 1.05 si hay versión corregida (accionable)
prioridad  = min(100, base × 10 × confianza × tipo × exposición × fix)
```

Etiquetas: **P1** ≥ 80, **P2** ≥ 55, **P3** ≥ 30, **P4** < 30.

Ejemplos reales de los fixtures:

| Hallazgo | Cálculo | Prioridad |
|---|---|---|
| CVE-2020-8203 en lodash (CVSS 7.4, directa, con fix) | 7.4×10×1×1×1.2×1.05 | 93 (P1) |
| AWS key en `config.js` (high, confianza high) | 7.5×10×1×0.8×1.2 | 72 (P2) |
| `eval()` en JS (medium, confianza medium) | 5×10×0.75×0.8 | 30 (P3) |

Cuando varias herramientas coinciden, la confianza sube un nivel antes de puntuar
(corroboración independiente). Por eso un hallazgo heurístico confirmado por dos
herramientas puede superar al de una sola.

## Gate de CI (`--fail-on`)

Un hallazgo cuenta si:

- está **abierto** (no `ignored`, `false-positive` ni `accepted`);
- su severidad es ≥ el umbral;
- si es `potential-risk`, su confianza es ≥ `fail_on_potential_min_confidence` (`medium` por defecto).
