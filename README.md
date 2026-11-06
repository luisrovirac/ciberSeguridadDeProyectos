# SecureProjects

CLI en Go, multiplataforma (Linux, macOS, Windows), que escanea proyectos locales o
repositorios Git y reporta:

1. **Vulnerabilidades conocidas** (`kind: vulnerability`): CVE/GHSA/OSV en dependencias,
   comprobadas contra una base de datos de vulnerabilidades y una versión exacta.
2. **Riesgos potenciales** (`kind: potential-risk`): secretos, malas configuraciones de
   Docker/Kubernetes/Terraform, patrones de código peligrosos y dependencias sin fijar.
   Cada uno lleva `confidence: low|medium|high`. **Nunca se presentan como CVE confirmadas.**

SecureProjects es un **orquestador híbrido**:

- **Analizadores nativos** (sin instalar nada): secretos (patrones + entropía), Dockerfile,
  IaC (Terraform, Kubernetes, docker-compose, CloudFormation), funciones peligrosas
  (Go/Python/JS), dependencias sin fijar, reglas YAML propias y un **comparador de dependencias
  contra la base pública OSV descargada localmente** (funciona offline).
- **Adaptadores** para herramientas open source, ejecutadas como binario local o como imagen
  Docker fijada: Trivy, OSV-Scanner, Gitleaks, Semgrep, Hadolint, kube-linter, Checkov,
  KICS, Bandit y OWASP ZAP (solo DAST autorizado).
- Normaliza todo a un modelo común, **deduplica entre herramientas**, puntúa, aplica
  triaje y genera **tabla, JSON versionado, SARIF 2.1.0 y HTML autocontenido**.

> ⚖️ **Escanea solo proyectos propios o para los que tengas autorización.** Ver [SECURITY.md](SECURITY.md).

---

## Instalación

Requiere Go ≥ 1.24 para compilar (se probó con Go 1.26).

```bash
go install github.com/luisrovirac/ciberSeguridadDeProyectos/cmd/secureprojects@latest
# o desde el código:
make build             # -> bin/secureprojects  (Windows: bin/secureprojects.exe)
```

Windows sin `make`:

```powershell
go build -trimpath -o bin\secureprojects.exe .\cmd\secureprojects
```

### Herramientas externas (opcionales)

```bash
secureprojects tools check
```

Muestra qué herramientas están disponibles (binario local o imagen Docker) con instrucciones
de instalación para las que faltan. Con `runner: auto` (por defecto) se usa el binario local
si existe y, si no, la imagen Docker fijada (si Docker está disponible y la imagen ya está
descargada; en modo `--online` se descarga).

| Herramienta | Qué aporta | Imagen fijada |
|---|---|---|
| Trivy | CVE en dependencias, IaC, Dockerfile, secretos | `aquasec/trivy:0.76.2` |
| OSV-Scanner | CVE en dependencias (base OSV local) | `ghcr.io/google/osv-scanner:v2.7.0` |
| Gitleaks | Secretos en archivos e **historial Git** | `zricethezav/gitleaks:v8.30.1` |
| Semgrep CE | SAST multi-lenguaje | `semgrep/semgrep:1.184.0` |
| Hadolint | Dockerfiles | `hadolint/hadolint:v2.15.1` |
| kube-linter | Manifiestos Kubernetes / Helm | `stackrox/kube-linter:v0.8.3` |
| Checkov | IaC (Terraform, K8s, CFN, Dockerfile…) | `bridgecrew/checkov:3.4.3` |
| KICS | IaC (opt-in: `scanners.settings.kics.enabled: true`) | `checkmarx/kics:v2.2.0` |
| Bandit | SAST Python (solo binario local: `pip install bandit`) | — |
| OWASP ZAP | DAST baseline, **solo con autorización explícita** | `ghcr.io/zaproxy/zaproxy:stable` |

### Base de datos OSV local (recomendado)

Para detectar CVE en dependencias **sin herramientas externas y sin red durante el escaneo**:

```bash
secureprojects db update          # descarga explícita de exports públicos de osv.dev
secureprojects db status
secureprojects db import all.zip --ecosystem npm   # entornos aislados (mirror)
```

Solo se hacen peticiones `GET` de archivos públicos; nunca se envía información del proyecto.

---

## Uso

```bash
secureprojects scan .                                       # tabla en consola, offline, modo seguro
secureprojects scan ./svc -f table,json,sarif,html -o reports --fail-on high
secureprojects scan --repo https://github.com/org/repo      # clon temporal, se borra al terminar
secureprojects scan . -c secureprojects.yaml                # configuración YAML
secureprojects scan . --online                              # deja que Trivy/OSV-Scanner actualicen sus BD
secureprojects scan . --baseline reports/secureprojects-report.json --diff   # solo hallazgos nuevos
secureprojects scan . --runner docker --only native-secrets,gitleaks
secureprojects report merge a.json b.json -f html,sarif -o merged
secureprojects version
```

### Flags principales de `scan`

| Flag | Descripción |
|---|---|
| `--repo <url>` | Clona (https/ssh/`git@`) en un directorio temporal y lo elimina siempre al terminar |
| `-c, --config <archivo>` | Configuración YAML (ver [`secureprojects.example.yaml`](secureprojects.example.yaml)) |
| `-f, --format` | `table,json,sarif,html,md` (sin `-f`, al terminar pregunta si generar el `.md`) |
| `-o, --output <dir>` | Directorio de informes (`secureprojects-report` por defecto) |
| `--fail-on` | `critical\|high\|medium\|low\|info\|none` (por defecto `high`) |
| `--baseline <json>` / `--diff` | Compara con un informe previo / muestra solo lo nuevo |
| `--offline` (defecto) / `--online` | Sin red / permitir actualizar BD de herramientas y descargar imágenes |
| `--safe` (defecto) | Sin pruebas intrusivas |
| `--allow-active-scan --target-url <url>` | DAST con ZAP baseline. Requiere `--i-have-authorization` o confirmación interactiva |
| `--runner auto\|local\|docker` | Cómo ejecutar herramientas externas |
| `--only`, `--disable` | Seleccionar escáneres |
| `--rules <yaml>` | Reglas personalizadas ([ejemplo](examples/secureprojects-rules.example.yaml)) |
| `--ignore-file <yaml>` | Triaje con justificación obligatoria ([ejemplo](examples/secureprojects-ignore.example.yaml)) |
| `--no-git-history`, `--no-cache` | Desactivar historial Git / caché |
| `--llm-explain --llm-consent` | Explicaciones opcionales por LLM (no autoritativas) |
| `--tool-timeout`, `--scan-timeout`, `--max-file-size` | Límites de recursos |

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Ningún hallazgo abierto alcanza el umbral `--fail-on` |
| `1` | Hay hallazgos abiertos ≥ umbral |
| `2` | Error de ejecución |
| `3` | Configuración o uso inválido |

Los hallazgos suprimidos (ignorados, falsos positivos, aceptados) nunca hacen fallar el CI, y
tampoco los riesgos potenciales con confianza menor que `fail_on_potential_min_confidence`
(`medium` por defecto). Una CVE sin severidad conocida cuenta como `medium`.

---

## Qué es "confirmado" y qué es "potencial"

| | `vulnerability` (CONFIRMED) | `potential-risk` (POTENTIAL) |
|---|---|---|
| Origen | Base de vulnerabilidades (OSV, Trivy DB) cruzada con la **versión exacta** instalada | Heurísticas, patrones, entropía o reglas de política (Checkov, kube-linter, Hadolint…) |
| Ejemplo | `CVE-2020-8203 in lodash@4.17.15` | AWS key en `config.js`, contenedor como root, `eval()` |
| Garantía | La versión está en el rango afectado publicado. **No** garantiza que el código vulnerable sea alcanzable | Puede ser un falso positivo; revisar. La confianza indica cuán probable es |

En la tabla y el HTML se muestran como `CONFIRMED` / `potential`. En SARIF, los riesgos
potenciales llevan el prefijo `[potential risk, confidence X]` en el mensaje.

---

## Informes

- **Tabla**: resumen ejecutivo, estado de cada escáner (con instrucciones si falta), hallazgos
  ordenados por prioridad y decisión del gate de CI. Colores opcionales (`--no-color`, `NO_COLOR`).
- **JSON** (`schemaVersion: 1.0.0`): estable y determinista (claves y hallazgos ordenados);
  incluye fecha, versión, commit, rama, configuración usada (redactada), perfil detectado,
  estado de cada escáner, resumen por severidad/tipo/categoría/herramienta/archivo y hallazgos.
- **SARIF 2.1.0**: validado en los tests contra el esquema oficial de OASIS; incluye
  `partialFingerprints`, `security-severity` (GitHub), CWE como tags y supresiones.
- **HTML autocontenido**: sin recursos externos, CSP estricta (script autorizado por hash),
  filtros por severidad/tipo/categoría/herramienta/confianza, búsqueda, detalle con remediación.

Ningún informe contiene secretos en claro: todo pasa por el redactor (también los logs).

---

## Integración CI/CD

### GitHub Actions

```yaml
name: security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # subir SARIF a Code Scanning
jobs:
  secureprojects:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }           # historial completo para gitleaks
      - uses: actions/setup-go@v5
        with: { go-version: "1.26" }
      - name: Install SecureProjects
        run: go install github.com/luisrovirac/ciberSeguridadDeProyectos/cmd/secureprojects@latest
      - name: Cache OSV database and tool DBs
        uses: actions/cache@v4
        with:
          path: ~/.cache/secureprojects
          key: secureprojects-${{ github.run_id }}
          restore-keys: secureprojects-
      - name: Update OSV database
        run: secureprojects db update
      - name: Scan
        run: |
          secureprojects scan . --online --runner auto \
            -f table,json,sarif,html -o reports --fail-on high
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: reports/secureprojects-report.sarif }
      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with: { name: secureprojects-reports, path: reports }
```

Solo hallazgos nuevos en PR: guarda el JSON de `main` como artefacto y usa
`--baseline main-report.json --diff`. El workflow completo está en
[`examples/github-actions.yml`](examples/github-actions.yml).

### GitLab CI

```yaml
secureprojects:
  image: golang:1.26
  script:
    - go install github.com/luisrovirac/ciberSeguridadDeProyectos/cmd/secureprojects@latest
    - secureprojects db update
    - secureprojects scan . -f table,sarif,json -o reports --fail-on high
  artifacts:
    when: always
    paths: [reports/]
```

---

## Privacidad

- **Sin telemetría**, nunca. A las herramientas externas se les fuerza a desactivarla
  (`SEMGREP_SEND_METRICS=off`, `--disable-telemetry`, etc.).
- **Offline por defecto**: sin red durante el escaneo. En Docker se usa `--network none`.
- **Nunca se sube código**. OSV-Scanner se ejecuta en modo de base local, así que la lista de
  dependencias no se envía a api.osv.dev, y Trivy usa `--offline-scan`. Las herramientas solo
  reciben un entorno mínimo: no heredan tokens ni credenciales de tu shell.
- La red solo se usa con acciones explícitas: `db update`, `--online`, `--repo`, DAST y LLM.

## Integración opcional con LLM

Está deshabilitada por defecto. Requiere `--llm-explain --llm-consent` (o `llm.enabled` +
`llm.consent` en YAML). Se aplica solo a los hallazgos más importantes (por defecto ≥ high,
máximo 20), y solo para **explicar y proponer remediaciones**: nunca decide si algo es una
vulnerabilidad, y el texto se marca como *non-authoritative*. Por defecto se envían únicamente
metadatos del hallazgo (título, regla, CWE/CVE, paquete y severidad). La línea de evidencia
(redactada) solo se envía con `llm.send_snippets: true`, y nunca se envían archivos. Proveedor:
Anthropic (SDK oficial), modelo configurable (`claude-opus-5-5` por defecto) y clave en
`ANTHROPIC_API_KEY`.

---

## Desarrollo

```bash
make test       # go test ./...
make lint       # golangci-lint run
make build
make run TARGET=testdata/fixtures/node-app
```

Los tests usan fixtures en `testdata/fixtures` (Go, Node.js, Python, IaC), **registros OSV
reales** en `testdata/osv` y **salidas reales grabadas** de cada herramienta en
`testdata/tool-outputs` (ver su README). No hay CVE inventadas.

Documentación adicional: [arquitectura](docs/architecture.md), [modelo de datos y scoring](docs/scoring.md),
[reglas nativas](docs/rules.md), [adaptadores](docs/adapters.md), [plan por hitos](docs/plan.md),
[limitaciones](LIMITATIONS.md) y [seguridad](SECURITY.md).

Licencia: elige una antes de publicar (las regex inspiradas en gitleaks provienen de un proyecto MIT; ver `docs/rules.md`).
