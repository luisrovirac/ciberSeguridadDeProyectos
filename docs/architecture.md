# Arquitectura

```
cmd/secureprojects/main.go        -> cli.Execute() (códigos de salida 0/1/2/3)
internal/
  cli/            Cobra: scan, tools check, report merge, db update|status|import, version
  app/            Pipeline de escaneo end-to-end (testeable sin CLI)
  config/         Config tipada, defaults seguros, validación (ErrInvalid -> exit 3), carga YAML+env (Viper)
  detector/       Perfil del proyecto: lenguajes, ecosistemas, manifiestos, Docker, IaC, .git
  fsutil/         Recorrido acotado (sin seguir symlinks), globs con **, lectura limitada, detección binaria
  execx/          Ejecución segura de herramientas: local o docker, sin shell, timeouts, entorno mínimo
  scanners/       Interfaz Scanner, motor concurrente (errgroup + límite), estados por escáner
    native/       Analizadores propios (secretos, dockerfile, iac, sast heurístico, deps, custom, osv)
    trivy/ osv/ gitleaks/ semgrep/ hadolint/ kubelinter/ iac/(checkov,kics) bandit/ zap/
    registry/     Lista ordenada de escáneres
  vulndb/         Base OSV local: descarga, índice compacto, matcher; lockfiles/; version/ (semver, PEP 440, Maven, Gem)
  finding/        Modelo común, severidad/confianza, fingerprint, IDs canónicos
  normalizer/     CVSS v2/v3 (cálculo de base score), rutas relativas (incl. /src de docker)
  redact/         Redacción de secretos (strings + slog.Handler)
  dedup/          Fusión entre herramientas (union-find) y agrupación
  scoring/        Prioridad 0-100
  policy/         Archivo de ignorados, falsos positivos conocidos, baseline/diff, gate --fail-on
  cache/          Caché de resultados por hash de contenido + versión + config (TTL 24 h)
  report/         Modelo de informe v1, JSON, SARIF 2.1.0, HTML (embed), tabla
  gitinfo/        Commit/rama/remoto, clon temporal endurecido
  llm/            Explicaciones opcionales (Anthropic SDK), no autoritativas
  toolcache/      Directorios de caché por herramienta (BD de Trivy, OSV-Scanner)
```

## Flujo de `scan`

```
config (defaults < YAML < env < flags) -> Validate
  -> [--repo] clon temporal endurecido (defer cleanup)
  -> detector.Detect (perfil)        -> gitinfo.Read (commit/rama)
  -> scanners.ListFiles (límites)    -> Engine.Run (concurrencia = limits.concurrency)
        para cada escáner: Selected? -> Resolve (local/docker/ausente) -> caché -> Scan
        normalización + redacción + fingerprint + Validate por hallazgo
        errores/ausencias -> estado skipped|error, nunca abortan el resto
  -> dedup.Merge -> policy (falsos positivos conocidos, ignorados) -> scoring -> orden estable
  -> baseline/diff -> [LLM opcional] -> gate --fail-on -> informe
  -> salidas: tabla (stdout), JSON, SARIF, HTML
```

## Interfaz de adaptadores

```go
type Scanner interface {
    Name() string
    Native() bool
    Applicable(p *detector.Profile, cfg *config.Config) bool
    Tool() *execx.Tool            // nil para nativos: binario, imagen, versión, instrucciones
    Scan(ctx context.Context, req *Request, res execx.Resolution) ([]finding.Finding, error)
}
```

- La disponibilidad (`Available` en el plan) la resuelve el motor con `execx.Runner.Resolve(Tool)`,
  que devuelve `local | docker | none` y el motivo, de modo que cada adaptador no repite esa lógica.
- `scanners.Skip(reason)` permite que un escáner informe "no aplicable por un motivo esperado"
  (p. ej. falta la base OSV) sin marcarse como error.
- `CacheKeyer` (opcional) añade entradas propias a la clave de caché (p. ej. fecha del índice OSV).
- Cada adaptador expone un `Parse([]byte, root)` puro, probado con salidas reales grabadas.

Para añadir una herramienta:

1. Crea `internal/scanners/<tool>` con `Tool()`, `Applicable()`, `Scan()` y `Parse()`.
2. Mapea sus reglas a familias comunes (`RuleFamily`) para que deduplique.
3. Regístrala en `registry.All`.
4. Graba una salida real en `testdata/tool-outputs` y añade un test.

## Modo docker

`docker run --rm --pull=missing --security-opt no-new-privileges --cap-drop ALL --memory <limits.docker_memory>
[--network none] -v <proyecto>:/src:ro [-v <salida>:/out] [-v <caché>:/cache] -e <privacidad> <imagen fijada> <args>`.
Los marcadores `{{src}}`, `{{out}}` y `{{cache}}` de los argumentos se sustituyen según el modo.

## Deduplicación

Ver el comentario de paquete de `internal/dedup`. Resumen:

1. Fingerprint idéntico.
2. Vulnerabilidades de dependencias: mismo `paquete@versión` y algún identificador compartido
   (CVE, GHSA, OSV, alias). Esto une GO-…, GHSA-… y CVE-… de la misma vulnerabilidad.
3. Hallazgos con ubicación, siempre de herramientas distintas: misma familia de regla y
   líneas a ±1. En IaC y contenedores también cuentan el mismo recurso o rangos solapados;
   en familias de nivel de archivo (root, healthcheck) basta el mismo archivo; para secretos,
   la misma línea; para SAST, misma línea y CWE compartido.

El hallazgo fusionado conserva el CVSS más rico, la unión de herramientas, CVE, CWE y
referencias, y la severidad máxima si no hay CVSS. Además sube un nivel de confianza
("corroborated") y mantiene el fingerprint del analizador nativo si existe, para que la
identidad sea estable aunque se instalen o desinstalen herramientas.
