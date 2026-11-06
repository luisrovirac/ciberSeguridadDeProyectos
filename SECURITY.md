# Política de seguridad

## Uso autorizado

SecureProjects es una herramienta **defensiva**. Úsala solo sobre:

- código y repositorios de los que eres propietario, o
- sistemas para los que tienes **autorización explícita y por escrito**.

El modo DAST (`--allow-active-scan`) envía tráfico HTTP a la URL indicada. Escanear sistemas de
terceros sin permiso puede ser **ilegal** en tu jurisdicción. Por eso el modo DAST:

- está desactivado por defecto y es incompatible con `--offline` y `--safe`;
- muestra una advertencia legal y exige `--i-have-authorization` o escribir `yes` de forma interactiva;
- usa solo el **ZAP baseline**: spider y reglas pasivas, sin payloads de ataque;
- nunca ejecuta exploits. SecureProjects no incluye ni ejecuta exploits en ningún modo.

## Diseño seguro de la propia herramienta

| Riesgo | Mitigación |
|---|---|
| Inyección de comandos al lanzar herramientas | `exec.CommandContext` con argumentos separados y nunca un shell; los argumentos con NUL se rechazan |
| Inyección vía `--repo` | Solo `https://`, `ssh://` o `git@host:path`; se rechazan `-…`, `file://`, `ext::` y `http://`. El clon usa `--` como separador, `protocol.ext.allow=never`, `protocol.file.allow=never`, `core.symlinks=false`, hooks desactivados, `--no-recurse-submodules` y `transfer.fsckObjects` |
| Fuga de credenciales del entorno a las herramientas | Entorno mínimo en lista blanca (PATH, HOME, proxies…); no se heredan tokens ni credenciales cloud |
| Secretos en informes y logs | Redactor por patrones aplicado a evidencias, títulos, descripciones, config y logs (`slog.Handler`); Gitleaks se ejecuta con `--redact=100` y Trivy ya enmascara. Los tests verifican que ningún secreto de los fixtures aparece en JSON/SARIF/HTML |
| XSS en el informe HTML | `html/template` con escape automático, CSP `default-src 'none'` con el script autorizado por hash SHA-256, solo enlaces `http(s)` y sin recursos externos |
| Agotamiento de recursos | Límites de tamaño y número de archivos, timeouts global y por herramienta, tope de bytes de salida y `--memory` en Docker |
| Escape de la raíz del proyecto | El recorrido no sigue symlinks; el código se monta en Docker como solo lectura (`:ro`), con `--cap-drop ALL` y `no-new-privileges` |
| Clones temporales que quedan en disco | Se borran siempre con `defer`, incluso con errores (también los objetos de solo lectura en Windows) |
| Telemetría / exfiltración | Sin telemetría; offline por defecto; `--network none` en Docker offline; OSV-Scanner usa la base local |
| Supresiones silenciosas | Cada entrada del archivo de ignorados exige `reason`; admite `expires` y los hallazgos suprimidos siguen apareciendo en los informes |

## Reportar una vulnerabilidad en SecureProjects

No abras un issue público. Envía un informe privado al mantenedor (configura aquí el canal,
por ejemplo GitHub Security Advisories del repositorio) con:

- versión (`secureprojects version`) y sistema operativo;
- pasos de reproducción y su impacto.

Objetivo: acuse de recibo en 72 h y corrección o mitigación coordinada en 90 días como máximo.
