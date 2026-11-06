# Guía de uso de SecureProjects

Esta guía explica, paso a paso, cómo **instalar y activar** SecureProjects y cómo **usarlo**
para revisar la seguridad de un proyecto. Para la referencia completa de flags, formatos e
integraciones, consulta el [README principal](../README.md).

> ⚖️ Escanea solo proyectos propios o para los que tengas autorización. Ver [SECURITY.md](../SECURITY.md).

---

## 1. ¿Qué hace?

SecureProjects es una herramienta de línea de comandos (`secureprojects`) que analiza una
carpeta o un repositorio Git y genera un informe con:

- **Vulnerabilidades confirmadas** (`CONFIRMED`): CVE conocidas en las dependencias, según la
  versión exacta que usa el proyecto.
- **Riesgos potenciales** (`potential`): secretos en el código, Dockerfile inseguros, malas
  configuraciones de Kubernetes/Terraform, funciones peligrosas (`eval`, `yaml.load`…), etc.
  Cada uno indica su nivel de confianza (`low`, `medium`, `high`).

Funciona **sin conexión por defecto**, no envía código a ningún sitio y no tiene telemetría.

---

## 2. Requisitos

| Requisito | ¿Obligatorio? | Para qué |
|---|---|---|
| [Go](https://go.dev/dl/) 1.24 o superior | Sí (para compilar) | Construir el binario |
| Git | Recomendado | Clonar el proyecto, escanear con `--repo` y revisar el historial |
| [Docker](https://docs.docker.com/get-docker/) | Opcional | Usar las herramientas externas (Trivy, Gitleaks, Semgrep…) sin instalarlas una a una |

Sin Docker ni herramientas externas, SecureProjects funciona igual con sus **analizadores
nativos** (secretos, Dockerfile, IaC, código peligroso y dependencias).

---

## 3. Instalación y activación

### Opción rápida: `go install`

Si el repositorio es público, basta con:

```bash
go install github.com/luisrovirac/ciberSeguridadDeProyectos/cmd/secureprojects@latest
```

El binario `secureprojects` queda en la carpeta `bin` de Go (`%USERPROFILE%\go\bin` en
Windows, `~/go/bin` en Linux/macOS), que normalmente ya está en el PATH. Salta al paso
[3.4](#34-comprobar-que-funciona).

### Opción desde el código

### 3.1 Obtener el código

```bash
git clone https://github.com/luisrovirac/ciberSeguridadDeProyectos.git
cd ciberSeguridadDeProyectos
```

### 3.2 Compilar

**Windows (PowerShell):**

```powershell
go build -trimpath -o bin\secureprojects.exe .\cmd\secureprojects
```

**Linux / macOS (o Windows con Git Bash y `make`):**

```bash
make build        # genera bin/secureprojects
```

### 3.3 Añadir el comando al PATH

Así podrás ejecutar `secureprojects` desde cualquier carpeta.

**Windows (PowerShell)** — permanente para tu usuario (abre una terminal nueva después):

```powershell
$bin = (Resolve-Path .\bin).Path
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
[Environment]::GetEnvironmentVariable('Path','User')
```

**Linux / macOS:**

```bash
sudo cp bin/secureprojects /usr/local/bin/
```

Si prefieres no tocar el PATH, ejecútalo con la ruta completa: `.\bin\secureprojects.exe`
(Windows) o `./bin/secureprojects` (Linux/macOS).

### 3.4 Comprobar que funciona

```bash
secureprojects version
```

Debe mostrar algo como:

```
SecureProjects 0.1.0-dev windows/amd64 go1.26.5
JSON report schema 1.0.0
```

### 3.5 Activar la detección de CVE en dependencias (recomendado)

Para encontrar vulnerabilidades conocidas **sin depender de herramientas externas**, descarga
una vez la base de datos pública de OSV:

```bash
secureprojects db update     # descarga (necesita Internet)
secureprojects db status     # muestra qué ecosistemas hay y su antigüedad
```

La base se guarda en la caché del usuario (en Windows:
`%LOCALAPPDATA%\secureprojects\osv`). Repite `db update` de vez en cuando para mantenerla al día.
Después, los escaneos funcionan sin conexión.

¿Equipo sin Internet? Descarga el archivo de OSV en otro equipo e impórtalo:

```bash
secureprojects db import all.zip --ecosystem npm
```

### 3.6 Activar las herramientas externas (opcional)

```bash
secureprojects tools check
```

Muestra qué herramientas están disponibles y cómo instalar las que faltan:

```
TOOL          STATUS     MODE    VERSION/IMAGE
trivy         available  docker  aquasec/trivy:0.76.2
gitleaks      available  docker  zricethezav/gitleaks:v8.30.1
bandit        missing    none
...
```

Tienes dos formas de activarlas:

1. **Con Docker (más fácil):** instala Docker y ejecuta un escaneo con `--online` una vez.
   SecureProjects descargará las imágenes fijadas. Después ya funcionan sin conexión.
   ```bash
   secureprojects scan . --online
   ```
2. **Instalándolas en local:** si el binario (`trivy`, `gitleaks`, `semgrep`…) está en el
   PATH, se usa directamente. Bandit solo funciona así: `pip install bandit`.

Con `--runner auto` (por defecto) se usa el binario local si existe y, si no, Docker.

---

## 4. Uso

### 4.1 Primer escaneo

Desde la carpeta del proyecto que quieres revisar:

```bash
secureprojects scan .
```

Verás en la consola:

1. **Scanners**: qué analizadores se ejecutaron (`ok`), cuáles se omitieron (`skipped`) y por qué.
2. **Summary**: total de hallazgos por severidad y tipo.
3. **Findings**: lista ordenada por prioridad (`P1` es lo más urgente).

Ejemplo de hallazgos:

```
PRIO    SEVERITY  KIND       CONF  LOCATION          TITLE
P1 100  critical  CONFIRMED  high  requirements.txt  CVE-2020-14343 in pyyaml@5.3 ...
P1 91   critical  potential  high  settings.py:2     GitHub Personal Access Token in settings.py
P2 66   high      potential  high  Dockerfile:5      Image user should not be 'root'
```

Puedes probarlo con los proyectos de ejemplo incluidos:

```bash
secureprojects scan testdata/fixtures/python-app
```

### 4.2 Generar informes en archivo

Al terminar un `secureprojects scan .` desde la terminal (sin `-f`), se te pregunta:

```
¿Generar el informe en Markdown en C:\ruta\actual\secureprojects-report.md? [S/n]:
```

Pulsa Enter (o `s`) para crearlo en el directorio actual, o `n` para omitirlo. La pregunta no
aparece en CI, con `-q` ni cuando eliges formatos con `-f`.

Para elegir los formatos tú mismo:

```bash
secureprojects scan . -f table,json,sarif,html,md -o reports
```

Crea en `reports/`:

| Archivo | Para qué sirve |
|---|---|
| `secureprojects-report.html` | Abrir en el navegador: filtros, búsqueda y cómo corregir cada hallazgo |
| `secureprojects-report.json` | Procesar con otras herramientas o usar como línea base |
| `secureprojects-report.sarif` | Subir a GitHub Code Scanning u otros visores SARIF |
| `secureprojects-report.md` | Leer en el editor, GitHub o adjuntar a un ticket (sin `-o`, se escribe en el directorio actual) |

Los secretos **nunca** aparecen en claro en los informes: siempre se ocultan.

### 4.3 Casos habituales

```bash
# Escanear un repositorio remoto (se clona en una carpeta temporal y se borra al terminar)
secureprojects scan --repo https://github.com/org/repo

# Ejecutar solo algunos analizadores
secureprojects scan . --only native-secrets,gitleaks

# Desactivar uno
secureprojects scan . --disable semgrep

# Ver solo los hallazgos nuevos respecto a un informe anterior
secureprojects scan . --baseline reports/secureprojects-report.json --diff

# Unir varios informes en uno
secureprojects report merge a.json b.json -f html -o merged

# Más detalle de lo que pasa por dentro
secureprojects scan . --log-level debug
```

### 4.4 Usar un archivo de configuración

Copia el ejemplo y ajústalo:

```bash
cp secureprojects.example.yaml secureprojects.yaml
secureprojects scan . -c secureprojects.yaml
```

El archivo **no se carga solo**: hay que indicarlo con `-c`. El orden de prioridad es:
valores por defecto < archivo YAML < variables `SECUREPROJECTS_*` < flags de la línea de comandos.

```bash
# Ejemplo con variable de entorno (PowerShell: $env:SECUREPROJECTS_FAIL_ON = "critical")
SECUREPROJECTS_FAIL_ON=critical secureprojects scan .
```

### 4.5 Ignorar hallazgos revisados

Si un hallazgo es un falso positivo o un riesgo aceptado, crea `.secureprojects-ignore.yaml`
en la raíz del proyecto escaneado (se carga automáticamente). Cada entrada **debe** incluir
un motivo:

```yaml
ignores:
  - rule: SP-DOCKER-NO-HEALTHCHECK
    path: "deploy/**"
    status: accepted          # ignored | false-positive | accepted
    reason: Las sondas de salud están definidas en Kubernetes.

  - cve: CVE-2020-8203
    package: lodash
    reason: Solo se usa al compilar; la función vulnerable nunca se llama.
    expires: 2027-03-31       # volver a revisar después de esta fecha
```

Los hallazgos ignorados siguen apareciendo en los informes (marcados), pero no hacen fallar el CI.
Ejemplo completo: [`examples/secureprojects-ignore.example.yaml`](../examples/secureprojects-ignore.example.yaml).

### 4.6 Reglas propias

```bash
secureprojects scan . --rules mis-reglas.yaml
```

Ver [`examples/secureprojects-rules.example.yaml`](../examples/secureprojects-rules.example.yaml).

---

## 5. Resultado del comando (para scripts y CI)

| Código | Significado |
|---|---|
| `0` | Ningún hallazgo abierto llega al umbral `--fail-on` |
| `1` | Hay hallazgos abiertos iguales o por encima del umbral |
| `2` | Error durante la ejecución |
| `3` | Configuración o uso incorrecto |

El umbral por defecto es `high`. Para que solo falle con lo crítico: `--fail-on critical`.
Para que nunca falle: `--fail-on none`.

---

## 6. Activarlo en CI/CD

Para que cada `push` o pull request se revise automáticamente en GitHub, copia
[`examples/github-actions.yml`](../examples/github-actions.yml) en
`.github/workflows/security.yml` de tu repositorio. El workflow:

1. Compila e instala SecureProjects.
2. Descarga la base OSV (`db update`).
3. Escanea con `--fail-on high`, de modo que el CI falla si hay hallazgos graves.
4. Sube el SARIF a la pestaña **Security → Code scanning** y guarda los informes como artefacto.

> El paso de instalación usa `go install`, que descarga el código desde GitHub: el
> repositorio debe ser **público**. Si es privado, configura `GOPRIVATE` y un token de acceso.

Hay un ejemplo para GitLab CI en el [README principal](../README.md#gitlab-ci).

---

## 7. Funciones opcionales (desactivadas por defecto)

| Función | Cómo se activa |
|---|---|
| **KICS** (IaC) | En el YAML: `scanners.settings.kics.enabled: true` |
| **Escaneo dinámico con OWASP ZAP** | `--allow-active-scan --target-url https://mi-app --i-have-authorization`. Solo contra aplicaciones propias o con permiso explícito |
| **Explicaciones con IA (Claude)** | Define `ANTHROPIC_API_KEY` y usa `--llm-explain --llm-consent`. Solo envía metadatos del hallazgo, nunca archivos |
| **Modo con red** | `--online`: permite actualizar las bases de las herramientas y descargar imágenes Docker |
| **Sin historial Git** | `--no-git-history` para no revisar commits antiguos con Gitleaks |

---

## 8. Ejecutarlo con Docker (sin instalar Go)

```bash
docker build -t secureprojects .
docker run --rm -v "$PWD:/src:ro" -v "$PWD/reports:/reports" secureprojects scan /src -o /reports -f table,json,sarif
```

Esta imagen solo trae los analizadores nativos; no incluye las herramientas externas.

---

## 9. Problemas frecuentes

| Mensaje | Solución |
|---|---|
| `native-osv skipped ... no local OSV database` | Ejecuta `secureprojects db update` |
| `osv-scanner ... run once with --online` | Ejecuta un escaneo con `--online` una vez para que descargue su base |
| `docker image ... not pulled and --offline forbids pulling` | Ejecuta con `--online` o descarga la imagen con `docker pull <imagen>` |
| `"bandit" not found in PATH` | `pip install bandit` (o ignóralo: es opcional) |
| `secureprojects: command not found` / no se reconoce el comando | Revisa el paso [3.3](#33-añadir-el-comando-al-path) o usa la ruta completa al binario |
| El CI falla con código `1` | Hay hallazgos ≥ `--fail-on`. Corrígelos, súbelos de umbral o tríalos en `.secureprojects-ignore.yaml` |

---

## 10. Más documentación

- [README principal](../README.md): referencia completa de flags, informes y privacidad
- [Arquitectura](architecture.md)
- [Reglas nativas](rules.md)
- [Adaptadores de herramientas externas](adapters.md)
- [Puntuación y modelo de datos](scoring.md)
- [Limitaciones](../LIMITATIONS.md)
