# Limitaciones conocidas

SecureProjects reduce el riesgo, **no lo elimina**. La ausencia de hallazgos no prueba la
ausencia de vulnerabilidades.

## Vulnerabilidades en dependencias (`kind: vulnerability`)

- Una coincidencia significa que la **versión instalada cae en un rango afectado publicado**.
  No significa que el código vulnerable sea alcanzable desde tu aplicación: no hay análisis de
  alcanzabilidad.
- **Base OSV nativa**:
  - Hay que descargarla explícitamente (`db update`). Sin ella, y sin Trivy/OSV-Scanner, el
    informe lo advierte: *"dependency CVE scanning not available"*. **No** muestra
    "0 vulnerabilidades".
  - Avisa cuando tiene más de `vulndb.max_age_days` días. Las CVE publicadas después de la
    última actualización no se detectan.
  - Ecosistemas soportados: Go, npm, PyPI, Maven, RubyGems, Packagist, crates.io y NuGet.
    Los paquetes de sistema operativo (apk/deb/rpm) y las imágenes de contenedor quedan
    cubiertos solo vía Trivy.
  - Solo se analizan **versiones exactas** (lockfiles o pins `==`). Los rangos sin lockfile
    (`^1.2`, `>=2`) no se pueden comparar y se reportan como riesgo potencial de "dependencia
    sin fijar".
  - En `go.mod` se usan las directivas `require`. En `pom.xml` solo se resuelven propiedades
    del mismo archivo: no hay herencia de POM padre ni BOM, y para eso conviene usar Trivy u
    OSV-Scanner. Gradle requiere `gradle.lockfile`.
  - Los comparadores Maven, RubyGems, NuGet y Packagist son simplificados; esas coincidencias
    por rango se marcan con `confidence: medium`.
  - Algunas fuentes (p. ej. la base de Go) no publican severidad, así que esos hallazgos salen
    con `severity: unknown`. Para el gate cuentan como `medium`.
  - CVSS v4: se conserva el vector, pero no se calcula la puntuación.
- No se puede saber si una dependencia está **muy desactualizada** sin consultar el registro
  (npm, PyPI…), lo que requiere red y revelaría la lista de dependencias. Por privacidad no se
  hace.

## Riesgos potenciales (heurísticos)

- **SAST nativo**: reglas de una sola línea con expresiones regulares, sin flujo de datos ni
  análisis entre archivos. Produce falsos positivos (p. ej. `eval` sobre una constante) y
  falsos negativos (código multilínea, alias de imports). Semgrep y Bandit amplían mucho la
  cobertura.
- **Secretos**:
  - Patrones y entropía, como gitleaks. Los secretos sin prefijo reconocible y con baja
    entropía pueden escapar.
  - Los placeholders conocidos (p. ej. `AKIAIOSFODNN7EXAMPLE`) se marcan como falso positivo.
  - El historial Git solo se analiza con Gitleaks.
  - **No** se verifica si un secreto está activo: eso exigiría llamar a la API del proveedor.
- **IaC nativo**:
  - Terraform: análisis por líneas, sin evaluar variables, módulos ni `count`/`for_each`.
  - Kubernetes: manifiestos YAML planos. Las plantillas Helm no se renderizan; kube-linter y
    Checkov sí las procesan.
  - CloudFormation: reglas mínimas.
- **Dockerfile**: análisis estático de instrucciones. No se inspeccionan imágenes construidas;
  para eso, `trivy image` queda fuera del alcance actual.

## Deduplicación

- Se fusionan duplicados por fingerprint, por identificadores de vulnerabilidad compartidos y,
  en hallazgos con ubicación, por familia de regla y archivo/línea/recurso.
- Dos herramientas que describen el mismo problema con reglas no mapeadas a una familia común
  pueden aparecer por separado.
- El emparejamiento por CWE en SAST exige la misma línea.

## Herramientas externas

- Cada herramienta tiene sus propios falsos positivos. Las severidades de Checkov sin API key
  no vienen en la salida y se asume `medium`.
- **Semgrep** en Windows nativo es beta: se recomienda la imagen Docker. En modo offline solo
  se usan las reglas embebidas y las del usuario. `p/default` requiere `--online`.
- **KICS** consulta GitHub para buscar versiones nuevas y no se puede desactivar. Por eso está
  deshabilitado por defecto y, en offline, solo se ejecuta en Docker con `--network none`.
- **Trivy y OSV-Scanner** necesitan descargar sus bases públicas la primera vez (`--online`).
  En modo offline sin base, se marcan como `skipped` con instrucciones.
- **Bandit** no tiene imagen oficial y solo se usa si está instalado localmente.
- **ZAP**: solo el baseline (pasivo) vía Docker. No hay autenticación ni escaneo activo de
  ataques.
- Las imágenes están fijadas a versiones concretas y conviene actualizarlas periódicamente.

## Plataforma

- Windows: probado en Windows 11 con Docker Desktop. Los colores ANSI se activan en consolas
  con soporte VT. El modo Docker en Linux/macOS usa los mismos argumentos.
- La caché de resultados se invalida con cambios en el contenido, la versión de la herramienta
  o la configuración, y caduca a las 24 h para no servir datos de vulnerabilidades obsoletos.
  `--no-cache` la desactiva.

## LLM

Opcional y no autoritativo. Puede equivocarse o "alucinar". Sus textos se etiquetan como
explicaciones generadas y nunca cambian severidad, tipo ni el gate de CI.
