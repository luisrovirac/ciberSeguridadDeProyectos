# Reglas nativas

Todas producen `kind: potential-risk`, salvo `native-osv`, que produce `kind: vulnerability`.
Una línea con `secureprojects:ignore` (o `gitleaks:allow`, `nosec`, `nosemgrep`) se omite.

## native-secrets (CWE-798)

Patrones con capturas y umbral de entropía de Shannon (bits por byte, como gitleaks):

| Regla | Patrón (resumen) | Entropía mínima |
|---|---|---|
| aws-access-key-id | `(A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}` | 3 |
| github-pat / fine-grained / oauth | `ghp_…{36}`, `github_pat_…{82}`, `gh[ousr]_…{36}` | 3 |
| gitlab-pat | `glpat-…{20}` | 3 |
| private-key | `-----BEGIN … PRIVATE KEY-----` | — |
| slack-token / slack-webhook | `xox[baprs]-…`, `hooks.slack.com/…` | 3 / — |
| stripe-key | `(sk\|rk)_(test\|live\|prod)_…` | 2 |
| gcp-api-key | `AIza…{35}` | 4 |
| openai / anthropic / npm | `sk-…T3BlbkFJ…`, `sk-ant-…`, `npm_…{36}` | 3 |
| jwt | `ey….ey….…` | 3 |
| url-credentials | `scheme://user:pass@host` | 3 |
| generic-secret | `(key\|secret\|token\|passw(or)d\|auth\|…) = valor` | 3.5, y el valor debe tener letras y dígitos |

- Los placeholders (`example`, `changeme`, `${…}`, `<…>`, `os.getenv`, `xxxx`, …) se descartan
  en la regla genérica. En las reglas específicas se rebajan a `confidence: low` con la
  etiqueta `placeholder`, y la política los marca como **falso positivo conocido**.
- En `.env*` la severidad mínima es `high`. En rutas de tests la confianza baja un nivel.
- Se omiten lockfiles, binarios y archivos minificados.
- *Atribución*: varias regex están adaptadas de la configuración por defecto de
  [gitleaks](https://github.com/gitleaks/gitleaks) (licencia MIT).

## native-dockerfile

| Regla | Familia | Severidad |
|---|---|---|
| SP-DOCKER-ROOT-USER: sin `USER`, o `USER root/0` en la etapa final | dockerfile.root-user | high |
| SP-DOCKER-UNPINNED-IMAGE / LATEST-TAG | dockerfile.unpinned-image | medium |
| SP-DOCKER-ADD-URL / SP-DOCKER-ADD | dockerfile.add-instead-of-copy | medium / low |
| SP-DOCKER-CURL-PIPE-SH (`curl … \| sh`) | dockerfile.curl-pipe-shell | medium |
| SP-DOCKER-CHMOD-777 | dockerfile.world-writable | medium |
| SP-DOCKER-SUDO | dockerfile.sudo | low |
| SP-DOCKER-SECRET-IN-ENV / ARG | dockerfile.secret-in-env | high |
| SP-DOCKER-EXPOSE-SSH | dockerfile.expose-ssh | medium |
| SP-DOCKER-NO-HEALTHCHECK | dockerfile.no-healthcheck | info |

## native-iac

- **Terraform**:
  - SP-IAC-OPEN-INGRESS: `0.0.0.0/0` o `::/0` en ingress; los bloques egress se ignoran.
  - SP-IAC-PUBLIC-ACL: `acl = public-read*`.
  - SP-IAC-PUBLIC-ACCESS-BLOCK-OFF.
  - SP-IAC-UNENCRYPTED: `encrypted`/`storage_encrypted = false`.
  - SP-IAC-PUBLIC-DB: `publicly_accessible = true`.
  - SP-IAC-PLAINTEXT-LISTENER.
- **Kubernetes** (Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob…):
  - privileged; hostNetwork/hostPID/hostIPC;
  - `allowPrivilegeEscalation` no desactivado;
  - sin `runAsNonRoot`/UID ≠ 0;
  - rootfs escribible;
  - sin límites de CPU/memoria;
  - imagen `:latest` o sin tag.
- **docker-compose**: `privileged`, `network_mode: host`, montaje de `docker.sock`.
- **CloudFormation**: `CidrIp 0.0.0.0/0`, `PublicRead`.

## native-sast (heurístico, por línea)

| Lenguaje | Reglas |
|---|---|
| Go | exec vía shell (CWE-78), `InsecureSkipVerify` (CWE-295), md5/sha1 (CWE-328), SQL con Sprintf/concatenación (CWE-89), `math/rand` (CWE-338, info) |
| Python | `eval`/`exec` (CWE-95), pickle/dill/shelve (CWE-502), `yaml.load` sin SafeLoader (CWE-502), `shell=True`/`os.system` (CWE-78), `verify=False` (CWE-295), md5/sha1, `debug=True` (CWE-489), SQL formateado (CWE-89) |
| JS/TS | `eval`/`new Function` (CWE-95), `child_process.exec` con interpolación (CWE-78), `innerHTML`/`document.write` (CWE-79), `dangerouslySetInnerHTML` (CWE-79), `rejectUnauthorized: false` (CWE-295), md5/sha1 |

## native-deps (CWE-1357)

- npm:
  - `*`, `latest`, `x`, `>=`, `||` o URL/git → low (info en devDependencies);
  - `^`/`~` sin lockfile → info.
- PyPI: requisito sin `==` → low; requisito desde URL/VCS → low.
- Go: `replace` a ruta local → info.
- RubyGems: gem sin restricción y sin `Gemfile.lock` → low.

## native-osv

Cruza las versiones exactas de los lockfiles con el índice OSV local. Lockfiles soportados:

| Ecosistema | Archivos |
|---|---|
| Go | `go.mod` |
| npm | `package-lock.json` v1-v3, `npm-shrinkwrap.json`, `yarn.lock` (classic y berry), `pnpm-lock.yaml` |
| PyPI | `requirements*.txt` (`==`), `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| Maven | `pom.xml` (con propiedades locales), `gradle.lockfile` |
| RubyGems | `Gemfile.lock` |
| Packagist | `composer.lock` |
| crates.io | `Cargo.lock` |
| NuGet | `packages.lock.json`, `*.csproj` |

Los rangos `SEMVER`/`ECOSYSTEM` se evalúan según la especificación OSV (`introduced`, `fixed`,
`last_affected`), además de la lista explícita `versions`.

## Reglas personalizadas

Ver [`examples/secureprojects-rules.example.yaml`](../examples/secureprojects-rules.example.yaml).
Campos: `id`, `title`, `pattern` (RE2), `exclude`, `extensions`, `files` (globs), `severity`,
`confidence` (por defecto `low`), `category`, `cwe`, `message`, `remediation`, `references`,
`family`.
