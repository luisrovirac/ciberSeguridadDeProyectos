package native

import (
	"context"
	"regexp"
	"strings"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/redact"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

// Dockerfile checks Dockerfiles for common insecure patterns.
type Dockerfile struct{ base }

// NewDockerfile creates the analyzer.
func NewDockerfile() *Dockerfile { return &Dockerfile{base{"native-dockerfile"}} }

// Applicable when Dockerfiles exist.
func (d *Dockerfile) Applicable(p *detector.Profile, _ *config.Config) bool {
	return len(p.Dockerfile) > 0
}

// Instruction is one logical Dockerfile instruction (continuations joined).
type Instruction struct {
	Cmd  string // upper-case keyword
	Args string
	Line int // 1-based line where it starts
}

// ParseDockerfile splits a Dockerfile into instructions.
func ParseDockerfile(data []byte) []Instruction {
	var out []Instruction
	var cur strings.Builder
	start := 0
	for i, l := range lines(data) {
		t := strings.TrimSpace(l)
		if cur.Len() == 0 && (t == "" || strings.HasPrefix(t, "#")) {
			continue
		}
		if cur.Len() > 0 && strings.HasPrefix(t, "#") {
			continue
		}
		if cur.Len() == 0 {
			start = i + 1
		}
		if strings.HasSuffix(t, "\\") {
			cur.WriteString(strings.TrimSuffix(t, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(t)
		full := cur.String()
		cur.Reset()
		cmd, args, _ := strings.Cut(full, " ")
		out = append(out, Instruction{Cmd: strings.ToUpper(cmd), Args: strings.TrimSpace(args), Line: start})
	}
	if cur.Len() > 0 {
		cmd, args, _ := strings.Cut(cur.String(), " ")
		out = append(out, Instruction{Cmd: strings.ToUpper(cmd), Args: strings.TrimSpace(args), Line: start})
	}
	return out
}

var (
	pipeShellRe  = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)
	secretNameRe = regexp.MustCompile(`(?i)(passw(or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)`)
	chmod777Re   = regexp.MustCompile(`\bchmod\s+(-R\s+)?0?777\b`)
	sudoRe       = regexp.MustCompile(`(^|[;&|]\s*)sudo\s`)
	exposeSSHRe  = regexp.MustCompile(`(^|\s)22(/tcp)?(\s|$)`)
	argOrEnvKVRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*|\s+)(.+)$`)
)

// Scan implements scanners.Scanner.
func (d *Dockerfile) Scan(ctx context.Context, req *scanners.Request, _ execx.Resolution) ([]finding.Finding, error) {
	set := map[string]bool{}
	for _, p := range req.Profile.Dockerfile {
		set[p] = true
	}
	var out []finding.Finding
	err := eachFile(ctx, req, func(rel string) bool { return set[rel] }, func(rel string, data []byte) {
		out = append(out, AnalyzeDockerfile(rel, data)...)
	})
	return out, err
}

// AnalyzeDockerfile runs the Dockerfile rules on one file.
func AnalyzeDockerfile(rel string, data []byte) []finding.Finding {
	ins := ParseDockerfile(data)
	var out []finding.Finding
	add := func(id, family, title, desc, remediation string, sev finding.Severity, conf finding.Confidence, line int, evidence string, cwe ...string) {
		out = append(out, finding.Finding{
			Title: title, Description: desc, Kind: finding.KindPotentialRisk, Category: finding.CategoryContainer,
			Severity: sev, Confidence: conf, RuleID: id, RuleFamily: family,
			Location: finding.Location{Path: rel, StartLine: line, EndLine: line},
			CWE:      cwe, Evidence: snippet(redact.String(evidence)), Remediation: remediation,
			References: []string{"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"},
			Tags:       []string{"heuristic", "dockerfile"},
		})
	}

	stages := map[string]bool{}
	lastUser, lastUserLine := "", 0
	lastFromLine := 0
	hasHealthcheck := false
	for _, in := range ins {
		switch in.Cmd {
		case "FROM":
			lastUser, lastUserLine = "", 0
			lastFromLine = in.Line
			fields := strings.Fields(in.Args)
			var image string
			for i := 0; i < len(fields); i++ {
				if strings.HasPrefix(fields[i], "--") {
					continue
				}
				image = fields[i]
				if i+2 < len(fields) && strings.EqualFold(fields[i+1], "AS") {
					stages[strings.ToLower(fields[i+2])] = true
				}
				break
			}
			low := strings.ToLower(image)
			if image == "" || low == "scratch" || stages[low] || strings.Contains(image, "$") || strings.Contains(image, "@sha256:") {
				continue
			}
			name := image
			if i := strings.LastIndex(image, "/"); i >= 0 {
				name = image[i+1:]
			}
			switch {
			case !strings.Contains(name, ":"):
				add("SP-DOCKER-UNPINNED-IMAGE", "dockerfile.unpinned-image", "Base image without tag: "+image,
					"The base image has no tag, so it resolves to 'latest' and builds are not reproducible; a compromised or breaking upstream release would be pulled silently.",
					"Pin the base image to a specific version tag, ideally with a digest (image:1.2.3@sha256:...).",
					finding.SeverityMedium, finding.ConfidenceHigh, in.Line, "FROM "+in.Args, "CWE-1357")
			case strings.HasSuffix(name, ":latest"):
				add("SP-DOCKER-LATEST-TAG", "dockerfile.unpinned-image", "Base image uses the 'latest' tag: "+image,
					"The 'latest' tag is mutable; builds are not reproducible and may pull vulnerable or malicious updates.",
					"Pin the base image to a specific version tag and digest.",
					finding.SeverityMedium, finding.ConfidenceHigh, in.Line, "FROM "+in.Args, "CWE-1357")
			}
		case "USER":
			lastUser, lastUserLine = strings.TrimSpace(in.Args), in.Line
		case "HEALTHCHECK":
			hasHealthcheck = true
		case "ADD":
			if strings.Contains(in.Args, "http://") || strings.Contains(in.Args, "https://") {
				add("SP-DOCKER-ADD-URL", "dockerfile.add-instead-of-copy", "ADD downloads a remote URL",
					"ADD with a URL fetches content at build time without integrity verification.",
					"Use RUN curl/wget with checksum verification, or COPY a vendored file.",
					finding.SeverityMedium, finding.ConfidenceHigh, in.Line, "ADD "+in.Args, "CWE-494")
			} else if !strings.Contains(in.Args, ".tar") {
				add("SP-DOCKER-ADD", "dockerfile.add-instead-of-copy", "ADD used instead of COPY",
					"ADD has implicit behaviours (remote URLs, auto-extraction). COPY is explicit and safer for local files.",
					"Replace ADD with COPY for local files.",
					finding.SeverityLow, finding.ConfidenceHigh, in.Line, "ADD "+in.Args)
			}
		case "RUN":
			if pipeShellRe.MatchString(in.Args) {
				add("SP-DOCKER-CURL-PIPE-SH", "dockerfile.curl-pipe-shell", "Remote script piped to a shell",
					"Downloading a script and piping it straight into a shell executes unverified remote code during the build.",
					"Download the script, verify its checksum or signature, then execute it.",
					finding.SeverityMedium, finding.ConfidenceHigh, in.Line, "RUN "+in.Args, "CWE-494")
			}
			if chmod777Re.MatchString(in.Args) {
				add("SP-DOCKER-CHMOD-777", "dockerfile.world-writable", "World-writable permissions (chmod 777)",
					"Files or directories made world-writable can be modified by any process in the container.",
					"Grant the minimal permissions needed (e.g. 755/644) and set ownership with COPY --chown.",
					finding.SeverityMedium, finding.ConfidenceHigh, in.Line, "RUN "+in.Args, "CWE-732")
			}
			if sudoRe.MatchString(in.Args) {
				add("SP-DOCKER-SUDO", "dockerfile.sudo", "sudo used in RUN",
					"sudo in images has unpredictable TTY and signal-forwarding behaviour and suggests privilege mixing.",
					"Use USER to switch users; use gosu if a step-down is required at runtime.",
					finding.SeverityLow, finding.ConfidenceHigh, in.Line, "RUN "+in.Args, "CWE-250")
			}
		case "ENV", "ARG":
			for _, kv := range splitEnv(in.Args) {
				m := argOrEnvKVRe.FindStringSubmatch(kv)
				if m == nil || !secretNameRe.MatchString(m[1]) {
					continue
				}
				val := strings.Trim(m[2], `"' `)
				if val == "" || strings.HasPrefix(val, "$") || placeholderRe.MatchString(val) {
					continue
				}
				add("SP-DOCKER-SECRET-IN-"+in.Cmd, "dockerfile.secret-in-env", "Secret-looking value in "+in.Cmd+" "+m[1],
					in.Cmd+" values are stored in image layers and visible with 'docker history' / 'docker inspect'.",
					"Use BuildKit secrets (RUN --mount=type=secret) or inject the value at runtime.",
					finding.SeverityHigh, finding.ConfidenceMedium, in.Line, in.Cmd+" "+m[1]+"="+redact.Mask, "CWE-798")
			}
		case "EXPOSE":
			if exposeSSHRe.MatchString(in.Args) {
				add("SP-DOCKER-EXPOSE-SSH", "dockerfile.expose-ssh", "SSH port 22 exposed",
					"Running SSH inside a container widens the attack surface; use 'docker exec' instead.",
					"Remove the SSH daemon and EXPOSE 22.",
					finding.SeverityMedium, finding.ConfidenceMedium, in.Line, "EXPOSE "+in.Args)
			}
		}
	}

	if len(ins) == 0 {
		return out
	}
	u := strings.ToLower(lastUser)
	if base, _, _ := strings.Cut(u, ":"); lastUser == "" || base == "root" || base == "0" {
		line, ev := lastFromLine, "no USER instruction in the final stage"
		if lastUserLine > 0 {
			line, ev = lastUserLine, "USER "+lastUser
		}
		add("SP-DOCKER-ROOT-USER", "dockerfile.root-user", "Container runs as root",
			"The final image stage does not switch to a non-root user, so the application runs as UID 0. A compromise of the process gives root inside the container and eases container escapes.",
			"Create an unprivileged user and add 'USER <name>' (or a numeric UID) at the end of the final stage.",
			finding.SeverityHigh, finding.ConfidenceHigh, line, ev, "CWE-250")
	}
	if !hasHealthcheck {
		add("SP-DOCKER-NO-HEALTHCHECK", "dockerfile.no-healthcheck", "No HEALTHCHECK instruction",
			"Without a HEALTHCHECK, orchestrators cannot detect a hung container.",
			"Add a HEALTHCHECK instruction (or define probes in your orchestrator).",
			finding.SeverityInfo, finding.ConfidenceHigh, 1, "")
	}
	return out
}

// splitEnv splits "A=1 B=2" or "KEY value" forms.
func splitEnv(args string) []string {
	if !strings.Contains(args, "=") {
		return []string{args}
	}
	var out []string
	var cur strings.Builder
	quote := rune(0)
	for _, c := range args {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			cur.WriteRune(c)
		case c == '"' || c == '\'':
			quote = c
			cur.WriteRune(c)
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
