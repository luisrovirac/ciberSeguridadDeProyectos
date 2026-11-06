package native

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

// IaC checks Terraform, Kubernetes, docker-compose and CloudFormation files
// with simple, documented rules. Deep IaC analysis is delegated to
// Trivy/Checkov/KICS when available.
type IaC struct{ base }

// NewIaC creates the analyzer.
func NewIaC() *IaC { return &IaC{base{"native-iac"}} }

// Applicable when any IaC file exists.
func (a *IaC) Applicable(p *detector.Profile, _ *config.Config) bool { return p.HasIaC() }

// Scan implements scanners.Scanner.
func (a *IaC) Scan(ctx context.Context, req *scanners.Request, _ execx.Resolution) ([]finding.Finding, error) {
	kind := map[string]string{}
	for _, p := range req.Profile.Terraform {
		kind[p] = "tf"
	}
	for _, p := range req.Profile.K8s {
		kind[p] = "k8s"
	}
	for _, p := range req.Profile.Compose {
		kind[p] = "compose"
	}
	for _, p := range req.Profile.CloudForm {
		kind[p] = "cfn"
	}
	var out []finding.Finding
	err := eachFile(ctx, req, func(rel string) bool { return kind[rel] != "" }, func(rel string, data []byte) {
		switch kind[rel] {
		case "tf":
			out = append(out, AnalyzeTerraform(rel, data)...)
		case "k8s":
			out = append(out, AnalyzeKubernetes(rel, data)...)
		case "compose":
			out = append(out, AnalyzeCompose(rel, data)...)
		case "cfn":
			out = append(out, AnalyzeCloudFormation(rel, data)...)
		}
	})
	return out, err
}

func iacFinding(rel string, line int, id, family, title, desc, remediation string, sev finding.Severity, conf finding.Confidence, resource, evidence string, cwe ...string) finding.Finding {
	return finding.Finding{
		Title: title, Description: desc, Kind: finding.KindPotentialRisk, Category: finding.CategoryIaC,
		Severity: sev, Confidence: conf, RuleID: id, RuleFamily: family,
		Location: finding.Location{Path: rel, StartLine: line, EndLine: line, Resource: resource},
		CWE:      cwe, Evidence: snippet(evidence), Remediation: remediation,
		Tags: []string{"heuristic", "iac"},
	}
}

var (
	tfResourceRe  = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"`)
	tfOpenCIDRRe  = regexp.MustCompile(`"(0\.0\.0\.0/0|::/0)"`)
	tfPublicACLRe = regexp.MustCompile(`^\s*acl\s*=\s*"(public-read|public-read-write|authenticated-read)"`)
	tfUnencrypted = regexp.MustCompile(`^\s*(encrypted|storage_encrypted|enable_encryption|encryption_enabled)\s*=\s*false`)
	tfPubAccessRe = regexp.MustCompile(`^\s*publicly_accessible\s*=\s*true`)
	tfBlockOffRe  = regexp.MustCompile(`^\s*(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false`)
	tfIngressRe   = regexp.MustCompile(`^\s*(ingress|type\s*=\s*"ingress")`)
	tfEgressRe    = regexp.MustCompile(`^\s*egress\b`)
	tfHTTPRe      = regexp.MustCompile(`^\s*protocol\s*=\s*"HTTP"`)
)

// AnalyzeTerraform applies line-oriented Terraform rules.
func AnalyzeTerraform(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	resource := ""
	inEgress := false
	for i, l := range lines(data) {
		n := i + 1
		if m := tfResourceRe.FindStringSubmatch(l); m != nil {
			resource = m[1] + "." + m[2]
			inEgress = false
			continue
		}
		if tfEgressRe.MatchString(l) {
			inEgress = true
		} else if tfIngressRe.MatchString(l) {
			inEgress = false
		}
		if strings.Contains(l, "cidr_blocks") || strings.Contains(l, "cidr_ipv4") || strings.Contains(l, "cidr_ipv6") || strings.Contains(l, "source_ranges") || strings.Contains(l, "source_address_prefix") {
			if tfOpenCIDRRe.MatchString(l) && !inEgress && !strings.Contains(resource, "egress") {
				out = append(out, iacFinding(rel, n, "SP-IAC-OPEN-INGRESS", "iac.public-ingress",
					"Ingress open to the internet (0.0.0.0/0) in "+resource,
					"A network rule allows inbound traffic from any address. Combined with an administrative port (SSH/RDP/DB) this is a frequent root cause of breaches.",
					"Restrict the CIDR to known address ranges, a VPN or a bastion host.",
					finding.SeverityHigh, finding.ConfidenceMedium, resource, l, "CWE-284"))
			}
		}
		if tfPublicACLRe.MatchString(l) {
			out = append(out, iacFinding(rel, n, "SP-IAC-PUBLIC-ACL", "iac.storage-public-acl",
				"Storage bucket with public ACL in "+resource,
				"The bucket ACL grants read (or write) access to everyone.",
				"Use a private ACL and enable S3 Block Public Access.",
				finding.SeverityHigh, finding.ConfidenceHigh, resource, l, "CWE-732"))
		}
		if tfBlockOffRe.MatchString(l) {
			out = append(out, iacFinding(rel, n, "SP-IAC-PUBLIC-ACCESS-BLOCK-OFF", "iac.storage-public-access-block",
				"Public access block disabled in "+resource,
				"A public-access protection setting is explicitly disabled.",
				"Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.",
				finding.SeverityMedium, finding.ConfidenceHigh, resource, l, "CWE-732"))
		}
		if tfUnencrypted.MatchString(l) {
			out = append(out, iacFinding(rel, n, "SP-IAC-UNENCRYPTED", "iac.unencrypted-storage",
				"Encryption at rest disabled in "+resource,
				"Data stored by this resource is not encrypted at rest.",
				"Enable encryption (ideally with a customer-managed KMS key).",
				finding.SeverityMedium, finding.ConfidenceHigh, resource, l, "CWE-311"))
		}
		if tfPubAccessRe.MatchString(l) {
			out = append(out, iacFinding(rel, n, "SP-IAC-PUBLIC-DB", "iac.publicly-accessible",
				"Resource publicly accessible: "+resource,
				"The resource (typically a database) is reachable from the internet.",
				"Set publicly_accessible = false and reach it through private networking.",
				finding.SeverityHigh, finding.ConfidenceHigh, resource, l, "CWE-284"))
		}
		if tfHTTPRe.MatchString(l) && strings.Contains(resource, "listener") {
			out = append(out, iacFinding(rel, n, "SP-IAC-PLAINTEXT-LISTENER", "iac.plaintext-listener",
				"Load balancer listener uses plain HTTP in "+resource,
				"Traffic is not encrypted in transit.",
				"Use HTTPS with a modern TLS policy, and redirect HTTP to HTTPS.",
				finding.SeverityMedium, finding.ConfidenceMedium, resource, l, "CWE-319"))
		}
	}
	return out
}

// --- Kubernetes ---

var podKinds = map[string]bool{"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true, "ReplicaSet": true, "Job": true, "CronJob": true, "ReplicationController": true}

// AnalyzeKubernetes parses multi-document YAML and checks pod security settings.
func AnalyzeKubernetes(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		kind := scalar(get(root, "kind"))
		if !podKinds[kind] {
			continue
		}
		name := scalar(get(get(root, "metadata"), "name"))
		obj := kind + "/" + name
		podSpec := get(root, "spec")
		switch kind {
		case "Pod":
		case "CronJob":
			podSpec = get(get(get(get(podSpec, "jobTemplate"), "spec"), "template"), "spec")
		default:
			podSpec = get(get(podSpec, "template"), "spec")
		}
		if podSpec == nil {
			continue
		}
		out = append(out, checkPodSpec(rel, obj, podSpec)...)
	}
	return out
}

func checkPodSpec(rel, obj string, spec *yaml.Node) []finding.Finding {
	var out []finding.Finding
	for _, f := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if n := get(spec, f); n != nil && n.Value == "true" {
			out = append(out, iacFinding(rel, n.Line, "SP-K8S-HOST-NAMESPACE", "k8s.host-namespace",
				fmt.Sprintf("%s shares the host namespace (%s: true)", obj, f),
				"Sharing host namespaces breaks container isolation and exposes host processes or network interfaces.",
				"Remove "+f+" or set it to false.",
				finding.SeverityHigh, finding.ConfidenceHigh, obj, f+": true", "CWE-250"))
		}
	}
	podSC := get(spec, "securityContext")
	podNonRoot := scalar(get(podSC, "runAsNonRoot")) == "true"
	var containers []*yaml.Node
	for _, key := range []string{"containers", "initContainers"} {
		if seq := get(spec, key); seq != nil && seq.Kind == yaml.SequenceNode {
			containers = append(containers, seq.Content...)
		}
	}
	for _, c := range containers {
		cname := scalar(get(c, "name"))
		where := obj + " container " + cname
		sc := get(c, "securityContext")
		line := c.Line
		if n := get(sc, "privileged"); n != nil && n.Value == "true" {
			out = append(out, iacFinding(rel, n.Line, "SP-K8S-PRIVILEGED", "k8s.privileged-container",
				"Privileged container: "+where,
				"A privileged container has all host capabilities and device access; escaping to the node is trivial.",
				"Remove 'privileged: true'; grant only the specific capabilities required.",
				finding.SeverityHigh, finding.ConfidenceHigh, obj, "privileged: true", "CWE-250"))
		}
		if n := get(sc, "allowPrivilegeEscalation"); n == nil || n.Value != "false" {
			out = append(out, iacFinding(rel, line, "SP-K8S-PRIV-ESCALATION", "k8s.privilege-escalation",
				"allowPrivilegeEscalation not disabled: "+where,
				"Processes may gain more privileges than their parent (setuid binaries).",
				"Set securityContext.allowPrivilegeEscalation: false.",
				finding.SeverityMedium, finding.ConfidenceHigh, obj, "allowPrivilegeEscalation unset", "CWE-250"))
		}
		nonRoot := podNonRoot || scalar(get(sc, "runAsNonRoot")) == "true"
		if uid := scalar(get(sc, "runAsUser")); uid != "" && uid != "0" {
			nonRoot = true
		}
		if !nonRoot {
			out = append(out, iacFinding(rel, line, "SP-K8S-RUN-AS-ROOT", "k8s.run-as-root",
				"Container may run as root: "+where,
				"Neither runAsNonRoot nor a non-zero runAsUser is set; the container runs as root if the image does.",
				"Set securityContext.runAsNonRoot: true and a non-zero runAsUser.",
				finding.SeverityMedium, finding.ConfidenceMedium, obj, "runAsNonRoot unset", "CWE-250"))
		}
		if scalar(get(sc, "readOnlyRootFilesystem")) != "true" {
			out = append(out, iacFinding(rel, line, "SP-K8S-WRITABLE-ROOTFS", "k8s.writable-root-fs",
				"Writable root filesystem: "+where,
				"A writable root filesystem lets an attacker persist tools or modify binaries.",
				"Set securityContext.readOnlyRootFilesystem: true and mount writable emptyDir volumes where needed.",
				finding.SeverityLow, finding.ConfidenceHigh, obj, "readOnlyRootFilesystem unset", "CWE-732"))
		}
		limits := get(get(c, "resources"), "limits")
		if get(limits, "memory") == nil || get(limits, "cpu") == nil {
			out = append(out, iacFinding(rel, line, "SP-K8S-NO-LIMITS", "k8s.no-resource-limits",
				"Missing CPU/memory limits: "+where,
				"Without limits a compromised or buggy container can exhaust node resources (denial of service).",
				"Define resources.limits.cpu and resources.limits.memory.",
				finding.SeverityLow, finding.ConfidenceHigh, obj, "resources.limits incomplete", "CWE-770"))
		}
		img := scalar(get(c, "image"))
		if img != "" && !strings.Contains(img, "@sha256:") {
			name := img
			if i := strings.LastIndex(img, "/"); i >= 0 {
				name = img[i+1:]
			}
			if !strings.Contains(name, ":") || strings.HasSuffix(name, ":latest") {
				n := get(c, "image")
				out = append(out, iacFinding(rel, n.Line, "SP-K8S-LATEST-TAG", "k8s.unpinned-image",
					"Image without a fixed tag: "+img,
					"Mutable tags make deployments non-reproducible and may pull unexpected code.",
					"Pin images to a version tag and digest.",
					finding.SeverityLow, finding.ConfidenceHigh, obj, "image: "+img, "CWE-1357"))
			}
		}
	}
	return out
}

// --- docker-compose ---

// AnalyzeCompose checks docker-compose services.
func AnalyzeCompose(rel string, data []byte) []finding.Finding {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	services := get(doc.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}
	var out []finding.Finding
	for i := 0; i+1 < len(services.Content); i += 2 {
		name := services.Content[i].Value
		svc := services.Content[i+1]
		res := "service/" + name
		if n := get(svc, "privileged"); n != nil && n.Value == "true" {
			out = append(out, iacFinding(rel, n.Line, "SP-COMPOSE-PRIVILEGED", "k8s.privileged-container",
				"Privileged compose service: "+name,
				"privileged: true gives the container full access to the host.",
				"Remove privileged and add only the required cap_add entries.",
				finding.SeverityHigh, finding.ConfidenceHigh, res, "privileged: true", "CWE-250"))
		}
		if n := get(svc, "network_mode"); n != nil && n.Value == "host" {
			out = append(out, iacFinding(rel, n.Line, "SP-COMPOSE-HOST-NETWORK", "k8s.host-namespace",
				"Compose service uses host networking: "+name,
				"Host networking removes network isolation between the container and the host.",
				"Use a bridge network and publish only the required ports.",
				finding.SeverityMedium, finding.ConfidenceHigh, res, "network_mode: host", "CWE-250"))
		}
		if vols := get(svc, "volumes"); vols != nil && vols.Kind == yaml.SequenceNode {
			for _, v := range vols.Content {
				src := v.Value
				if v.Kind == yaml.MappingNode {
					src = scalar(get(v, "source"))
				}
				if strings.Contains(src, "docker.sock") {
					out = append(out, iacFinding(rel, v.Line, "SP-COMPOSE-DOCKER-SOCKET", "container.docker-socket",
						"Docker socket mounted into service: "+name,
						"Access to the Docker socket is equivalent to root on the host.",
						"Do not mount /var/run/docker.sock; use a restricted socket proxy if unavoidable.",
						finding.SeverityHigh, finding.ConfidenceHigh, res, src, "CWE-250"))
				}
			}
		}
	}
	return out
}

// --- CloudFormation ---

var cfnOpenCIDRRe = regexp.MustCompile(`(?i)"?CidrIp(v6)?"?\s*:\s*"?(0\.0\.0\.0/0|::/0)`)

// AnalyzeCloudFormation applies minimal regex rules to CloudFormation templates.
func AnalyzeCloudFormation(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	for i, l := range lines(data) {
		if cfnOpenCIDRRe.MatchString(l) {
			out = append(out, iacFinding(rel, i+1, "SP-IAC-OPEN-INGRESS", "iac.public-ingress",
				"Security group open to the internet (0.0.0.0/0)",
				"A security group rule allows traffic from any address.",
				"Restrict CidrIp to known address ranges.",
				finding.SeverityHigh, finding.ConfidenceLow, "", l, "CWE-284"))
		}
		if strings.Contains(l, "PublicRead") {
			out = append(out, iacFinding(rel, i+1, "SP-IAC-PUBLIC-ACL", "iac.storage-public-acl",
				"Bucket with public AccessControl",
				"The bucket grants public read access.",
				"Use Private access control and enable PublicAccessBlockConfiguration.",
				finding.SeverityHigh, finding.ConfidenceMedium, "", l, "CWE-732"))
		}
	}
	return out
}

// --- yaml helpers ---

func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if key == "" {
		return n
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
