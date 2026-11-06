package redact

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestStringRedactsKnownSecrets(t *testing.T) {
	secrets := []string{
		"AKIADFIPAUZRABHNRIKT",
		"ghp_Liv4RapTXSGaeK69G1UEYHoSm8e4xTAIBUek",
		"sk_prod_YXAfKsWlSzBnCouWdncCTJNd",
		"xoxb-1234567890-1234567890123-abcdefghijkl",
	}
	for _, s := range secrets {
		out := String("value: " + s + " end")
		if strings.Contains(out, s) {
			t.Errorf("secret %q not redacted: %q", s, out)
		}
	}
	for _, in := range []string{
		`password = "hunter2hunter2"`,
		`DB_PASSWORD=Sup3rS3cretPassw0rd`,
		`url: https://admin:s3cr3tpass@db.example.com/x`,
	} {
		out := String(in)
		if strings.Contains(out, "hunter2hunter2") || strings.Contains(out, "Sup3rS3cretPassw0rd") || strings.Contains(out, "s3cr3tpass") {
			t.Errorf("assignment not redacted: %q", out)
		}
	}
}

func TestStringKeepsNormalText(t *testing.T) {
	in := "func main() { fmt.Println(\"hello\") }"
	if out := String(in); out != in {
		t.Fatalf("normal text modified: %q", out)
	}
	in = `password = os.getenv("DB_PASSWORD")`
	if out := String(in); strings.Contains(out, Mask) && !strings.Contains(out, "os.getenv") {
		t.Fatalf("env lookup mangled: %q", out)
	}
}

func TestValueMasksExactSecret(t *testing.T) {
	out := Value("token=abcd1234efgh", "abcd1234efgh")
	if strings.Contains(out, "abcd1234efgh") {
		t.Fatal(out)
	}
}

func TestSlogHandlerRedacts(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewTextHandler(&buf, nil)))
	log.Info("leaked ghp_Liv4RapTXSGaeK69G1UEYHoSm8e4xTAIBUek", "key", "AKIADFIPAUZRABHNRIKT", slog.Group("g", "p", "password=verysecret123"))
	out := buf.String()
	for _, s := range []string{"ghp_Liv4RapTXSGaeK69G1UEYHoSm8e4xTAIBUek", "AKIADFIPAUZRABHNRIKT", "verysecret123"} {
		if strings.Contains(out, s) {
			t.Errorf("log leaked %q: %s", s, out)
		}
	}
}
