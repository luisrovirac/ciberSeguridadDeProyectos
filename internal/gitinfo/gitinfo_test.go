package gitinfo

import "testing"

func TestValidateRepoURL(t *testing.T) {
	ok := []string{"https://github.com/org/repo", "https://github.com/org/repo.git", "ssh://git@github.com/org/repo.git", "git@github.com:org/repo.git"}
	bad := []string{"", "-uhelp", "--upload-pack=touch /tmp/x", "file:///etc", "ext::sh -c touch% /tmp/pwned", "http://github.com/org/repo", "/local/path", "https://", "https://github.com/org/repo with space"}
	for _, u := range ok {
		if err := ValidateRepoURL(u); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := ValidateRepoURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestStripCredentials(t *testing.T) {
	if got := StripCredentials("https://user:tok3n@github.com/o/r.git"); got != "https://github.com/o/r.git" {
		t.Fatal(got)
	}
}
