package lockfiles

import "testing"

func find(t *testing.T, pkgs []Package, name, ver string) Package {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name && p.Version == ver {
			return p
		}
	}
	t.Fatalf("package %s@%s not found in %+v", name, ver, pkgs)
	return Package{}
}

func TestGoMod(t *testing.T) {
	p := ParseGoMod("go.mod", []byte("module x\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.7\n\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n\tgithub.com/c/d v0.0.0-20210101-abcdef\n)\n"))
	x := find(t, p, "golang.org/x/text", "0.3.7")
	if x.Line != 5 || x.Direct == nil || !*x.Direct {
		t.Fatalf("%+v", x)
	}
	if b := find(t, p, "github.com/a/b", "1.2.3"); *b.Direct {
		t.Fatal("indirect marked direct")
	}
}

func TestPackageLockV3AndV1(t *testing.T) {
	v3 := `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.15"}},"node_modules/lodash":{"version":"4.17.15"},"node_modules/a/node_modules/lodash":{"version":"3.0.0"},"node_modules/@scope/x":{"version":"1.0.0","dev":true}}}`
	p := ParsePackageLock("package-lock.json", []byte(v3))
	if l := find(t, p, "lodash", "4.17.15"); !*l.Direct {
		t.Fatal("direct dep not detected")
	}
	find(t, p, "lodash", "3.0.0")
	if s := find(t, p, "@scope/x", "1.0.0"); !s.Dev {
		t.Fatal("dev flag")
	}
	v1 := `{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.15","dependencies":{"x":{"version":"1.0.0"}}}}}`
	p = ParsePackageLock("package-lock.json", []byte(v1))
	find(t, p, "lodash", "4.17.15")
	find(t, p, "x", "1.0.0")
}

func TestYarnAndPnpm(t *testing.T) {
	yarn := "# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.15:\n  version \"4.17.15\"\n  resolved \"x\"\n\n\"@babel/core@^7.0.0\":\n  version \"7.1.0\"\n"
	p := ParseYarnLock("yarn.lock", []byte(yarn))
	find(t, p, "lodash", "4.17.15")
	find(t, p, "@babel/core", "7.1.0")
	pnpm := "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.15:\n    resolution: {integrity: x}\n\n  '@babel/core@7.1.0':\n    resolution: {integrity: y}\n"
	p = ParsePnpmLock("pnpm-lock.yaml", []byte(pnpm))
	find(t, p, "lodash", "4.17.15")
	find(t, p, "@babel/core", "7.1.0")
}

func TestPython(t *testing.T) {
	p := ParseRequirements("requirements.txt", []byte("requests==2.25.0\nPyYAML == 5.3 ; python_version>'3'\nflask>=2\n# c\n-r other.txt\n"))
	find(t, p, "requests", "2.25.0")
	find(t, p, "pyyaml", "5.3")
	if len(p) != 2 {
		t.Fatalf("unpinned requirement must be ignored: %+v", p)
	}
	poetry := "[[package]]\nname = \"Django\"\nversion = \"3.2.0\"\n\n[package.dependencies]\nx = \"*\"\n\n[[package]]\nname = \"jinja2\"\nversion = \"2.10\"\n"
	p = ParserFor("poetry.lock")("poetry.lock", []byte(poetry))
	find(t, p, "django", "3.2.0")
	find(t, p, "jinja2", "2.10")
	pip := `{"default":{"requests":{"version":"==2.25.0"}},"develop":{"pytest":{"version":"==6.0.0"}}}`
	p = ParsePipfileLock("Pipfile.lock", []byte(pip))
	find(t, p, "requests", "2.25.0")
}

func TestOthers(t *testing.T) {
	gem := "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (6.1.0)\n      actionpack (= 6.1.0)\n    nokogiri (1.13.0-x86_64-linux)\n"
	p := ParseGemfileLock("Gemfile.lock", []byte(gem))
	find(t, p, "rails", "6.1.0")
	find(t, p, "nokogiri", "1.13.0")

	comp := `{"packages":[{"name":"monolog/monolog","version":"v2.1.0"}],"packages-dev":[{"name":"x/y","version":"dev-main"}]}`
	p = ParseComposerLock("composer.lock", []byte(comp))
	find(t, p, "monolog/monolog", "2.1.0")

	pom := `<project><properties><log4j.version>2.14.1</log4j.version></properties><dependencies>
<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
<dependency><groupId>a</groupId><artifactId>b</artifactId><version>[1.0,2.0)</version></dependency>
</dependencies></project>`
	p = ParsePom("pom.xml", []byte(pom))
	find(t, p, "org.apache.logging.log4j:log4j-core", "2.14.1")
	if len(p) != 1 {
		t.Fatalf("ranges must be skipped: %+v", p)
	}

	cargo := "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n"
	find(t, ParserFor("Cargo.lock")("Cargo.lock", []byte(cargo)), "serde", "1.0.0")

	cs := `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`
	find(t, ParseCsproj("a.csproj", []byte(cs)), "Newtonsoft.Json", "12.0.1")

	nuget := `{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"}}}}`
	find(t, ParseNuGetLock("packages.lock.json", []byte(nuget)), "Newtonsoft.Json", "12.0.1")

	gradle := "# comment\ncom.google.guava:guava:30.0-jre=compileClasspath\nempty=\n"
	find(t, ParseGradleLock("gradle.lockfile", []byte(gradle)), "com.google.guava:guava", "30.0-jre")
}
