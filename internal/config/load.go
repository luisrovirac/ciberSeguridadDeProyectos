package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

// EnvPrefix is the prefix for environment variable overrides, e.g.
// SECUREPROJECTS_FAIL_ON=critical or SECUREPROJECTS_LIMITS_TOOL_TIMEOUT=5m.
const EnvPrefix = "SECUREPROJECTS"

// Load merges defaults, an optional YAML file and environment variables.
// CLI flags are applied afterwards by the caller.
func Load(path string) (Config, error) {
	cfg := Default()
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix(EnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	bindEnvs(v, reflect.TypeOf(cfg), "")

	if path != "" {
		f, err := os.Open(path) //nolint:gosec // user-provided config path is intended
		if err != nil {
			return cfg, fmt.Errorf("%w: cannot open config: %w", ErrInvalid, err)
		}
		defer f.Close()
		if err := v.ReadConfig(f); err != nil {
			return cfg, fmt.Errorf("%w: cannot parse YAML: %w", ErrInvalid, err)
		}
	}
	if err := v.Unmarshal(&cfg); err != nil {
		return cfg, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return cfg, nil
}

// bindEnvs registers every leaf key so AutomaticEnv works with Unmarshal.
func bindEnvs(v *viper.Viper, t reflect.Type, prefix string) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("mapstructure")
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		if f.Type.Kind() == reflect.Struct && f.Type.String() != "time.Duration" {
			bindEnvs(v, f.Type, key)
			continue
		}
		_ = v.BindEnv(key)
	}
}

// IsInvalid reports whether err is a configuration error.
func IsInvalid(err error) bool { return errors.Is(err, ErrInvalid) }
