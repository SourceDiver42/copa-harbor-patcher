// sweep-helper turns a copa bulk PatchConfig into a flat patch plan: one
// "<source-ref>\t<target-ref>" line per image:tag. sweep.sh consumes it to
// drive a comprehensive per-image `copa patch` (see sweep.sh for why we don't
// use copa's own bulk/report-driven mode).
//
// It re-derives the small slice of pkg/bulk/engine.go's target-naming logic
// we depend on: buildTargetRepository's last-path-segment rule and
// resolveTargetTag's default "{{ .SourceTag }}-patched" template. If copa
// changes those, update this to match. The target tag is the *base* patched
// tag (e.g. "11.3-patched"); we overwrite it every patch rather than minting
// copa's "-N" re-patch versions.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"

	"github.com/project-copacetic/copacetic/pkg/bulk"
	"gopkg.in/yaml.v3"
)

const defaultTagTemplate = "{{ .SourceTag }}-patched"

func main() {
	configPath := flag.String("config", "", "path to the PatchConfig YAML")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}

	raw, err := os.ReadFile(*configPath) // #nosec G304 -- operator-supplied path, same trust level as copa's own --config flag
	if err != nil {
		log.Fatalf("reading config: %v", err)
	}

	var cfg bulk.PatchConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("parsing config: %v", err)
	}

	for _, img := range cfg.Images {
		if img.Tags.Strategy != "list" {
			fmt.Fprintf(os.Stderr, "skip %q: strategy %q not supported (only \"list\" is)\n", img.Name, img.Tags.Strategy)
			continue
		}

		registry := firstNonEmpty(img.Target.Registry, cfg.Target.Registry)
		if registry == "" {
			fmt.Fprintf(os.Stderr, "skip %q: no target.registry configured\n", img.Name)
			continue
		}
		tagTemplate := firstNonEmpty(img.Target.Tag, cfg.Target.Tag, defaultTagTemplate)
		targetRepo := fmt.Sprintf("%s/%s", strings.TrimSuffix(registry, "/"), lastPathSegment(img.Image))

		for _, sourceTag := range img.Tags.List {
			baseTag, err := renderTagTemplate(tagTemplate, sourceTag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skip %s:%s: %v\n", img.Name, sourceTag, err)
				continue
			}
			fmt.Printf("%s:%s\t%s:%s\n", img.Image, sourceTag, targetRepo, baseTag)
		}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// lastPathSegment mirrors copa's buildTargetRepository: only the final path
// segment of the source image name is kept under the target registry.
func lastPathSegment(image string) string {
	parts := strings.Split(image, "/")
	return parts[len(parts)-1]
}

func renderTagTemplate(tmplStr, sourceTag string) (string, error) {
	tmpl, err := template.New("tag").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("invalid tag template %q: %w", tmplStr, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ SourceTag string }{SourceTag: sourceTag}); err != nil {
		return "", fmt.Errorf("executing tag template %q: %w", tmplStr, err)
	}
	return buf.String(), nil
}
