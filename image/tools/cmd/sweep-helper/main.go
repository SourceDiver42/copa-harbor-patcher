// sweep-helper turns a copa bulk PatchConfig into a flat patch plan: one
// "<source-ref>\t<target-ref>" line per image:tag. sweep.sh consumes it to
// drive a comprehensive per-image `copa patch` (see sweep.sh for why we don't
// use copa's own bulk/report-driven mode).
//
// Single-platform mode: when exactly one platform is requested (-platform),
// the source ref is resolved to that platform's child DIGEST so copa patches a
// single-arch image and produces a single-arch result — instead of a manifest
// list that still carries the other, unpatched architectures (which would keep
// Harbor's aggregate CVE count high). With zero or multiple platforms the
// source tag is emitted as-is (copa patches the whole image / a subset,
// preserving the rest).
//
// It re-derives the small slice of pkg/bulk/engine.go's target-naming logic we
// depend on: buildTargetRepository's last-path-segment rule and
// resolveTargetTag's default "{{ .SourceTag }}-patched" template. The target
// tag is the base patched tag (e.g. "11.3-patched"); we overwrite it rather
// than minting copa's "-N" re-patch versions.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/project-copacetic/copacetic/pkg/bulk"
	"gopkg.in/yaml.v3"
)

const defaultTagTemplate = "{{ .SourceTag }}-patched"

func main() {
	configPath := flag.String("config", "", "path to the PatchConfig YAML")
	platformsCSV := flag.String("platforms", "", "comma-separated platforms being patched; when exactly one, source refs are pinned to that platform's digest for a single-arch result")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}

	// Only pin to a single-platform digest when exactly one platform is
	// requested; otherwise leave the source as a tag (whole image / subset).
	var singlePlatform string
	if ps := splitNonEmpty(*platformsCSV); len(ps) == 1 {
		singlePlatform = ps[0]
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
			sourceRef := fmt.Sprintf("%s:%s", img.Image, sourceTag)
			if singlePlatform != "" {
				pinned, err := resolvePlatformDigest(sourceRef, singlePlatform)
				if err != nil {
					// Fall back to the tag: copa will still patch (with
					// --platform in sweep.sh), just producing a manifest list.
					fmt.Fprintf(os.Stderr, "warn: %s:%s: couldn't pin to %s (%v); patching the full image\n", img.Name, sourceTag, singlePlatform, err)
				} else {
					sourceRef = pinned
				}
			}
			fmt.Printf("%s\t%s:%s\n", sourceRef, targetRepo, baseTag)
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

func splitNonEmpty(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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

// resolvePlatformDigest returns "<repo>@<digest>" for the given platform's
// child of a multi-arch source (so copa patches a single-arch image). For a
// single-arch source it returns the ref unchanged.
func resolvePlatformDigest(sourceRef, platform string) (string, error) {
	wantOS, wantArch, wantVariant := parsePlatform(platform)

	ref, err := name.ParseReference(sourceRef)
	if err != nil {
		return "", fmt.Errorf("parsing %q: %w", sourceRef, err)
	}
	desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("fetching %q: %w", sourceRef, err)
	}
	if !desc.MediaType.IsIndex() {
		return sourceRef, nil // already single-arch
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return "", err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", err
	}
	for _, m := range manifest.Manifests {
		p := m.Platform
		if p != nil && p.OS == wantOS && p.Architecture == wantArch &&
			normVariant(p.Architecture, p.Variant) == normVariant(wantArch, wantVariant) {
			return ref.Context().Digest(m.Digest.String()).Name(), nil
		}
	}
	return "", fmt.Errorf("platform %s not present in image index", platform)
}

// normVariant canonicalizes CPU variants so that e.g. an index entry of
// arm64/v8 matches a requested linux/arm64 (and vice-versa) — the same
// normalization copa applies internally.
func normVariant(arch, variant string) string {
	if arch == "arm64" && variant == "v8" {
		return ""
	}
	return variant
}

// parsePlatform splits "linux/amd64" or "linux/arm/v7" into os, arch, variant.
func parsePlatform(p string) (os, arch, variant string) {
	parts := strings.Split(p, "/")
	if len(parts) > 0 {
		os = parts[0]
	}
	if len(parts) > 1 {
		arch = parts[1]
	}
	if len(parts) > 2 {
		variant = parts[2]
	}
	return os, arch, variant
}
