// sweep-helper resolves the target image:tag references that `copa patch
// --config` just pushed, so sweep.sh can re-scan them with trivy and feed
// the results back into copa's report directory for next run's
// skip-detection.
//
// This intentionally re-derives a small slice of pkg/bulk/engine.go's
// unexported target-resolution logic (buildTargetRepository's
// last-path-segment rule, and resolveTargetTag's default
// "{{ .SourceTag }}-patched" template) — those helpers aren't exported, so
// this is a deliberate, documented duplication. If copa changes that
// default template or repository-naming rule, this must be updated to
// match.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/project-copacetic/copacetic/pkg/bulk"
	"github.com/project-copacetic/copacetic/pkg/patch"
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

	ctx := context.Background()
	for _, img := range cfg.Images {
		if img.Tags.Strategy != "list" {
			fmt.Fprintf(os.Stderr, "skip auto-rescan for %q: strategy %q not supported (only \"list\" is); skip-detection will not apply to it\n", img.Name, img.Tags.Strategy)
			continue
		}

		registry := firstNonEmpty(img.Target.Registry, cfg.Target.Registry)
		if registry == "" {
			fmt.Fprintf(os.Stderr, "skip auto-rescan for %q: no target.registry configured\n", img.Name)
			continue
		}
		tagTemplate := firstNonEmpty(img.Target.Tag, cfg.Target.Tag, defaultTagTemplate)

		targetRepoName := fmt.Sprintf("%s/%s", strings.TrimSuffix(registry, "/"), lastPathSegment(img.Image))

		for _, sourceTag := range img.Tags.List {
			baseTag, err := renderTagTemplate(tagTemplate, sourceTag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skip %s:%s: %v\n", img.Name, sourceTag, err)
				continue
			}

			resolvedTag, err := latestPatchedTag(ctx, targetRepoName, baseTag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skip %s (%s): %v\n", img.Name, targetRepoName, err)
				continue
			}
			if resolvedTag == "" {
				fmt.Fprintf(os.Stderr, "skip %s: no tag matching %q found in %s (patch may have failed or not run yet)\n", img.Name, baseTag, targetRepoName)
				continue
			}

			fmt.Printf("%s:%s\n", targetRepoName, resolvedTag)
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

// latestPatchedTag lists tags in repoName and returns the highest of
// baseTag / baseTag-N (matching copa's own re-patch versioning scheme), or
// "" if none exist yet.
//
// This MUST resolve to the exact same tag copa's skip-detection looks the
// report up under (its latestPatchTag over discoverExistingPatchTags) — copa
// keys reports by "<repo>:<latestTag>" and fail-opens (re-patches with an
// incremented -N tag) on a lookup miss. In particular copa *excludes*
// architecture-specific tags like "<baseTag>-386"/"<baseTag>-arm-v7"; the
// numeric ones (e.g. "-386") would otherwise be mistaken for a "-N" re-patch
// version here, causing us to key the report under the wrong tag and copa to
// increment forever. We reuse copa's own ArchTagSuffixes() so the exclusion
// list stays in sync with copa automatically.
func latestPatchedTag(ctx context.Context, repoName, baseTag string) (string, error) {
	repo, err := name.NewRepository(repoName)
	if err != nil {
		return "", fmt.Errorf("parsing repository %q: %w", repoName, err)
	}

	tags, err := remote.List(repo, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("listing tags: %w", err)
	}

	return pickLatestPatchedTag(baseTag, tags), nil
}

// pickLatestPatchedTag is the pure tag-selection logic, split out for testing.
func pickLatestPatchedTag(baseTag string, tags []string) string {
	archSuffixes := patch.ArchTagSuffixes()
	isArchSpecific := func(t string) bool {
		for _, suffix := range archSuffixes {
			if t == baseTag+"-"+suffix {
				return true
			}
		}
		return false
	}

	suffixPattern := regexp.MustCompile("^" + regexp.QuoteMeta(baseTag) + `(-([0-9]+))?$`)
	best := -1
	bestTag := ""
	for _, t := range tags {
		if isArchSpecific(t) {
			continue // copa excludes these from its patched-tag versioning
		}
		m := suffixPattern.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		n := 0
		if m[2] != "" {
			var err error
			n, err = strconv.Atoi(m[2])
			if err != nil {
				continue
			}
		}
		if n > best {
			best = n
			bestTag = t
		}
	}
	return bestTag
}
