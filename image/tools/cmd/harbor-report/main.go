// harbor-report fetches the vulnerability report Harbor's built-in scanner
// (Trivy, run by Harbor itself on push/schedule) already produced for an
// artifact, and converts it into a copa v1alpha2 UpdateManifest JSON file
// suitable for `copa patch -r <file> --scanner native`.
//
// This deliberately does NOT run a second trivy scan — it reuses Harbor's
// own scan pipeline via its documented REST API
// (GET /projects/{p}/repositories/{r}/artifacts/{ref}/additions/vulnerabilities,
// requesting the generic scanner-adapter report schema via the
// X-Accept-Vulnerabilities header). That schema is confirmed against
// goharbor/pluggable-scanner-spec's VulnerabilityItem definition: each
// vulnerability has `id`, `package`, `version`, `fix_version`, `severity` —
// notably no field distinguishing OS vs. language packages, so this tool
// treats every reported vulnerability as an OS-package update (Class
// "os-pkgs"), matching copa's own default `--pkg-types os` behavior. If you
// need language-package patching from Harbor-sourced reports, you'll need
// to extend this once you've confirmed whether your Harbor/scanner version
// exposes an ecosystem field beyond this spec's baseline.
//
// OS type/version (needed to pick copa's package manager) isn't part of
// Harbor's vulnerability report schema either, so this tool determines it
// independently and reliably by reading /etc/os-release directly out of the
// image's layers (same primitive Trivy itself uses) via go-containerregistry,
// using the same registry credentials/keychain as everything else in this
// project.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/project-copacetic/copacetic/pkg/types/v1alpha2"
)

// harborVulnerabilityReport mirrors goharbor/pluggable-scanner-spec's
// HarborVulnerabilityReport/VulnerabilityItem schema (application/vnd.security.vulnerability.report; version=1.1).
type harborVulnerabilityReport struct {
	Vulnerabilities []struct {
		ID         string `json:"id"`
		Package    string `json:"package"`
		Version    string `json:"version"`
		FixVersion string `json:"fix_version"`
		Severity   string `json:"severity"`
	} `json:"vulnerabilities"`
}

// reportEnvelope is v1alpha2.UpdateManifest plus an extra top-level
// ArtifactName field. pkg/bulk's skip-detection (buildReportIndex) reads
// that literal field directly off the file regardless of --scanner, so it
// must be present even though it's not part of the v1alpha2 schema itself.
type reportEnvelope struct {
	v1alpha2.UpdateManifest
	ArtifactName string `json:"ArtifactName"`
}

func main() {
	ref := flag.String("ref", "", "image reference to report on, e.g. harbor.local:30003/library/python:3.7-alpine-patched")
	out := flag.String("out", "", "path to write the resulting v1alpha2 report JSON")
	flag.Parse()
	if *ref == "" || *out == "" {
		log.Fatal("-ref and -out are required")
	}

	apiBase := requireEnv("HARBOR_API_BASE")
	username := requireEnv("HARBOR_USERNAME")
	password := requireEnv("HARBOR_PASSWORD")

	tag, err := name.NewTag(*ref, name.WeakValidation)
	if err != nil {
		log.Fatalf("parsing ref %q: %v", *ref, err)
	}

	osType, osVersion, err := detectOS(tag)
	if err != nil {
		log.Fatalf("detecting OS for %q: %v", *ref, err)
	}
	log.Printf("detected OS %s %s for %s", osType, osVersion, *ref)

	client := &http.Client{Timeout: 60 * time.Second}
	if os.Getenv("HARBOR_INSECURE_SKIP_VERIFY") == "1" {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // explicit opt-in for test clusters only
	}

	waitTimeout := 5 * time.Minute
	if v := os.Getenv("HARBOR_SCAN_WAIT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			waitTimeout = d
		}
	}
	if err := ensureScanned(client, apiBase, username, password, tag, waitTimeout); err != nil {
		log.Fatalf("waiting for Harbor scan of %q: %v", *ref, err)
	}

	report, err := fetchHarborReport(client, apiBase, username, password, tag)
	if err != nil {
		log.Fatalf("fetching Harbor vulnerability report for %q: %v", *ref, err)
	}
	log.Printf("Harbor reported %d vulnerabilities for %s", len(report.Vulnerabilities), *ref)

	var osUpdates v1alpha2.UpdatePackages
	for _, v := range report.Vulnerabilities {
		if v.FixVersion == "" {
			continue // not fixable, nothing for copa to do
		}
		osUpdates = append(osUpdates, v1alpha2.UpdatePackage{
			Name:             v.Package,
			InstalledVersion: v.Version,
			FixedVersion:     v.FixVersion,
			VulnerabilityID:  v.ID,
			Type:             osType,
			Class:            "os-pkgs",
		})
	}

	envelope := reportEnvelope{
		UpdateManifest: v1alpha2.UpdateManifest{
			APIVersion: v1alpha2.APIVersion,
			Metadata: v1alpha2.Metadata{
				OS: v1alpha2.OS{Type: osType, Version: osVersion},
			},
			OSUpdates: osUpdates,
		},
		ArtifactName: *ref,
	}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		log.Fatalf("marshaling report: %v", err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // report file, not sensitive
		log.Fatalf("writing %s: %v", *out, err)
	}
	log.Printf("wrote %s (%d fixable OS updates)", *out, len(osUpdates))
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s must be set", key)
	}
	return v
}

// splitProjectRepo splits a go-containerregistry repository string
// ("project/repo" or "project/nested/repo") into Harbor's project_name and
// repository_name path parameters.
func splitProjectRepo(repo string) (project, repository string, err error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected repository of the form project/repo, got %q", repo)
	}
	return parts[0], parts[1], nil
}

func artifactURL(apiBase string, tag name.Tag, suffix string) (string, error) {
	project, repository, err := splitProjectRepo(tag.RepositoryStr())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s%s",
		strings.TrimSuffix(apiBase, "/"),
		url.PathEscape(project),
		url.PathEscape(repository), // Harbor expects "/" within a nested repository name percent-encoded as %2F; PathEscape does this.
		url.PathEscape(tag.TagStr()),
		suffix,
	), nil
}

// ensureScanned triggers a scan (best-effort — Harbor returns 409 if one is
// already running/queued, which is fine) and polls the artifact until its
// scan_overview shows a completed scan, or waitTimeout elapses.
func ensureScanned(client *http.Client, apiBase, username, password string, tag name.Tag, waitTimeout time.Duration) error {
	scanURL, err := artifactURL(apiBase, tag, "/scan")
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, scanURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("triggering scan: %w", err)
	}
	resp.Body.Close()
	log.Printf("scan trigger for %s returned %s (409 = already scanning, that's fine)", tag.String(), resp.Status)

	overviewURL, err := artifactURL(apiBase, tag, "?with_scan_overview=true")
	if err != nil {
		return err
	}

	deadline := time.Now().Add(waitTimeout)
	for {
		status, complete, err := pollScanStatus(client, overviewURL, username, password)
		if err != nil {
			return err
		}
		if complete {
			log.Printf("scan complete for %s (status %s)", tag.String(), status)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for scan to complete (last status: %s)", waitTimeout, status)
		}
		time.Sleep(5 * time.Second)
	}
}

func pollScanStatus(client *http.Client, overviewURL, username, password string) (status string, complete bool, err error) {
	req, err := http.NewRequest(http.MethodGet, overviewURL, nil)
	if err != nil {
		return "", false, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("X-Accept-Vulnerabilities", "application/vnd.security.vulnerability.report; version=1.1")

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("Harbor API returned %s: %s", resp.Status, string(body))
	}

	var artifact struct {
		ScanOverview map[string]struct {
			ScanStatus string `json:"scan_status"`
		} `json:"scan_overview"`
	}
	if err := json.Unmarshal(body, &artifact); err != nil {
		return "", false, fmt.Errorf("parsing artifact response: %w", err)
	}
	if len(artifact.ScanOverview) == 0 {
		return "pending", false, nil
	}
	for _, summary := range artifact.ScanOverview {
		switch summary.ScanStatus {
		case "Success":
			return summary.ScanStatus, true, nil
		case "Error":
			return summary.ScanStatus, false, fmt.Errorf("Harbor reported scan status %q", summary.ScanStatus)
		default:
			status = summary.ScanStatus
		}
	}
	return status, false, nil
}

// fetchHarborReport calls Harbor's artifact-vulnerabilities-addition API and
// requests the generic scanner-adapter report schema specifically (rather
// than Harbor's own proprietary UI-oriented format) via
// X-Accept-Vulnerabilities.
func fetchHarborReport(client *http.Client, apiBase, username, password string, tag name.Tag) (*harborVulnerabilityReport, error) {
	reqURL, err := artifactURL(apiBase, tag, "/additions/vulnerabilities")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("X-Accept-Vulnerabilities", "application/vnd.security.vulnerability.report; version=1.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Harbor API returned %s: %s", resp.Status, string(body))
	}

	var report harborVulnerabilityReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("parsing Harbor report (Content-Type %q): %w", resp.Header.Get("Content-Type"), err)
	}
	return &report, nil
}

// detectOS reads /etc/os-release out of the image's layers, most-recent
// layer first (so an overriding file in a later layer wins), and returns
// the os-release ID and VERSION_ID fields.
func detectOS(ref name.Reference) (osType, osVersion string, err error) {
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", "", fmt.Errorf("fetching image: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return "", "", fmt.Errorf("reading layers: %w", err)
	}

	for i := len(layers) - 1; i >= 0; i-- {
		rc, err := layers[i].Uncompressed()
		if err != nil {
			return "", "", fmt.Errorf("reading layer %d: %w", i, err)
		}
		osType, osVersion, found, err := findOSRelease(rc)
		rc.Close()
		if err != nil {
			return "", "", err
		}
		if found {
			return osType, osVersion, nil
		}
	}
	return "", "", fmt.Errorf("no /etc/os-release found in any layer")
}

func findOSRelease(r io.Reader) (osType, osVersion string, found bool, err error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", "", false, nil
		}
		if err != nil {
			return "", "", false, err
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != "etc/os-release" && name != "usr/lib/os-release" {
			continue
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil {
			return "", "", false, err
		}
		osType, osVersion = parseOSRelease(buf.Bytes())
		return osType, osVersion, true, nil
	}
}

func parseOSRelease(data []byte) (osType, osVersion string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "ID="):
			osType = unquote(strings.TrimPrefix(line, "ID="))
		case strings.HasPrefix(line, "VERSION_ID="):
			osVersion = unquote(strings.TrimPrefix(line, "VERSION_ID="))
		}
	}
	return osType, osVersion
}

func unquote(s string) string {
	return strings.Trim(s, `"'`)
}
