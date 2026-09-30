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
// notably no field distinguishing OS vs. language packages.
//
// That distinction matters: Harbor's report mixes OS-package CVEs (apk/apt)
// with language/application ones (npm, pip, composer, ...), and copa driven
// by this report with the OS package manager can only fix the OS ones.
// Emitting a language package copa can't touch makes the "patched" image keep
// reporting that CVE forever (copa re-patches endlessly and never converges).
// Since the API exposes no type field, this tool determines which packages
// are OS-managed by reading the image's own OS package database out of its
// layers — /lib/apk/db/installed (Alpine) or /var/lib/dpkg/status
// (Debian/Ubuntu) — and drops any reported vuln whose package isn't in it. If
// no recognized DB is found (rpm, distroless, unknown), it falls back to
// emitting everything rather than dropping legitimate OS updates.
//
// OS type/version (needed to pick copa's package manager) isn't part of
// Harbor's vulnerability report schema either, so it too is read directly out
// of the image's layers (/etc/os-release, the same primitive Trivy uses) via
// go-containerregistry, in the same single layer pass, using the same
// registry credentials/keychain as everything else in this project.
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

// reportSchemaVersion stamps every report this tool writes. sweep.sh prunes
// any report in the reports dir that lacks the current value before handing
// the dir to copa, so reports written by an older, buggier version of this
// tool (e.g. the pre-fix ones that always recorded zero vulnerabilities)
// can't silently cause copa's skip-detection to skip a still-vulnerable
// image. Bump this whenever a change makes previously-written reports
// untrustworthy. Keep it in sync with the grep in scripts/sweep.sh.
const reportSchemaVersion = "2"

// reportEnvelope is v1alpha2.UpdateManifest plus an extra top-level
// ArtifactName field. pkg/bulk's skip-detection (buildReportIndex) reads
// that literal field directly off the file regardless of --scanner, so it
// must be present even though it's not part of the v1alpha2 schema itself.
// SchemaVersion is our own marker (see reportSchemaVersion); copa ignores
// unknown fields, so it's harmless to the parser.
type reportEnvelope struct {
	v1alpha2.UpdateManifest
	ArtifactName  string `json:"ArtifactName"`
	SchemaVersion string `json:"copaHarborReportVersion"`
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

	osType, osVersion, osPkgs, err := detectImageFacts(tag)
	if err != nil {
		log.Fatalf("detecting OS for %q: %v", *ref, err)
	}
	if osPkgs == nil {
		log.Printf("detected OS %s %s for %s (no readable OS package DB; emitting all fixable vulns unfiltered)", osType, osVersion, *ref)
	} else {
		log.Printf("detected OS %s %s for %s (%d OS-managed packages)", osType, osVersion, *ref, len(osPkgs))
	}

	client := &http.Client{Timeout: 60 * time.Second}
	if os.Getenv("HARBOR_INSECURE_SKIP_VERIFY") == "1" {
		// Keep ProxyFromEnvironment: a bare &http.Transport{} has a nil Proxy,
		// which would bypass HTTP(S)_PROXY entirely — unlike the default
		// client used on the verify path, which honors it.
		client.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicit opt-in for test clusters only
		}
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

	// Harbor's report mixes OS-package vulnerabilities with language/app
	// package ones (npm, pip, composer, ...) and — in the schema we can get
	// from its API — exposes no field to tell them apart. copa, driven by
	// this report with the OS package manager (apk/apt), can only ever fix
	// the OS ones; feeding it a language package it can't touch makes the
	// "patched" image keep reporting that vuln forever (endless re-patch /
	// never converges). So drop any vuln whose package isn't in the image's
	// OS package DB. If we couldn't read that DB (osPkgs == nil: unknown
	// distro, distroless, rpm, ...), fall back to emitting everything rather
	// than dropping legitimate OS updates.
	var osUpdates v1alpha2.UpdatePackages
	var droppedNonOS int
	for _, v := range report.Vulnerabilities {
		if v.FixVersion == "" {
			continue // not fixable, nothing for copa to do
		}
		if osPkgs != nil && !osPkgs[v.Package] {
			droppedNonOS++
			continue // language/app package: copa can't fix it from a Harbor report
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
	if droppedNonOS > 0 {
		log.Printf("dropped %d fixable vuln(s) in non-OS packages (copa patches OS packages only from Harbor reports)", droppedNonOS)
	}

	envelope := reportEnvelope{
		UpdateManifest: v1alpha2.UpdateManifest{
			APIVersion: v1alpha2.APIVersion,
			Metadata: v1alpha2.Metadata{
				OS: v1alpha2.OS{Type: osType, Version: osVersion},
			},
			OSUpdates: osUpdates,
		},
		ArtifactName:  *ref,
		SchemaVersion: reportSchemaVersion,
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

	report, err := parseHarborReport(body)
	if err != nil {
		return nil, fmt.Errorf("parsing Harbor report (Content-Type %q): %w", resp.Header.Get("Content-Type"), err)
	}
	return report, nil
}

// parseHarborReport decodes the body of Harbor's additions/vulnerabilities
// endpoint. Harbor returns the report(s) as a JSON object *keyed by MIME
// type* — e.g. {"application/vnd.security.vulnerability.report; version=1.1":
// {"vulnerabilities": [...]}} — NOT as a flat {"vulnerabilities": [...]}.
// Decoding the outer object straight into harborVulnerabilityReport therefore
// silently yields zero vulnerabilities (the previous behaviour, which made
// copa believe every image was already clean). We handle both shapes: try the
// MIME-keyed map first, then fall back to a flat object, so the tool is robust
// across Harbor versions and to the raw scanner-adapter format.
func parseHarborReport(body []byte) (*harborVulnerabilityReport, error) {
	// Preferred shape: object keyed by MIME type. Each value is a report; we
	// merge the vulnerabilities across all reports present (there is normally
	// exactly one, matching the X-Accept-Vulnerabilities we requested).
	var byMIME map[string]json.RawMessage
	if err := json.Unmarshal(body, &byMIME); err == nil {
		if _, isFlat := byMIME["vulnerabilities"]; !isFlat && len(byMIME) > 0 {
			merged := &harborVulnerabilityReport{}
			decoded := false
			for _, raw := range byMIME {
				var r harborVulnerabilityReport
				if err := json.Unmarshal(raw, &r); err != nil {
					continue // a value that isn't a report object; skip it
				}
				merged.Vulnerabilities = append(merged.Vulnerabilities, r.Vulnerabilities...)
				decoded = true
			}
			if decoded {
				return merged, nil
			}
		}
	}

	// Fallback: a flat report object, i.e. {"vulnerabilities": [...]}.
	var flat harborVulnerabilityReport
	if err := json.Unmarshal(body, &flat); err != nil {
		return nil, err
	}
	return &flat, nil
}

// detectImageFacts reads, from the image's layers (most-recent first, so a
// later layer's copy of a file wins), both the os-release fields and the set
// of package names the OS package manager tracks. osPkgs is nil — not an
// empty map — when no recognized package DB (apk/dpkg) was found, so callers
// can tell "distro with no OS packages" (impossible) apart from "couldn't
// read the DB, don't filter" (rpm, distroless, unknown).
func detectImageFacts(ref name.Reference) (osType, osVersion string, osPkgs map[string]bool, err error) {
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", "", nil, fmt.Errorf("fetching image: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return "", "", nil, fmt.Errorf("reading layers: %w", err)
	}

	for i := len(layers) - 1; i >= 0; i-- {
		rc, err := layers[i].Uncompressed()
		if err != nil {
			return "", "", nil, fmt.Errorf("reading layer %d: %w", i, err)
		}
		lt, lv, pkgs, err := scanLayer(rc)
		rc.Close()
		if err != nil {
			return "", "", nil, err
		}
		if osType == "" && lt != "" {
			osType, osVersion = lt, lv
		}
		if osPkgs == nil && len(pkgs) > 0 {
			osPkgs = pkgs
		}
		if osType != "" && osPkgs != nil {
			break // found both; older layers can't override
		}
	}
	if osType == "" {
		return "", "", nil, fmt.Errorf("no /etc/os-release found in any layer")
	}
	return osType, osVersion, osPkgs, nil
}

// scanLayer reads one uncompressed layer tarball, extracting the os-release
// fields and/or the OS package set if either appears in it. Non-regular
// entries are skipped: on Alpine /etc/os-release is a symlink to
// /usr/lib/os-release, and a symlink tar entry carries no content — reading
// it would yield an empty OS type and silently break copa's report-driven
// patching (it couldn't pick the package manager).
func scanLayer(r io.Reader) (osType, osVersion string, osPkgs map[string]bool, err error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return osType, osVersion, osPkgs, nil
		}
		if err != nil {
			return "", "", nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		switch strings.TrimPrefix(hdr.Name, "./") {
		case "etc/os-release", "usr/lib/os-release":
			buf, err := io.ReadAll(tr) //nolint:gosec // bounded by layer size; os-release is tiny
			if err != nil {
				return "", "", nil, err
			}
			if t, v := parseOSRelease(buf); t != "" && osType == "" {
				osType, osVersion = t, v
			}
		case "lib/apk/db/installed":
			buf, err := io.ReadAll(tr) //nolint:gosec // bounded by layer size
			if err != nil {
				return "", "", nil, err
			}
			if p := parseAPKInstalled(buf); len(p) > 0 {
				osPkgs = p
			}
		case "var/lib/dpkg/status":
			buf, err := io.ReadAll(tr) //nolint:gosec // bounded by layer size
			if err != nil {
				return "", "", nil, err
			}
			if p := parseDpkgStatus(buf); len(p) > 0 {
				osPkgs = p
			}
		}
	}
}

// parseAPKInstalled extracts package (P:) and origin (o:) names from Alpine's
// /lib/apk/db/installed. Origin names are included too so a vuln Trivy
// attributes to a subpackage's origin still counts as OS-managed.
func parseAPKInstalled(data []byte) map[string]bool {
	pkgs := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) > 2 && (line[0] == 'P' || line[0] == 'o') && line[1] == ':' {
			pkgs[line[2:]] = true
		}
	}
	return pkgs
}

// parseDpkgStatus extracts binary (Package:) and source (Source:) package
// names from Debian/Ubuntu's /var/lib/dpkg/status. Source names are included
// because Trivy sometimes reports a vuln against the source package name.
func parseDpkgStatus(data []byte) map[string]bool {
	pkgs := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Package: "):
			pkgs[strings.TrimSpace(line[len("Package:"):])] = true
		case strings.HasPrefix(line, "Source: "):
			s := strings.TrimSpace(line[len("Source:"):])
			if i := strings.IndexByte(s, ' '); i >= 0 {
				s = s[:i] // drop trailing "(version)"
			}
			pkgs[s] = true
		}
	}
	return pkgs
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
