# copa-harbor-patcher

Automates [copa](https://github.com/project-copacetic/copacetic) vulnerability
patching for images in a [Harbor](https://goharbor.io) registry, running in
Kubernetes as either a nightly `CronJob` sweep or a Harbor-webhook-triggered
patch, sharing one container image and one Helm chart.

Vulnerability data comes from **Harbor's own built-in scanner** (Trivy, run
by Harbor itself) via its REST API — this project does not bundle or run a
second scanner.

## How it works

- **CronJob mode** (`mode: cronjob`): for every image in a declarative
  `PatchConfig` (see copacetic's [bulk-image-patching
  docs](https://github.com/project-copacetic/copacetic/blob/main/website/docs/bulk-image-patching.md)
  for the config schema), runs a **comprehensive** `copa patch` (updates all
  OS packages, across every platform of a multi-arch image) and pushes the
  result as `<tag>-patched`. Before patching each image it asks Harbor whether
  the already-patched target still has any fixable **OS-package** CVEs; if not,
  it skips. It deliberately does **not** use copa's report-driven bulk mode —
  copa matches reports to platforms by architecture, which Harbor's report has
  no per-platform notion of, so a multi-arch image would patch nothing ("No
  scan report for platform"). See [Known limitations](#known-limitations).
- **Webhook mode** (`mode: webhook`): a small Go HTTP server receives
  Harbor's webhook events, validates a shared secret, and patches the single
  image identified in the event.
- **`mode: both`** runs both from the same chart install.

BuildKit runs as a **sidecar** in the same pod, which is **rootful (`privileged: true`) by
default**, not rootless. See [BuildKit: rootful vs
rootless](#buildkit-rootful-vs-rootless) for why.

## Quickstart

From a checkout:

```bash
helm install copa-harbor ./chart \
  --set harborserver.registry=harbor.example.com \
  --set harborserver.credentials.username='robot$library+copa-patcher' \
  --set harborserver.credentials.password='...' \
  --set-file cronjob.bulkConfig=./bulk.yaml
```

Or install a published chart without a checkout. CI publishes each `v*` tag
two ways:

**HTTP Helm repo** (classic `helm repo add`, GitHub Pages — no OCI-capable
Helm or registry login needed):

```bash
helm repo add copa-harbor https://sourcediver42.github.io/copa-harbor-patcher
helm repo update
helm install copa-harbor copa-harbor/copa-harbor-patcher --version 0.1.0 \
  --set harborserver.registry=harbor.example.com \
  --set harborserver.credentials.username='robot$library+copa-patcher' \
  --set harborserver.credentials.password='...' \
  --set-file cronjob.bulkConfig=./bulk.yaml
```

**OCI artifact** (GHCR — note new GHCR packages default to private, so make
the `charts/copa-harbor-patcher` package public in its GitHub package
settings first if you want `helm install` to work without `helm registry
login`):

```bash
helm install copa-harbor oci://ghcr.io/sourcediver42/charts/copa-harbor-patcher --version 0.1.0 \
  --set harborserver.registry=harbor.example.com \
  --set harborserver.credentials.username='robot$library+copa-patcher' \
  --set harborserver.credentials.password='...' \
  --set-file cronjob.bulkConfig=./bulk.yaml
```

### Using an existing credentials secret

Instead of passing `harborserver.credentials.*` (which lands in Helm's release
Secret), point the chart at a secret you manage out-of-band — e.g. one
produced by External Secrets Operator or sealed-secrets. It only needs
**plaintext `username` and `password` keys**, plus an optional `url`
(registry host) key. It does **not** need a precomputed `.dockerconfigjson`:
the docker `config.json` copa/BuildKit use for registry auth is generated
from those keys at container startup.

```bash
kubectl create secret generic my-harbor-creds \
  --from-literal=username='robot$library+copa-patcher' \
  --from-literal=password='...' \
  --from-literal=url='harbor.example.com'

helm install copa-harbor ./chart \
  --set harborserver.registry=harbor.example.com \
  --set harborserver.existingSecret=my-harbor-creds \
  --set-file cronjob.bulkConfig=./bulk.yaml
```

If your secret uses different key names, override them via
`harborserver.existingSecretKeys.{username,password,url}`. If it has no
registry-host key, set `harborserver.existingSecretKeys.url=""` — the container
then uses `harborserver.registry` as the docker-config auth host.

### Required Harbor robot account permissions

The robot account needs **pull, push, and list-tags**, plus **scan read and
create**, on the target project:

- `repository`: `pull`, `push`, `list`
- `tag`: `list`
- `artifact`: `read`, `list`
- `scan`: `read`, `create`

Skip-detection does a live tag-list call even for images it ends up
skipping — a push-only robot account will silently defeat it (fail-open →
every run re-patches everything).

## Values reference

> **Upgrading from ≤0.2.0:** the top-level `harbor:` values key was renamed
> to `harborserver:` (to avoid confusion with the Harbor chart/product).
> Update your values files and `--set harbor.*` flags to `harborserver.*`.

See `chart/values.yaml` for the full set with comments. Key ones:

| Value | Purpose |
|---|---|
| `mode` | `cronjob` \| `webhook` \| `both` |
| `image.repository` | Container image; defaults to `ghcr.io/sourcediver42/copa-harbor-patcher` (this repo's CI-published image) |
| `imagePullSecrets` | List of `{name: <secret>}` pull secrets, for a private GHCR package |
| `podLabels` / `podAnnotations` | Extra labels/annotations applied to every workload's pod template |
| `harborserver.registry` | `host[:port]`, no scheme — used for `bulk.yaml`'s `target.registry` and the pushed docker-config secret |
| `harborserver.apiBase` | Harbor Core API base URL; defaults to `https://<harborserver.registry>` |
| `harborserver.credentials.{username,password}` | Robot account, templated into an Opaque Secret (username/password/url); the docker `config.json` is generated from it at container startup. Keep the values file with real credentials out of git — `--set`/`-f` values land in Helm's in-cluster release Secret (base64, not encrypted), acceptable for a throwaway test robot account but worth a harder look (External Secrets Operator, sealed-secrets, etc.) before pointing this at production Harbor. |
| `harborserver.existingSecret` | Name of a pre-existing secret with plaintext `username`/`password` (+ optional `url`) keys, used instead of `harborserver.credentials`. No `.dockerconfigjson` required — it's inferred at startup. See [Using an existing credentials secret](#using-an-existing-credentials-secret). |
| `harborserver.existingSecretKeys.{username,password,url}` | Key names to read from `harborserver.existingSecret`. Default `username`/`password`/`url`; set `url` to `""` if the secret has no registry-host key (falls back to `harborserver.registry`). |
| `buildkit.rootless` | `false` (default) or `true` — see below |
| `patch.platforms` | Platforms to patch, e.g. `["linux/amd64"]`; empty = all platforms in the image. Unlisted platforms are preserved unpatched. See [Multi-arch images](#multi-arch-images) |
| `buildkit.emulation` | `false` (default) or `true` — install QEMU/binfmt so non-native platforms can be patched. See [Multi-arch images](#multi-arch-images) |
| `cronjob.bulkConfig` | The `PatchConfig` YAML, embedded directly (not sensitive) |
| `webhook.sharedSecret` / `webhook.existingSecret` | Bearer token Harbor's webhook policy must send as its "Auth Header"; auto-generated on install if left unset |
| `extraVolumes` / `extraVolumeMounts` | Mounted on both the main container and the buildkitd sidecar — this is the integration point for CA trust (see below) and anything else your cluster needs injected |
| `extraEnv` | Extra env vars applied to **both** the main container and the buildkitd sidecar — the integration point for an egress HTTP proxy (see [Egress HTTP proxy](#egress-http-proxy)) |

# Buildkit rootful vs rootless
Rootful (`buildkit.rootless: false`, the default) is the simplest, most
portable option — it just needs a namespace-level PodSecurity `privileged`
exemption (see below), with no dependency on kernel features. Rootless is
opt-in for clusters that support it well and where you want a smaller
footprint than full `privileged: true`.

**Rootful specifics** (all confirmed live):
- Needs `privileged: true`.
- The pod-level securityContext defaults every container to uid 1000; the
  non-rootless buildkit image needs real root, so the buildkitd container
  explicitly overrides to `runAsUser/runAsGroup: 0`.
- The socket it creates in the shared emptyDir ends up **root-owned with no
  group-write bit** by default — a permissive `umask 0007` before starting
  buildkitd fixes the *permission bits*, but the socket's **group** still
  comes out as `root`, not the pod's `fsGroup` (setgid-directory inheritance
  didn't apply to it in this testing, for reasons not fully root-caused).
  The fix is `supplementalGroups: [0]` on the pod, so the non-root
  containers can use the existing root-group socket without buildkitd
  needing a non-standard group.

**Rootless specifics** (`buildkit.rootless: true`, all confirmed live):
1. Creates its own unprivileged user namespace internally (the standard,
   safe rootless-container technique) — needs `seccompProfile: Unconfined`
   (RuntimeDefault blocks the `unshare`/`clone` syscalls involved) and
   `appArmorProfile: Unconfined` on clusters that enforce AppArmor.
2. Sets up its UID/GID range via rootlesskit's `newuidmap`/`newgidmap`,
   which are setuid-root binaries — needs `allowPrivilegeEscalation: true`,
   and `capabilities: {drop: [ALL], add: [SETUID, SETGID]}` (dropping *all*
   capabilities, including the bounding set, blocks even a setuid-root exec
   from gaining anything — the fix is adding back just `SETUID`/`SETGID`).
3. Needs `--oci-worker-no-process-sandbox` (matches BuildKit's own [official
   rootless Kubernetes
   example](https://github.com/moby/buildkit/blob/master/examples/kubernetes/statefulset.rootless.yaml)) —
   without it, each build step's nested container fails to mount `/proc`
   ("operation not permitted") when the outer container's own mount
   namespace is itself sandboxed, as in Kubernetes.
4. **Does not work on Talos Linux** (as of this writing): Talos disables
   unprivileged user namespaces at the kernel level by default
   (`user.max_user_namespaces=0`) — see [siderolabs/talos#12287](https://github.com/siderolabs/talos/issues/12287),
   an open, unresolved issue for this exact workload. Fixable via
   `machine.sysctls`, but not reliably even then per that issue's reports.
   Use rootful on Talos.

## Multi-arch images

A comprehensive patch rebuilds **every** platform of a multi-arch image, and
BuildKit can only build a platform it has a worker for. On a single-arch node
(e.g. amd64) without emulation, patching `linux/arm64`/`linux/arm/v7` fails with
`emulation is not enabled for platform …`, which fails the whole image. Two
ways to handle it (combinable):

- **`buildkit.emulation: true`** — adds a privileged `tonistiigi/binfmt` init
  container that registers QEMU handlers at the node level, so the worker can
  build every platform. Patches all arches; emulated builds are slower and the
  registration is node-wide (kernel `binfmt_misc`).
- **`patch.platforms: ["linux/amd64", …]`** — patch only the platforms you
  list (copa `--platform`); the rest are **preserved unpatched** (and stay
  vulnerable). Fast, no node changes — right when you only deploy one arch.

**Single arch → single-arch output.** If you list exactly **one** platform, the
sweep pins the source to that platform's digest and produces a **single-arch
patched image** (not a manifest list). This matters: with a preserved
manifest list, Harbor scans the whole index, so the *other* arches' CVEs keep
the count high and the patched tag looks just as vulnerable as the source — you
can't tell it apart without pulling the per-arch child. A single-arch output
scans cleanly. So on an amd64-only cluster, `patch.platforms: ["linux/amd64"]`
gives you an amd64 `…-patched` image Harbor reports accurately.

If you leave both at defaults on a single-arch node, a multi-arch image's
non-native platforms will fail to patch.

**Talos (and other nodes that already provide binfmt):** keep
`buildkit.emulation: false`. The Talos **binfmt system extension** already
registers QEMU emulators node-wide (with the `F` flag, so BuildKit uses them
directly) — the rootful sidecar will then patch every platform with no init
container. Enabling `buildkit.emulation` on Talos actually *breaks* it: the
`tonistiigi/binfmt` container tries to mount `binfmt_misc` on Talos's
locked-down `/proc` and dies with `cannot mount binfmt_misc filesystem … no
such device`. Same applies to any cluster running a node-level binfmt
DaemonSet — rely on it and leave this off.

## Egress HTTP proxy

In a proxy-only egress network, copa's patch build fails at image resolution
(`dial tcp …:443: i/o timeout` on e.g.
`ghcr.io/project-copacetic/copacetic/debian:stable-slim`). That pull is done by
**BuildKit**, which reads proxy settings from the **buildkitd sidecar's own
environment** — so the proxy must be set there, not only on the main container.
`extraEnv` applies to both. Put your Harbor host (and cluster-internal ranges)
in `NO_PROXY` so target-image pulls/pushes stay direct, and set both upper- and
lower-case forms:

```yaml
extraEnv:
  - {name: HTTPS_PROXY, value: "http://proxy.internal:3128"}
  - {name: HTTP_PROXY,  value: "http://proxy.internal:3128"}
  - {name: NO_PROXY,    value: "harbor.example.com,.svc,.cluster.local,10.0.0.0/8"}
  - {name: https_proxy, value: "http://proxy.internal:3128"}
  - {name: http_proxy,  value: "http://proxy.internal:3128"}
  - {name: no_proxy,    value: "harbor.example.com,.svc,.cluster.local,10.0.0.0/8"}
```

This covers image resolve/pull/push (BuildKit) and `harbor-report`/copa's own
registry + Harbor-API calls. The package-download RUN steps inside the patch
build (apt/apk reaching distro mirrors) are a separate concern not addressed by
this — if your mirrors are only reachable via the proxy, raise an issue.

## Pod Security Admission

**Both** rootful and rootless buildkitd need a namespace-level PodSecurity
`privileged` exemption — there's no "baseline" middle ground that admits
either (Baseline already forbids `privileged: true`, and separately forbids
`seccompProfile`/`appArmorProfile: Unconfined`). Pod Security Admission
evaluates the **whole pod**: if any one container (including the buildkitd
`initContainers` entry) fails, the entire pod is rejected — there's no
per-container exemption. Put this chart in its own namespace and exempt just
that namespace:

```bash
kubectl label ns <namespace> pod-security.kubernetes.io/enforce=privileged
```

## Known limitations

- **Cross-registry multi-platform preserve**: when patching a multi-arch
  source pulled from one registry (e.g. Docker Hub) with `platforms:` scoped
  to a subset, copa fails to push the final manifest list with `blob unknown
  to registry` for the *preserved* (non-target) platforms — confirmed live.
  Preserving platforms across a source→target registry boundary apparently
  isn't fully implemented for that path today. This is not something this
  chart/image can work around; it doesn't occur when source and target are
  the same registry, or when the source is already single-platform.
- **Harbor's own Trivy scan can fail on very old/EOL base images** (observed
  live against a patched Alpine 3.18 image, itself past EOL) — when it does,
  `harbor-report` logs a warning and the next sweep fails open (re-patches
  rather than silently skipping), so this degrades gracefully but does mean
  skip-detection won't kick in for that image until Harbor's scan succeeds.
- **Only OS-package CVEs are patched.** copa driven by a Harbor report patches
  with the image's OS package manager (`apk`/`apt`), so it can only fix
  OS-package vulnerabilities — not language/application ones (npm, pip,
  composer, …), which Harbor's scan also reports. Harbor's report exposes no
  field to tell the two apart, so `harbor-report` distinguishes them by reading
  the image's own OS package DB (`/lib/apk/db/installed` or
  `/var/lib/dpkg/status`) and **drops the non-OS vulns** (it logs the count).
  Practical consequence: for a fat application image (e.g. a PHP/Node app),
  Harbor's total CVE count will **not** drop to zero after patching — the
  language-package CVEs remain, by design, because this tool can't fix them.
  Rebuild those from an updated base/app image instead. (Before v0.3.x these
  were mislabeled as OS packages and fed to copa, which couldn't fix them and
  re-patched the image every run without converging.)
- **"Fixable" in Harbor ≠ fixable by this tool.** Harbor/Trivy flag a CVE as
  Fixable when a fixed version exists *in the vulnerability database* — not when
  that fix is installable in the image's distro release. A comprehensive patch
  installs the latest packages available in the release's repos; CVEs whose fix
  isn't in that release (common on EOL or frozen bases — e.g. an Alpine 3.19 or
  an old pinned image) **stay Fixable in Harbor even after patching**. So a
  patched image's "Fixable" count often won't reach zero. The real fix is to
  rebuild from an updated base image. To avoid re-patching such images every
  run, skip-detection records the fixable-OS count it last patched at and skips
  while it's unchanged (a `<target>.fixable` memo file in the reports volume) —
  so each image is patched at most once per change in its CVE set. Delete the
  memo file (or change the source) to force a re-patch.
- **Skip-detection only covers `tags.strategy: list`** entries in `bulk.yaml`.
  `pattern`/`latest`-discovered images are not swept (`sweep-helper` logs why
  to stderr) since resolving their live source tags ahead of time would
  require duplicating copa's own registry-discovery logic.
- **Webhook mode has not yet been exercised against a real Harbor-triggered
  event** in this repo's own testing (only unit-tested and validated with a
  synthetic request) — the webhook payload parsing intentionally reads only
  `event_data.resources[0].resource_url`, discarding everything else, so it
  should be robust to most Harbor versions/events, but treat this as the
  first thing to verify against your actual Harbor version before relying on
  it. Also verify what header name and format your Harbor version actually
  sends its configured webhook "Auth Header" as.
- **DNS**: if your cluster's node/upstream DNS has search domains configured
  (`ndots` defaults to 5), a short `harborserver.registry` hostname gets tried
  against every search domain *before* being tried as an absolute name. On a
  cluster whose search-domain DNS happens to answer for that exact
  search-suffixed query (e.g. a wildcard record), this can silently resolve
  your registry hostname to something unrelated — this bit us during testing
  in an environment with such a wildcard. This chart doesn't work around it
  by default (a real Harbor hostname is unlikely to collide in practice); if
  you hit it, the fix is `dnsConfig.options: [{name: ndots, value: "1"}]` on
  the pod, or just use a hostname with enough dots that this doesn't apply.
- The values-driven credentials path (`harborserver.credentials.*`) is the
  supported default for this project's own testing; see the values-reference
  note above before using it against a real production Harbor.
