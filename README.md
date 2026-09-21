# copa-harbor-patcher

Automates [copa](https://github.com/project-copacetic/copacetic) vulnerability
patching for images in a [Harbor](https://goharbor.io) registry, running in
Kubernetes as either a nightly `CronJob` sweep or a Harbor-webhook-triggered
patch, sharing one container image and one Helm chart.

Vulnerability data comes from **Harbor's own built-in scanner** (Trivy, run
by Harbor itself) via its REST API — this project does not bundle or run a
second scanner.

## How it works

- **CronJob mode** (`mode: cronjob`): runs `copa patch --config bulk.yaml
  --push` against every image in a declarative `PatchConfig` (see
  copacetic's [bulk-image-patching
  docs](https://github.com/project-copacetic/copacetic/blob/main/website/docs/bulk-image-patching.md)),
  then fetches Harbor's freshly computed vulnerability report for whatever
  got pushed and drops it into a persistent reports volume, so the next
  scheduled run's skip-detection can avoid re-patching images with no new
  fixable vulnerabilities.
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
  --set harbor.registry=harbor.example.com \
  --set harbor.credentials.username='robot$library+copa-patcher' \
  --set harbor.credentials.password='...' \
  --set-file cronjob.bulkConfig=./bulk.yaml
```

Or directly from the OCI chart published by CI on each `v*` tag (no
checkout needed — note new GHCR packages default to private, so make the
`charts/copa-harbor-patcher` package public in its GitHub package settings
first if you want `helm install` to work without `helm registry login`):

```bash
helm install copa-harbor oci://ghcr.io/sourcediver42/charts/copa-harbor-patcher --version 0.1.0 \
  --set harbor.registry=harbor.example.com \
  --set harbor.credentials.username='robot$library+copa-patcher' \
  --set harbor.credentials.password='...' \
  --set-file cronjob.bulkConfig=./bulk.yaml
```

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

See `chart/values.yaml` for the full set with comments. Key ones:

| Value | Purpose |
|---|---|
| `mode` | `cronjob` \| `webhook` \| `both` |
| `harbor.registry` | `host[:port]`, no scheme — used for `bulk.yaml`'s `target.registry` and the pushed docker-config secret |
| `harbor.apiBase` | Harbor Core API base URL; defaults to `https://<harbor.registry>` |
| `harbor.credentials.{username,password}` | Robot account, templated into a `dockerconfigjson` Secret. Keep the values file with real credentials out of git — `--set`/`-f` values land in Helm's in-cluster release Secret (base64, not encrypted), acceptable for a throwaway test robot account but worth a harder look (External Secrets Operator, sealed-secrets, etc.) before pointing this at production Harbor. |
| `buildkit.rootless` | `false` (default) or `true` — see below |
| `cronjob.bulkConfig` | The `PatchConfig` YAML, embedded directly (not sensitive) |
| `webhook.sharedSecret` / `webhook.existingSecret` | Bearer token Harbor's webhook policy must send as its "Auth Header"; auto-generated on install if left unset |
| `extraVolumes` / `extraVolumeMounts` | Mounted on both the main container and the buildkitd sidecar — this is the integration point for CA trust (see below) and anything else your cluster needs injected |

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
- **Skip-detection / auto-rescan only covers `tags.strategy: list`** entries
  in `bulk.yaml`. `pattern`/`latest`-discovered images are patched every run
  (`sweep-helper` logs why to stderr) since resolving their live source tags
  ahead of time would require duplicating copa's own registry-discovery
  logic.
- **Webhook mode has not yet been exercised against a real Harbor-triggered
  event** in this repo's own testing (only unit-tested and validated with a
  synthetic request) — the webhook payload parsing intentionally reads only
  `event_data.resources[0].resource_url`, discarding everything else, so it
  should be robust to most Harbor versions/events, but treat this as the
  first thing to verify against your actual Harbor version before relying on
  it. Also verify what header name and format your Harbor version actually
  sends its configured webhook "Auth Header" as.
- **DNS**: if your cluster's node/upstream DNS has search domains configured
  (`ndots` defaults to 5), a short `harbor.registry` hostname gets tried
  against every search domain *before* being tried as an absolute name. On a
  cluster whose search-domain DNS happens to answer for that exact
  search-suffixed query (e.g. a wildcard record), this can silently resolve
  your registry hostname to something unrelated — this bit us during testing
  in an environment with such a wildcard. This chart doesn't work around it
  by default (a real Harbor hostname is unlikely to collide in practice); if
  you hit it, the fix is `dnsConfig.options: [{name: ndots, value: "1"}]` on
  the pod, or just use a hostname with enough dots that this doesn't apply.
- The values-driven credentials path (`harbor.credentials.*`) is the
  supported default for this project's own testing; see the values-reference
  note above before using it against a real production Harbor.
