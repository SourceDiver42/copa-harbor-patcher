{{- define "copa-harbor.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "copa-harbor.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "copa-harbor.labels" -}}
app.kubernetes.io/name: {{ include "copa-harbor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "copa-harbor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "copa-harbor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "copa-harbor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ .Values.serviceAccount.name | default (include "copa-harbor.fullname" .) }}
{{- else -}}
{{ .Values.serviceAccount.name | default "default" }}
{{- end -}}
{{- end -}}

{{- define "copa-harbor.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "copa-harbor.buildkitImage" -}}
{{- if .Values.buildkit.image -}}
{{- .Values.buildkit.image -}}
{{- else if .Values.buildkit.rootless -}}
moby/buildkit:v0.31.1-rootless
{{- else -}}
moby/buildkit:v0.31.1
{{- end -}}
{{- end -}}

{{- define "copa-harbor.harborAPIBase" -}}
{{- .Values.harbor.apiBase | default (printf "https://%s" .Values.harbor.registry) -}}
{{- end -}}

{{- define "copa-harbor.registrySecretName" -}}
{{- .Values.harbor.existingCredentialsSecret | default (printf "%s-registry-creds" (include "copa-harbor.fullname" .)) -}}
{{- end -}}

{{- define "copa-harbor.webhookSecretName" -}}
{{- .Values.webhook.existingSecret | default (printf "%s-webhook-secret" (include "copa-harbor.fullname" .)) -}}
{{- end -}}

{{/*
Pod-level securityContext applied to every workload. As close to the
PodSecurity "restricted" profile as the buildkitd sidecar allows (see
below) — non-root, RuntimeDefault seccomp, a shared fsGroup so mounted
emptyDirs/secrets are group-writable/readable by uid 1000 regardless of
which container mounts them.
*/}}
{{- define "copa-harbor.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
{{- if not .Values.buildkit.rootless }}
# Rootful buildkitd (uid/gid 0) creates its buildkitd.sock owned by group
# root, not group 1000 — fsGroup/setgid-directory inheritance doesn't apply
# to it in practice (confirmed live: the socket's group stayed root despite
# the emptyDir's setgid bit). Making the non-root containers a supplementary
# member of group 0 lets them use that root-group socket (already
# group-writable via buildkitd's own umask) without needing buildkitd
# itself to run as a different, non-standard group.
supplementalGroups: [0]
{{- end }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
Container-level securityContext for the copa/webhook container. Fully
"restricted"-profile compatible: no privilege escalation, all capabilities
dropped, read-only root filesystem (the mounted /tmp emptyDir covers
anything that needs to write — copa's own working folder, mktemp calls,
etc.).
*/}}
{{- define "copa-harbor.mainSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
{{- end -}}

{{/*
Security context for the buildkitd sidecar.

Default (buildkit.rootless: false, "rootful"/privileged): the standard,
simplest BuildKit-in-Kubernetes setup, and the only one that doesn't depend
on unprivileged user namespaces being enabled at the kernel level — several
hardened distros (e.g. Talos Linux) disable that by default, which breaks
rootless outright regardless of any Kubernetes-level configuration. This is
a strictly larger blast radius than rootless (needs `privileged: true`, and
in turn a namespace-level PodSecurity "privileged" exemption — see README),
but it's the one that's portable across hardened clusters today.

Opt-in (buildkit.rootless: true): cannot fully satisfy the PodSecurity
"restricted" profile either — same privileged-tier namespace exemption is
needed — for two documented reasons verified against a real cluster:

1. Rootless BuildKit creates its own unprivileged user namespace internally
   (standard, safe rootless-container technique), which requires the
   *outer* container's seccomp profile to permit the `unshare`/`clone`
   syscalls that RuntimeDefault blocks — hence `seccompProfile: Unconfined`.
2. Setting up the full UID/GID range inside that namespace goes through
   rootlesskit's `newuidmap`/`newgidmap` helpers, which are setuid-root
   binaries — executing one is a privilege-escalation syscall sequence, so
   `allowPrivilegeEscalation` must stay true here (confirmed live: with it
   false, buildkitd fails at startup with "newuidmap ... operation not
   permitted"). Even with that, dropping the *capability bounding set* to
   nothing still blocks it (the bounding set caps what any future privilege
   transition — including a setuid-root exec — can ever grant a process),
   so this adds back just CAP_SETUID/CAP_SETGID instead of dropping all
   capabilities (confirmed live: `drop: [ALL]` alone reproduces the same
   "operation not permitted" failure even with allowPrivilegeEscalation:
   true).

Either way, a writable root filesystem is needed for BuildKit's own
build-cache storage, so readOnlyRootFilesystem is intentionally not set.
*/}}
{{- define "copa-harbor.buildkitSecurityContext" -}}
{{- if .Values.buildkit.rootless -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
allowPrivilegeEscalation: true
capabilities:
  drop: ["ALL"]
  add: ["SETUID", "SETGID"]
seccompProfile:
  type: Unconfined
appArmorProfile:
  type: Unconfined
{{- else -}}
privileged: true
# The pod-level securityContext defaults every container to uid 1000; the
# non-rootless buildkit image needs real root (confirmed live: without this
# override it inherits uid 1000, and buildkitd's entrypoint then assumes it
# should run in rootless mode — since it wasn't actually set up for that,
# via RootlessKit, it fails immediately with "rootless mode requires to be
# executed as the mapped root in a user namespace").
runAsUser: 0
runAsGroup: 0
runAsNonRoot: false
{{- end -}}
{{- end -}}

{{/*
Renders the buildkitd sidecar container. Pass `.nativeSidecar: true` (via a
merged context dict) when placing this under a Job pod's `initContainers:`
list as a Kubernetes "native sidecar" (restartPolicy: Always) — required
there because a Job only completes when every *regular* container has
exited; buildkitd never exits on its own, so without this the Job's pod
would run forever even after copa finishes successfully (confirmed live).
For a long-running Deployment (webhook mode), include it under `containers:`
as usual with `nativeSidecar` unset.
*/}}
{{- define "copa-harbor.buildkitSidecar" -}}
- name: buildkitd
  {{- if .nativeSidecar }}
  restartPolicy: Always
  {{- end }}
  image: {{ include "copa-harbor.buildkitImage" . | quote }}
  {{- if .Values.buildkit.rootless }}
  args:
    # The rootless image's own default listen address is
    # /run/user/<uid>/buildkit/buildkitd.sock, not copa's default
    # /run/buildkit/buildkitd.sock — pin it explicitly to match the shared
    # emptyDir both containers mount, so copa needs no --addr flag of its own.
    - --addr
    - unix:///run/buildkit/buildkitd.sock
    # Matches BuildKit's own official rootless Kubernetes example
    # (examples/kubernetes/statefulset.rootless.yaml upstream): without
    # this, each build step's nested container fails to mount /proc
    # ("operation not permitted") when the outer container's own mount
    # namespace is itself sandboxed, as in Kubernetes.
    - --oci-worker-no-process-sandbox
  {{- else }}
  # Rootful buildkitd runs as uid 0 (see securityContext below), so the
  # socket it creates in the shared emptyDir defaults to root-owned with no
  # group-write bit — the copa container (uid 1000) then gets "permission
  # denied" connecting to it (confirmed live). fsGroup only fixes group
  # *ownership* of new files in the volume, not their permission bits, so a
  # permissive umask before starting buildkitd is needed too.
  command: ["sh", "-c"]
  args:
    - umask 0007 && exec buildkitd --addr unix:///run/buildkit/buildkitd.sock
  {{- end }}
  securityContext:
    {{- include "copa-harbor.buildkitSecurityContext" . | nindent 4 }}
  resources:
    {{- toYaml .Values.buildkit.resources | nindent 4 }}
  volumeMounts:
    - name: buildkitd-socket
      mountPath: /run/buildkit
    {{- with .Values.extraVolumeMounts }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
{{- end -}}

{{- define "copa-harbor.sharedVolumes" -}}
- name: buildkitd-socket
  emptyDir: {}
- name: docker-config
  secret:
    secretName: {{ include "copa-harbor.registrySecretName" . }}
    items:
      - key: .dockerconfigjson
        path: config.json
- name: scratch
  emptyDir: {}
{{- with .Values.extraVolumes }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end -}}

{{/*
Env vars shared by every container that runs copa/harbor-report (the sweep
Job container and the webhook container). Emits list items only — the
caller owns the `env:` key so it can add container-specific vars too.
*/}}
{{- define "copa-harbor.commonEnv" -}}
- name: DOCKER_CONFIG
  value: /etc/copa/docker
- name: HARBOR_API_BASE
  value: {{ include "copa-harbor.harborAPIBase" . | quote }}
- name: HARBOR_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "copa-harbor.registrySecretName" . }}
      key: username
- name: HARBOR_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "copa-harbor.registrySecretName" . }}
      key: password
- name: HARBOR_INSECURE_SKIP_VERIFY
  value: {{ .Values.harbor.insecureSkipVerify | quote }}
- name: PATCH_TIMEOUT
  value: {{ .Values.patch.timeout | quote }}
{{- end -}}

{{/*
Volume mounts shared by every container that runs copa/harbor-report. Emits
list items only — the caller owns the `volumeMounts:` key so it can add
container-specific mounts too.
*/}}
{{- define "copa-harbor.commonVolumeMounts" -}}
- name: buildkitd-socket
  mountPath: /run/buildkit
- name: docker-config
  mountPath: /etc/copa/docker
  readOnly: true
- name: scratch
  mountPath: /tmp
{{- with .Values.extraVolumeMounts }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end -}}
