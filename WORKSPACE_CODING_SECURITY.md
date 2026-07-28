# Workspace-Scoped Coding Agent security boundary

## Decision record

**Status:** approved boundary with default-off source contracts for selection,
isolated staging, broker operations, Sandbox configuration, and result
verification. Workspace coding stays build-unavailable until Diff/Apply,
packaged worker/launcher integration, and the Windows acceptance matrix pass.

**V1 boundary:** a fresh, network-disabled Windows Sandbox containing a bounded
copy of one user-selected Git working tree. The original repository is never
mapped into the sandbox. A normal process, a dedicated Git worktree, a Job
Object, an AppContainer, or path checks alone are not an acceptable fallback.

The application already uses Windows Sandbox for release-bound runtime
validation. Workspace coding may reuse its authenticated input preparation,
two-mapping structure, Protected Client configuration, reparse-point checks,
bounded result verification, and post-run host verification. It must use a
separate coding-task configuration with networking disabled.

This decision intentionally excludes Windows editions or managed devices where
Windows Sandbox and its required virtualization features are unavailable. The
feature must report `workspace_sandbox_unavailable`; it must not silently run
the task on the host.

## Security goals

The boundary must:

1. give one task access only to the reviewed repository snapshot intentionally
   copied into its task staging directory;
2. prevent access to the original repository, host user profile, host
   credentials, ambient provider secrets, browser state, SSH/GPG material,
   package-manager credentials, and unrelated drives;
3. prevent network access, including host-reachable private networks;
4. preserve every pre-existing tracked, modified, deleted, and untracked user
   path in the original repository;
5. provide no host-side change until the user reviews and explicitly adopts an
   exact diff in a later Apply step;
6. permit only broker-defined relative file operations and separately approved,
   tokenized verification-command profiles;
7. terminate the worker and every owned child process on cancellation or limit
   breach;
8. return bounded, content-minimized evidence and make failed verification
   failed or partial, never completed; and
9. leave Codex, Qwen Code, tutor, dictation, compose, pointing, skills, and
   ordinary Task Agent modes without workspace authority.

## Non-goals and residual risks

Windows Sandbox reduces host exposure; it is not a proof that arbitrary code is
safe. This design does not claim to contain:

- a Windows Sandbox, Hyper-V, Windows kernel, or CPU isolation escape;
- denial of service entirely within the configured memory, process, time, and
  writable-mapping bounds;
- disclosure of source files that the user explicitly includes in the staged
  repository copy;
- malicious or vulnerable repository code changing files inside the disposable
  staging copy;
- malicious changes that a user knowingly approves and adopts after diff
  review;
- logic errors in the future host-side diff parser or adoption implementation;
  or
- generated code quality, correctness, licensing, or absence of
  vulnerabilities.

Windows Sandbox mapped folders have no per-folder disk quota. The host must
monitor the bounded staging root, terminate the Sandbox on quota breach, and
reject the complete run if the result tree exceeds its declared file or byte
limits. This is mitigation, not a storage-containment guarantee.

## Authority layers

Workspace coding is a distinct high-authority feature. Every operation requires
all applicable layers:

1. `FeatureCapability.WORKSPACE_CODING` is available in that reviewed build;
2. the current versioned `workspace_coding` user permission is enabled;
3. the task owns an exact run-bound grant:
   - `workspace.read` for the staged copy,
   - `workspace.write` for changes inside that copy, and
   - `workspace.command` for an approved verification command;
4. write, command, and later Apply operations consume a one-use action approval
   bound to the task, source snapshot, exact target, and argument digest; and
5. the Windows Sandbox runtime attests the expected task/run nonce and exact
   staged manifest before any tool becomes available.

One authority never implies another. `workspace.read` cannot write or run a
command. A write grant cannot run a command or adopt changes. A command grant
cannot install dependencies, change the command profile, or adopt results.

The existing Codex and Qwen Code integrations remain response providers. Their
read-only flags, temporary working directory, safe approval mode, bounded
runtime, and prompt-through-stdin behavior are unchanged. They are not reused as
workspace workers and receive no workspace grant, mapped repository, broker
handle, Apply token, or task credentials.

## Host-side workspace selection

V1 accepts one user-selected, existing Git working tree on a fixed local NTFS
volume. Selection is explicit for every task; recent paths are display
convenience only and confer no authority.

Before staging, the trusted host must:

1. open the selected directory without following a link and obtain its final
   path from the directory handle;
2. reject UNC, device, volume-GUID, subst, remote, removable, cloud-placeholder,
   reparse-point, alternate-data-stream, case-ambiguous, and non-NTFS roots;
3. invoke one authenticated, absolute Git for Windows executable with
   `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=NUL`,
   `GIT_NO_REPLACE_OBJECTS=1`, `core.hooksPath=NUL`,
   `core.fsmonitor=false`, and `core.attributesFile=NUL`;
4. resolve and require one repository top level equal to the final selected
   path;
5. reject replacement refs, grafts, object alternates, executable FSMonitor,
   unexpected hooks, unsafe repository ownership, and unresolved submodule
   boundaries;
6. record the exact `HEAD` commit, branch/detached state, index identity, and
   porcelain-v2 status including every tracked modification, deletion, rename,
   conflict, ignored-policy result, and untracked path;
7. reject repositories whose path/file/byte counts exceed the task limits; and
8. show the selected final path, commit, and dirty-state summary before the task
   can stage source.

A dirty repository is allowed, but its current user-visible bytes form the
baseline. They are copied to the isolated snapshot and hashed. Later adoption
must compare the original repository to that same baseline and stop if any
baseline path or repository identity changed.

## Staging and secret exclusion

The host creates a new private task root under
`%LOCALAPPDATA%\Clicky\coding-tasks\<opaque-run-directory>`. The name is derived
from an opaque random identifier, not the repository or user name. The
directory grants access only to the current user and SYSTEM.

The staging copy contains ordinary regular working-tree files needed for the
task, including approved untracked files, but never contains:

- `.git` directories/files, hooks, object databases, remote URLs, reflogs, or
  credential helpers;
- any reparse point, symbolic link, junction, mount point, hard-linked file,
  named pipe, socket, device, alternate data stream, sparse/cloud placeholder,
  or path escaping through Unicode/case normalization;
- `.env`, `.env.*`, `.netrc`, `.npmrc`, `.yarnrc*`, `.pypirc`,
  `.git-credentials`, `.gitconfig`, package-store authentication files, or
  files whose reviewed metadata classifies them as credentials;
- SSH private keys, GPG private keys, certificate private keys, signing keys,
  OAuth tokens, browser profiles, cloud credentials, wallet secrets, password
  databases, DPAPI token blobs, or Clicky local state;
- user/global package caches, user profiles, editor settings, shell histories,
  or unrelated build caches; or
- files outside the selected repository top level.

The preparer fails closed on a denied path. It does not silently omit a denied
path and continue with an incomplete snapshot. The UI may identify the denied
relative path and policy category, but must not show or persist its contents.

The host writes a canonical baseline manifest containing relative path,
regular-file mode, byte count, and SHA-256 for every staged file. The manifest,
task/run identity, selected-root identity, `HEAD`, dirty-state digest, limits,
command-profile digests, and a fresh nonce are authenticated together. The raw
host path and user name are not given to the model.

## Windows Sandbox configuration

Each run uses a new `.wsb` configuration and a newly started Sandbox. Reuse of a
Sandbox instance is forbidden.

The configuration has exactly two non-overlapping host mappings:

- one read-only input mapping containing the authenticated worker/runtime,
  baseline manifest, policy, and task envelope; and
- one fresh writable task mapping containing only the isolated repository copy
  and bounded results directory.

The original repository and its parent, `%USERPROFILE%`, `%APPDATA%`,
`%LOCALAPPDATA%`, package caches, Windows credential locations, browser data,
SSH/GPG directories, and host toolchain directories are never mapped.

The required `.wsb` settings are:

- `<Networking>Disable</Networking>`;
- `<vGPU>Disable</vGPU>`;
- `<AudioInput>Disable</AudioInput>`;
- `<VideoInput>Disable</VideoInput>`;
- `<PrinterRedirection>Disable</PrinterRedirection>`;
- `<ClipboardRedirection>Disable</ClipboardRedirection>`; and
- `<ProtectedClient>Enable</ProtectedClient>`.

No folder sharing, clipboard, URI launch, browser, socket, connector, or proxy
fallback may be added by a task definition. A task requiring network access is
unsupported in V1.

The read-only input contains a version/hash-pinned Windows Python runtime and
worker already covered by the repository dependency policy. Candidate
repository code and package executables are never executed on the host.

## Sandbox worker and broker

The Sandbox worker starts from the authenticated read-only mapping, verifies the
task envelope, nonce, baseline manifest, staging root identity, and every
initial staged file before accepting a tool request. Any mismatch invalidates
the whole run.

The model has no direct filesystem, process, shell, environment, connector,
browser, desktop, clipboard, or host API. It can submit only typed broker
requests. V1 broker operations are:

- list a bounded set of relative paths;
- read one bounded regular file by exact relative path and expected baseline or
  current digest;
- create or replace one bounded regular file by exact relative path, expected
  prior digest/absence, and content digest;
- create one bounded directory by exact relative path;
- delete one task-created file or an explicitly approved baseline file by exact
  relative path and expected digest; and
- run one exact verification command profile after separate approval.

Every path is normalized as a relative Windows path, rejects empty/dot/dot-dot,
reserved names, trailing dots/spaces, drive/UNC/device prefixes, separators in
components, alternate streams, case collisions, and links. The worker opens
each ancestor from the validated root, rejects reparse points and unexpected
file identities immediately before and after access, and never accepts an
absolute path from the model.

Writes are same-directory temporary-file replacements with exclusive creation,
bounded bytes, flush, identity recheck, and atomic replace where available.
They cannot change ACLs, owner, attributes outside the allowed regular-file
mode, timestamps as authority, or execute a file merely because it was written.

Diagnostics contain operation IDs, relative-path hashes, byte counts, digests,
status, and content-free policy errors. File content, prompts, diffs, environment
values, secrets, and command output are stored only in their separately bounded
artifacts, never ordinary logs.

## Verification command policy

There is no arbitrary command string and no command shell. `cmd.exe`,
PowerShell, Windows Script Host, `bash`, `sh`, `eval`, command substitution,
redirection, pipes, shell metacharacters, response files, executable discovery
through `PATH`, and caller-supplied environment variables are unavailable.

A command request names one reviewed profile and exact bounded arguments. The
profile fixes:

- an authenticated absolute executable inside the Sandbox read-only runtime or
  staged reviewed toolchain;
- tokenized argument templates and allowed test/target selectors;
- the isolated repository root as working directory;
- a minimal environment allowlist;
- wall-clock, CPU, memory, process-count, stdout/stderr, and result-file limits;
- whether candidate repository code will execute; and
- expected exit-status and evidence parsers.

Initial profiles may cover dependency-free syntax/tests and already provisioned
locked tools only. For Python projects, execution uses the reviewed runtime or
`uv run --frozen --no-sync` with the exact locked Python. For JavaScript or
TypeScript projects, execution uses a reviewed pnpm version with
`--offline --frozen-lockfile` against dependencies already included in the
isolated snapshot. No npm, yarn, bun, pip, `uv sync`, `uv add`, `pnpm install`,
`pnpm add`, Cargo fetch/update, source build, registry access, package-cache
mount, or dependency mutation is available in V1.

Dependency installation is disabled, not merely approval-gated, in V1. A future
dependency-change design requires a separate capability, exact package/version
preview, public-age/provenance verification, lockfile diff, network boundary,
and security review. It cannot be introduced as another command profile.

Before a verification command, the UI shows the profile, executable identity,
complete tokenized arguments, working-directory label, whether candidate code
will execute, limits, and current staging digest. Approval is one use. Any
change creates a new action digest and requires new approval.

## Environment and process limits

The Sandbox worker constructs, rather than filters, its child environment. The
initial allowlist is limited to:

- `SystemRoot` and `WINDIR` fixed to the Sandbox Windows directory;
- `TEMP` and `TMP` fixed inside the writable task mapping;
- a fixed `PATH` containing only authenticated Sandbox/runtime directories;
- `PYTHONNOUSERSITE=1`, `PYTHONDONTWRITEBYTECODE=1`,
  `PYTHONHASHSEED=0`, `PIP_CONFIG_FILE=NUL`, and
  `PIP_DISABLE_PIP_VERSION_CHECK=1` for Python profiles;
- `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=NUL`,
  `GIT_NO_REPLACE_OBJECTS=1`, and `GIT_TERMINAL_PROMPT=0` where an
  authenticated Git read is required; and
- task/run nonce identifiers that contain no host path or credential.

`HOME`, `USERPROFILE`, provider API keys, connector tokens, cloud variables,
credential-helper variables, proxy variables, package-registry tokens, SSH/GPG
variables, editor variables, and inherited host environment values are not
forwarded.

Default maximums are one 15-minute Sandbox run, one active command at a time,
five minutes per command, eight owned processes, 2 GiB committed memory, 1 GiB
staged bytes, 10,000 staged files, 8 MiB combined command output, 16 MiB diff
artifact, and 256 KiB diagnostic metadata. Later code may choose stricter
limits but cannot exceed these without another threat-model review.

The worker places every child in one kill-on-close Job Object inside the
Sandbox. Cancellation closes the job, invalidates pending approvals and the
task nonce, terminates Windows Sandbox, rejects late output, and prevents any
subsequent command or adoption.

## Result verification and completion

The writable mapping is untrusted output. After the Sandbox shuts down, the host
verifier must inspect it without executing its contents and must reject:

- a missing or mismatched run/nonce/source identity;
- an extra, missing, oversized, non-regular, linked, reparse, hard-linked,
  alternate-stream, case-colliding, or out-of-root result;
- a changed policy, baseline manifest, worker identity, command profile, or
  approval digest;
- a changed file not declared by the final result manifest;
- a path that was denied during staging;
- incomplete cancellation/timeout evidence;
- verification output that is malformed, truncated, from another staging
  digest, or reports a non-success exit status; and
- result totals beyond task limits.

The host computes the exact diff from the authenticated baseline and final
regular-file manifests. Model prose is not diff evidence. The run may reach
`awaiting_review` only when path scope, source identity, result structure, and
requested verification evidence pass. Failed, timed-out, cancelled, or partial
verification never becomes `completed`.

WIN-CODE-001 grants no adoption authority. WIN-CODE-002 may produce only an
isolated verified result. WIN-CODE-003 must separately define exact diff review,
stale-original detection, Apply/Discard, transactional adoption, rollback, and
post-Apply repository verification. Until WIN-CODE-003 passes, no result can
modify the selected repository.

## Availability and release gates

Source implementation must remain behind the existing default-off
`workspace_coding` build availability, user permission, and per-run grants.
There is no automatic availability based on Windows Sandbox being installed.

Before any release can enable workspace coding, interactive Windows evidence
must prove:

- Windows Sandbox availability detection and no-fallback behavior;
- exact two-mapping configuration with networking and redirections disabled;
- absence of the original repository, host profile, host secrets, and host
  environment inside the Sandbox;
- path traversal, reparse, hardlink, alternate-stream, case-collision, stale
  digest, and quota failures before access or adoption;
- dirty/untracked baseline preservation and stale-original rejection;
- command-token, environment, dependency-install, timeout, process-tree, and
  cancellation enforcement;
- exact diff and verification evidence from the same staging digest;
- no workspace authority from response-provider, tutor, dictation, compose,
  pointing, skill, connector, or ordinary Task Agent permissions; and
- signed-release exact-byte validation after the feature is deliberately made
  build-available.

## Review checklist

The approved source contracts implement only the portions named above. They do
not enable the feature, provide host Apply authority, or prove live Windows
containment. Each later task must cite the exact sections it implements, retain
the default-off gate, add adversarial source/Windows tests, and pass the
dependency, locked-build, packaging, interactive Sandbox, and signed-release
gates applicable to its authority.
