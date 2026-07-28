# Permissioned Desktop Automation security boundary

Status: source-only policy, review, and one-shot executor; unavailable in
release builds.

## Authority boundary

Pointing identifies a visual area for explanation. Desktop automation changes
external application state. They do not share permission, grants, target
objects, approval, or execution code.

The existing `desktop.uia.action` capability is the only V1 desktop action
authority. It remains build-unavailable, needs its independent persisted
permission, is granted to one task run, and always requires action approval.
Tutor, Dictation, Compose, screen capture, response providers, and pointing
cannot satisfy any of those requirements.

The source adds a read-only focused-control inspector, review highlighter,
global stop ownership, and a one-shot semantic UIA executor. A policy-eligible
or visibly reviewed target is not an authorization to act. The executor is
reachable only through the trusted broker after the Task Agent consumes one
exact action approval.

## Exact target identity

A trusted Windows inspector must construct `DesktopTarget` without reading the
control's current `ValuePattern` value. The immutable identity binds:

- target process ID and process start time;
- application identity digest;
- top-level and foreground window handles;
- UI Automation runtime ID, control type, framework, and automation ID;
- bounding rectangle and supported semantic UIA patterns;
- enabled, visible, control-element, password, and protected state;
- Clicky and target integrity levels; and
- the input desktop name.

The identity digest excludes labels and mutable screen position. The review
digest additionally binds the name shown to the user, bounds, foreground
window, supported patterns, visibility, and desktop. A later executor must
reinspect and revalidate both immediately before every action.

PID alone, window title alone, label alone, coordinates, screenshots, OCR,
model output, and the current foreground location are not target identity.

## V1 semantic actions

The only modeled and executable actions are focus, invoke, select, toggle,
expand, collapse, scroll, and set a bounded printable single-line value. Each
non-focus action requires its matching UI Automation pattern. Invoke requires
one declared observable postcondition; toggle requires the desired state;
scroll requires exact amounts for both axes; and set-value approval displays
the exact value while receipts retain only its SHA-256 evidence. Set-value
text passes the same transient credential, two-factor, payment, security,
account-change, administrator, and destructive-content classifier as target
labels; a match fails closed without retaining the value in diagnostics.

Raw mouse clicks, pointer coordinates, keyboard input, paste, shell commands,
browser scripting, arbitrary accessibility methods, and fallback to a similar
control are outside V1.

## Denied surfaces

Policy blocks rather than asks for approval when any signal identifies:

- credentials, passwords, passphrases, PINs, or recovery/private keys;
- two-factor, one-time, authenticator, or verification codes;
- payments, purchases, checkout, transfers, or orders;
- security settings, security tools, firewall, encryption, or policy editors;
- administrator prompts or administrator-integrity targets;
- account creation, removal, credential change, or closure;
- permanent deletion, erase/reset, disk formatting, or trash emptying; or
- a non-default/secure desktop.

It also blocks Clicky's own process, background windows, disabled, offscreen,
non-control, password, protected, cross-integrity, unknown-integrity, and
unsupported-pattern targets. Bounded UIA labels are classified transiently
into category-only diagnostics; their source text is not retained by policy.
Invalid or oversized classification input fails closed.

Approval cannot override these denials.

## Approval, worker, and result boundary

One request binds the run, call, visible review, target identity, target
presentation, semantic action, and all action-specific arguments. The Task
Agent must enter and leave `waiting_for_approval`; the broker consumes that
one-use approval before launching any worker. It immediately revalidates the
same focused target and active highlight and refuses a stale, hidden, changed,
expired, stopped, or already-consumed action.

The worker processes exactly one bounded JSON frame over private pipes. The
host launches the exact Clicky executable or reviewed Python entry point
suspended, assigns it to a kill-on-close Windows Job Object, then resumes it.
The source-test path resolves the virtual environment's exact base interpreter
and starts it with Python isolated mode, explicitly adding only the reviewed
application root and locked environment site-packages path. This avoids a
virtual-environment redirector child bypassing the one-process job limit.
The job is limited to one process, 256 MiB, and five seconds of host wall wait
and job CPU time. Its minimal environment contains Windows and temporary
directory paths plus a worker sentinel; ambient credentials, provider keys,
proxy settings, `PATH`, and `PYTHONPATH` are omitted. Windows Job UI
restrictions are intentionally not applied because they would prevent UI
Automation. This boundary limits trusted Clicky worker lifetime and resources;
it is not a sandbox for untrusted code and does not claim network isolation.

The global Escape stop invalidates the run before terminating the bound job.
There is no action retry. A nonce-bound HMAC authenticates the single worker
receipt to its pipe exchange. Success requires action-specific observed
post-state. A failed observation is `failed_verification`; an exception or
transport/authentication failure after request delivery is `outcome_unknown`;
and only a proven pre-delivery failure is safe to classify as pre-action or
cancelled. Callers must never retry an unknown outcome automatically.

## Remaining implementation gates

No release may expose the feature until later reviewed changes provide:

1. Task Center action review, receipt display, and adversarial integration;
2. disposable native Windows proof for target inspection, highlight,
   mixed-DPI routing, every UIA pattern and postcondition, stop races, timeout,
   process-tree termination, and unknown-outcome handling; and
3. interactive packaged Windows and signed-release exact-byte validation.
