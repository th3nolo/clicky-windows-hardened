# Permissioned Desktop Automation security boundary

Status: source-only policy contract; unavailable in release builds.

## Authority boundary

Pointing identifies a visual area for explanation. Desktop automation changes
external application state. They do not share permission, grants, target
objects, approval, or execution code.

The existing `desktop.uia.action` capability is the only V1 desktop action
authority. It remains build-unavailable, needs its independent persisted
permission, is granted to one task run, and always requires action approval.
Tutor, Dictation, Compose, screen capture, response providers, and pointing
cannot satisfy any of those requirements.

This phase adds no executor. A policy-eligible target is not an authorization
to act.

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

The only modeled actions are focus, invoke, select, toggle, expand, collapse,
scroll, and set a simple non-sensitive value. Each non-focus action requires
its matching UI Automation pattern.

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

## Remaining implementation gates

No release may expose the feature until later reviewed changes provide:

1. a Windows UIA inspector, visible non-interactive highlight, immediate
   revalidation, queue cancellation, and global stop;
2. a one-use task grant and exact step approval bound to the highlighted
   review digest;
3. allowlisted pattern executors with bounded time and no coordinate fallback;
4. post-action state verification and truthful failure/partial results;
5. Task Center evidence and adversarial Windows tests; and
6. interactive packaged Windows and signed-release exact-byte validation.
