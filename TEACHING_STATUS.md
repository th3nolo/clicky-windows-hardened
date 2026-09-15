# Experimental native notebook teaching

Clicky's selected model plans a lesson from an authorized notebook snapshot and
generates native pen geometry. InkNotes executes those actions with page identity,
revision checks, operation receipts, and editable ink. The optional local CLI
controls Clicky; it does not generate the drawings independently.

## Current evidence and limits

Isolated real-component tests with Muse Spark 1.3 created pages, drew row and
column vectors and labels, inspected crops, and corrected owned annotations.
Larger uppercase labels were clearer than small lettering. Some numerals and
dimensions remained malformed, and one run stalled in repeated crop inspections.
That run was cancelled, produced no TTS, and did not reach terminal independent
verification or verified saving. These observations do not establish a reliable
completed lesson, packaged startup, or physical microphone/hotkey behavior.

The planner freezes per-component requirements before mutation. Terminal
verification reads each component from the final page revision in a fresh reader
context. Writer history and expected answers are withheld from that reader; the
same configured model is still used, so it is not a different-model review.
Intermediate writer inspection is not equivalent to this independent reader.
Verified completion currently requires a verifiably blank initial target or a
validated new blank page. Annotations on a source-bearing page remain unverified because source ink can otherwise
be mistaken for the agent's output; they must not trigger a completion claim or
final teaching speech until attribution-aware verification is implemented.

The journal records progress and uncertain operation outcomes. The resume storage
module is a foundation; a complete user-facing resume/reconciliation flow is not
yet wired. Do not describe an idle, paused, or cancelled task as completed.

## Next correction-loop experiment

1. Read back each coherent batch independently before asking the writer for the
   next batch. Return a specific discrepancy, such as an unreadable numeral or a
   dimension mismatch, rather than a generic instruction to inspect again.
2. Detect repeated inspection of overlapping regions at the same page revision.
   Require a concrete correction, a materially different observation, or a useful
   pause; do not repeatedly send unchanged context without new evidence.
3. Verify a proposed replacement before removing the old annotation. Keep prior
   attempts and support an atomic, undoable replacement rather than deleting a
   component and potentially stopping before rebuilding it.
4. Compare bounded test cases across changes: readable labels, numeral order,
   dimension correctness, successful corrections, tool/model calls, elapsed time,
   and actual reported usage. Preserve screenshots of failures.
5. Experiment with additional reasoning effort only for failed glyphs or geometry
   groups. A higher output ceiling alone does not improve stroke construction.

These are proposed follow-up changes, not implemented guarantees. Acceptance
requires live native output and a reached, correct verification outcome, including
save/readback where the task requires persistence.
