# Local agent control

Enable `CLICKY_CONTROL_API=1` in the environment of the normal Clicky launch.
Optionally set `CLICKY_CONTROL_ENDPOINT_FILE`; otherwise discovery is at
`%LOCALAPPDATA%/Clicky/local-control.json`. Existing app consent and selected
provider remain authoritative. The interface is disabled by default.

From the Clicky checkout, using its existing Python environment:

```powershell
python -m automation.local_control --endpoint-file PATH submit --text-file QUESTION.txt --notebook-pid PID --request-id lesson-001
python -m automation.local_control --endpoint-file PATH status --task-id 1
python -m automation.local_control --endpoint-file PATH events --task-id 1 --cursor 0
python -m automation.local_control --endpoint-file PATH cancel --task-id 1
```

Use the task ID returned by submit, and the `next_cursor` returned by events.
Reuse the same request ID to retry an uncertain submission without replaying
it. Event pages and retained task history are bounded; retain the pages needed
for a longer experiment. A paused or idle task is not a completed lesson.

The CLI submits to the running application's normal manager. It does not
generate handwriting or mutate InkNotes itself. Clicky's selected model plans
the task and generates the pen curves, then Clicky executes the native tools.
Typed notebook tasks skip microphone capture, STT, and desktop screenshots;
they bind the explicitly selected InkNotes process and its page snapshot.

Observations include public response chunks, final responses, state, bounded
notebook events, and actual provider usage where supplied. Missing usage is
null. Private model reasoning is not exposed. Event coverage depends on what
the planner emits; a missing event is not proof an action executed. Final
success requires independent notebook verification, not merely writer prose.

The server binds only to `127.0.0.1` on an ephemeral port and requires the
random bearer token in the local discovery file. The CLI reads that file;
do not share or log its contents. Browser origins and incorrect Host headers
are rejected. There is no shell, arbitrary-code, or raw-mutation endpoint.
Another instance cannot replace a live discovery-file owner.
