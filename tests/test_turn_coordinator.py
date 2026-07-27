import threading
import unittest

from turn_coordinator import TurnCoordinator, TurnPhase


class _Task:
    def __init__(self, events, name):
        self.events = events
        self.name = name
        self.cancel_count = 0

    def cancel(self):
        self.cancel_count += 1
        self.events.append(self.name)


class TurnCoordinatorTests(unittest.TestCase):
    def test_barge_in_invalidates_then_cancels_before_new_capture_is_visible(self):
        turns = TurnCoordinator()
        first = turns.start_processing()
        self.assertIsNotNone(first)
        observed = []

        def cancel_generation():
            observed.append(("generation", turns.active, turns.phase))

        turns.bind_cancel(first, "generation", cancel_generation)
        replacement = turns.start_capture()

        self.assertIsNotNone(replacement)
        self.assertNotEqual(first, replacement)
        self.assertEqual(
            observed,
            [("generation", None, TurnPhase.IDLE)],
        )
        self.assertEqual(turns.active, replacement)
        self.assertEqual(turns.phase, TurnPhase.CAPTURING)

    def test_repeated_press_during_capture_starts_exactly_one_capture(self):
        turns = TurnCoordinator()
        first = turns.start_capture()
        self.assertIsNotNone(first)
        self.assertIsNone(turns.start_capture())
        self.assertEqual(turns.active, first)

    def test_stale_release_and_completion_cannot_touch_replacement(self):
        turns = TurnCoordinator()
        first = turns.start_capture()
        self.assertTrue(turns.release_capture(first))
        replacement = turns.start_capture()

        self.assertFalse(turns.release_capture(first))
        self.assertFalse(turns.complete(first))
        self.assertEqual(turns.active, replacement)
        self.assertEqual(turns.phase, TurnPhase.CAPTURING)

    def test_exact_cancel_cannot_cancel_a_replacement(self):
        turns = TurnCoordinator()
        first = turns.start_processing()
        replacement = turns.start_capture()

        self.assertFalse(turns.cancel(first))
        self.assertEqual(turns.active, replacement)
        self.assertTrue(turns.cancel(replacement))
        self.assertIsNone(turns.active)
        self.assertEqual(turns.phase, TurnPhase.IDLE)

    def test_bound_generation_playback_recording_and_stream_are_all_cancelled(self):
        turns = TurnCoordinator()
        session = turns.start_processing()
        events = []
        resources = {
            name: _Task(events, name)
            for name in ("generation", "playback", "recording", "streaming-stt")
        }
        for name, resource in resources.items():
            self.assertTrue(turns.bind_task(session, resource, name=name))

        turns.cancel_active()

        self.assertEqual(
            events,
            ["generation", "playback", "recording", "streaming-stt"],
        )
        self.assertTrue(all(resource.cancel_count == 1 for resource in resources.values()))
        self.assertEqual(turns.phase, TurnPhase.IDLE)

    def test_late_task_and_ui_callbacks_are_rejected_after_barge_in(self):
        turns = TurnCoordinator()
        first = turns.start_processing()
        events = []
        old_task = _Task(events, "old-task")
        turns.bind_task(first, old_task)
        replacement = turns.start_capture()

        ran, _ = turns.run_if_current(first, events.append, "stale-ui")
        self.assertFalse(ran)
        self.assertEqual(events, ["old-task"])

        ran, _ = turns.run_if_current(replacement, events.append, "current-ui")
        self.assertTrue(ran)
        self.assertEqual(events, ["old-task", "current-ui"])

    def test_stale_resource_binding_is_cancelled_immediately(self):
        turns = TurnCoordinator()
        first = turns.start_processing()
        turns.start_capture()
        events = []
        task = _Task(events, "late-stt")

        self.assertFalse(turns.bind_task(first, task, name="streaming-stt"))
        self.assertEqual(events, ["late-stt"])

    def test_concurrent_completion_cannot_emit_idle_after_new_capture(self):
        turns = TurnCoordinator()
        first = turns.start_processing()
        completed = threading.Event()
        allow_finish = threading.Event()
        states = []

        def finish():
            turns.complete(
                first,
                lambda: (states.append("idle"), completed.set(), allow_finish.wait(1)),
            )

        thread = threading.Thread(target=finish)
        thread.start()
        self.assertTrue(completed.wait(1))

        # start_capture blocks behind the completion callback, so IDLE is
        # published before the replacement capture can become visible.
        started = []

        def start():
            started.append(turns.start_capture())

        starter = threading.Thread(target=start)
        starter.start()
        self.assertEqual(started, [])
        allow_finish.set()
        thread.join(1)
        starter.join(1)

        self.assertEqual(states, ["idle"])
        self.assertEqual(turns.active, started[0])
        self.assertEqual(turns.phase, TurnPhase.CAPTURING)


if __name__ == "__main__":
    unittest.main()
