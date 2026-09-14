import ctypes
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from automation.tutor_notes import TutorNotes, note_requested
from dictation.insertion import InsertionStatus
from dictation.policy import TargetLease
from tests.test_dictation_insertion import descriptor


class TutorNoteTests(unittest.TestCase):
    def setUp(self):
        self.target = TargetLease(descriptor(application_name='InkNotes.exe'))
        self.targets = Mock()
        self.targets.capture.return_value = SimpleNamespace(allowed=True, lease=self.target)
        self.targets.revalidate.return_value = SimpleNamespace(allowed=True, lease=self.target)
        self.broker = Mock()
        self.broker.insert_explicit.return_value = SimpleNamespace(
            status=InsertionStatus.ATTEMPTED_UNVERIFIED, preview=None,
        )
        self.reader = Mock(return_value='')
        self.notes = TutorNotes(self.targets, self.broker, self.reader)

    def test_question_never_authorizes_writing(self):
        self.assertFalse(note_requested('Explain the matrix on my notes'))
        self.assertFalse(note_requested("Don't write notes, just explain"))
        self.assertFalse(note_requested('Why can you not write notes?'))
        self.assertTrue(note_requested('Write the complete explanation here'))
        self.assertTrue(note_requested('Anota la respuesta en mi cuaderno'))

    def test_existing_content_is_not_a_new_note(self):
        self.reader.return_value = 'My original work'
        self.notes.capture(1)
        self.notes.write(1, 'Answer')
        self.broker.insert_explicit.assert_not_called()

    def test_focus_change_blocks_insertion(self):
        self.notes.capture(1)
        self.targets.revalidate.return_value = SimpleNamespace(allowed=False)
        self.notes.write(1, 'Answer')
        self.broker.insert_explicit.assert_not_called()

    def test_new_content_blocks_insertion(self):
        self.notes.capture(1)
        self.reader.return_value = 'Something the learner typed while waiting'
        self.notes.write(1, 'Answer')
        self.broker.insert_explicit.assert_not_called()

    def test_cancel_discards_destination(self):
        self.notes.capture(1)
        self.notes.discard(1)
        self.notes.write(1, 'Answer')
        self.broker.insert_explicit.assert_not_called()

    def test_answer_is_inserted_once_without_claiming_save(self):
        self.notes.capture(1)
        status = self.notes.write(1, '1×1 + 2×2 + 3×6 = 23')
        self.notes.write(1, 'duplicate')
        self.broker.insert_explicit.assert_called_once()
        self.assertEqual(self.broker.insert_explicit.call_args.args[0].text, '1×1 + 2×2 + 3×6 = 23')
        self.assertIn('saving has not been verified', status)

    @unittest.skipUnless(os.name == 'nt', 'Windows ABI')
    def test_native_input_uses_full_windows_union(self):
        from dictation.windows_insertion import _Input
        self.assertEqual(ctypes.sizeof(_Input), 40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 28)
