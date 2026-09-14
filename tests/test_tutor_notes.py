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

    def test_explicit_teaching_annotation_intent(self):
        cases = {
            'Circle this term': True,
            'Could you draw an arrow to the denominator?': True,
            'Please annotate my equation': True,
            'Mark my mistake in blue': True,
            'Explain and draw a diagram': True,
            'Explain the matrix and write the calculation here': True,
            'Clicky, please underline this row': True,
            'Por favor, rodea este término': True,
            '¿Puedes dibujar una flecha a la columna?': True,
            'Marca mi error en azul': True,
            'Explica y escribe la solución en mi cuaderno': True,
            'Explica la matriz y dibuja un diagrama': True,
            'Explain the drawing in my notes': False,
            'Explain how to circle a term and draw an arrow': False,
            'Can you explain why teachers underline and write notes?': False,
            'Can you explain why we draw an arrow here?': False,
            'Why can you not write notes?': False,
            'What does "circle this term" mean?': False,
            'The teacher said draw an arrow to the answer': False,
            "Don't circle this term": False,
            'Please do not annotate my equation': False,
            'Could you not write notes?': False,
            'Explain without drawing a circle': False,
            'No dibujes una flecha': False,
            'Por favor nunca marques mi error': False,
            'Explica sin escribir notas': False,
            'Open a file and draw a diagram': False,
        }
        for prompt, expected in cases.items():
            with self.subTest(prompt=prompt):
                self.assertEqual(note_requested(prompt), expected)

    def test_multi_sentence_annotation_requests_and_constraints(self):
        cases = {
            'Explain this matrix multiplication fully. Use your blue pencil to bracket each row and write the corresponding calculation beside it. Complete both rows and the final result. Preserve my original writing.': True,
            'What went wrong here? Circle my mistake in blue.': True,
            'Explain this equation. Draw an arrow without covering my work.': True,
            'Write the explanation here. Do not erase my original strokes.': True,
            'Explica esta matriz. Usa tu l\u00e1piz azul para subrayar la fila.': True,
            '\u00bfQu\u00e9 hice mal? Marca mi error sin tapar mi trabajo.': True,
            'Explica esto. Dibuja una flecha. No borres mi trabajo.': True,
            'Explain this. Do not draw an arrow.': False,
            'Explain this without writing notes.': False,
            'Write notes here. Actually do not write anything.': False,
            'Explica esto. No dibujes una flecha.': False,
            'The teacher said: Explain this. Circle this term.': False,
            'What does "Explain this. Circle this term." mean?': False,
            'Explain the instruction \u201cUse your blue pencil to draw an arrow. Write notes here.\u201d': False,
            'Can you explain this drawing? Why did the teacher circle this term?': False,
            'Use your blue pencil to open a file': False,
        }
        for prompt, expected in cases.items():
            with self.subTest(prompt=prompt):
                self.assertEqual(note_requested(prompt), expected)

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
