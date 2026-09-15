import ctypes
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from automation.tutor_notes import TutorNotes, drawn_letter_requested, note_requested, pen_trace_requested
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

    def test_direct_review_with_coordinated_annotation(self):
        cases = {
            'Review my handwritten transpose notes. Check whether my row and column labels agree with the matrices, and add a few concise blue teacher annotations beside the relevant work. Inspect unclear handwriting closely and ask me before relying on an ambiguous reading. Preserve all my original writing.': True,
            'Check the multiplication of the row at the top right by the matrix at the top left. Compare it with my working lower on the page and annotate the specific steps that need explanation in blue. If you cannot distinguish a digit or which expression belongs to the calculation, inspect it closely and ask me rather than guessing. Keep all my writing.': True,
            'Could you review my derivation and add blue annotations beside it?': True,
            'Check my working and annotate the steps': True,
            'I am taking notes while learning matrices. Can you explain what my two sketches show and whether the words I wrote match them? Add concise blue teacher notes beside my sketches so I can understand the difference between rows and columns. Use my own drawing in the explanation, preserve my handwriting, and finish with one short question to check my understanding. If my intent is ambiguous, explain the possible meanings instead of assuming I made a mistake.': True,
            'The teacher said my labels were unclear. Add blue notes beside my sketch.': True,
            'I wrote draw a diagram': False,
            'Check whether my labels are correct': False,
            'Check whether I can circle the terms and add annotations.': False,
            'Check if I need to write notes and annotate the calculation.': False,
            'Review whether we are allowed to circle terms and add annotations.': False,
            'Check whether my labels match and add annotations.': True,
            'Review how teachers check work and add annotations': False,
            'Check whether I should review my notes and add annotations': False,
            'Compare this with the instruction and add annotations': False,
            'Check my work and do not add annotations': False,
            'Review my work without writing annotations': False,
            'Explain "Check my labels and add annotations"': False,
            'My teacher said check my labels and add annotations': False,
        }
        for prompt, expected in cases.items():
            with self.subTest(prompt=prompt):
                self.assertEqual(note_requested(prompt), expected)

    def test_explicit_pen_requests_and_discussion(self):
        for text in ['Draw pen strokes to explain this equation', 'Add blue pen traces beside this term',
                     'Trace this row', 'Sketch a diagram', 'Use your blue pencil to circle this term']:
            with self.subTest(text=text):
                self.assertTrue(note_requested(text))
                self.assertTrue(pen_trace_requested(text))
        for text in ['Write complete notes here', 'Explain how to draw pen strokes',
                     'Do not trace this row', 'What does "draw pen strokes" mean?']:
            with self.subTest(text=text):
                self.assertFalse(pen_trace_requested(text))

    def test_pen_method_and_shared_accepted_clauses(self):
        accepted = ['Explain these two sketches using real colored pencil traces on the notebook page. Use a circle or bracket around each whole vector and arrows that show its direction. Keep labels short; do not replace the drawing with another paragraph. Preserve my handwriting and the existing blue notes. Use another readable color. Do not depend on an exact symbol count or correct unclear headings. Explain the directions and how the whole vector relates to the rows or columns inside it.', 'Explain this with pen traces', 'Use a circle around the vector',
                    'Dibuja un c\u00edrculo alrededor de este t\u00e9rmino', 'Subraya esta ecuaci\u00f3n']
        for text in accepted:
            with self.subTest(text=text):
                self.assertTrue(note_requested(text))
                self.assertTrue(pen_trace_requested(text))
        rejected = ['Explain how to use a circle around the vector', 'Do not draw pen traces',
                    'Write notes here. Explain how to circle a term and draw an arrow.']
        for text in rejected:
            with self.subTest(text=text):
                self.assertFalse(pen_trace_requested(text))

    def test_generic_annotations_do_not_require_pen_shapes(self):
        for text in ['Anota esta ecuaci\u00f3n', 'Annotate this equation with a written explanation',
                     'Mark this error with a written explanation']:
            with self.subTest(text=text):
                self.assertTrue(note_requested(text))
                self.assertFalse(pen_trace_requested(text))
        self.assertTrue(pen_trace_requested('Annotate this equation with an arrow'))
        for text in ['Write notes about circles', 'Write notes about arrows', 'Add notes about arrows',
                     'Write a circle explanation here']:
            with self.subTest(text=text):
                self.assertTrue(note_requested(text))
                self.assertFalse(pen_trace_requested(text))
        for text in ['Add arrows beside this equation', 'Put circles around this term', 'Draw an arrow']:
            with self.subTest(text=text):
                self.assertTrue(pen_trace_requested(text))

    def test_drawn_letter_intent_uses_direct_english_and_spanish_commands(self):
        exact_question = (
            'Under the existing red row vector label, draw the same words in green using actual '
            'freehand pencil strokes. Form the letters themselves from pen paths, with pen lifts '
            'between separate strokes; do not trace font outlines or use the normal handwriting '
            'text tool. Keep the original red label so I can compare them. Make the green words '
            'readable and naturally handwritten, with clear spacing, and preserve all existing '
            'notebook content. Inspect the result and save.'
        )
        accepted = ['Draw the letter A', 'Hand-letter the word AI', 'Escribe la letra A', exact_question]
        rejected = [
            'What does \"draw the letter A\" mean?',
            'The teacher said draw the letter A',
            'Do not draw the letter A',
            'Explain how to draw the letter A',
            'Draw a circle around the letter A',
        ]
        for text in accepted:
            with self.subTest(text=text):
                self.assertTrue(note_requested(text))
                self.assertTrue(drawn_letter_requested(text))
        for text in rejected:
            with self.subTest(text=text):
                self.assertFalse(drawn_letter_requested(text))

    def test_handwritten_copy_requests_require_explicit_pen_work(self):
        accepted = [
            'Study my original black handwritten headings Rows and Columns on this notebook page. '
            'Draw cleaner versions of those same two words in the blank lower area as actual pen traces.',
            'Draw the letters in my original black handwritten headings "Rows" and "Columns" as actual pen traces.',
            'Trace my handwritten word Rows with cleaner pen strokes.',
            'Draw the same two handwritten words as pen traces.',
            'Trace those same handwritten letters.',
            'Draw a handwritten copy of Rows.',
            'Copy these handwritten letters as separate pen strokes.',
            'Traza las palabras manuscritas con trazos de pluma.',
        ]
        for text in accepted:
            with self.subTest(text=text):
                self.assertTrue(note_requested(text))
                self.assertTrue(pen_trace_requested(text))
                self.assertTrue(drawn_letter_requested(text))

        rejected = [
            'What does "draw cleaner versions of those same two words" mean?',
            'The teacher said: Draw cleaner versions of those same two words.',
            'Do not draw cleaner versions of those same two words.',
            'Explain how to draw cleaner versions of those same two words.',
            'Draw a circle around my handwritten word.',
            'Study whether I should copy my handwritten words.',
        ]
        for text in rejected:
            with self.subTest(text=text):
                self.assertFalse(drawn_letter_requested(text))

    def test_normal_note_request_does_not_require_drawn_letter_receipt(self):
        self.assertTrue(note_requested('Write the complete explanation here'))
        self.assertFalse(drawn_letter_requested('Write the complete explanation here'))

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
