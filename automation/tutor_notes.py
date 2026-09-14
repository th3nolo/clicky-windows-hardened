"""Place a requested tutor answer into a captured, empty native text editor.

No notebook API or file writes: the existing desktop insertion broker types
into the same ordinary editor the learner selected before recording.
"""
from __future__ import annotations

import re
import uuid

from dictation.insertion import ExplicitInsertionRequest, InsertionStatus

NOTE_RESPONSE_CONTRACT = (
    "\nNOTE REQUEST: Give the complete, self-contained explanation as plain text "
    "suitable for a notebook. Include every calculation and final result. "
    "Do not emit pointer tags or instructions to say next. Do not claim "
    "to have written or saved anything: Clicky will separately report insertion. "
    "This turn can type into an empty native text editor selected before recording; "
    "it cannot create or position that editor itself. This capability description "
    "replaces the earlier statement that no notebook editing is available.\n"
)


def note_requested(text: str) -> bool:
    """Recognize explicit notebook writing/annotation requests, not discussion."""
    text = text.casefold().replace("’", "'").strip(" ¿¡")
    # Ignore quoted instructions and reported speech, including sentence breaks
    # inside a quotation. Those words describe someone else's request.
    text = re.sub(r'"[^"\n]*"|\u201c[^\u201d]*\u201d|\u00ab[^\u00bb]*\u00bb', '', text)
    if re.search(r"\b(?:said|says|wrote|told me|dijo|dice|escribi\u00f3)\b", text):
        return False
    actions = (
        r"(?:writ\w*|handwrit\w*|add|leave|put|insert|circl\w*|underlin\w*|"
        r"bracket\w*|annotat\w*|mark\w*|draw\w*|escrib\w*|anot\w*|"
        r"dibuj\w*|marc\w*|rode\w*|encerr\w*|subray\w*|a\u00f1ad\w*|agreg\w*)"
    )
    # Reject negated drawing/writing, while permitting constraints such as
    # "without covering my work" or "do not erase my original strokes".
    if re.search(
        r"\b(?:don't|do not|never|not|no|nunca|jam\u00e1s|sin|without|avoid)"
        r"\s+(?:(?:ever|please|actually|ever again|por favor)\s+)?" + actions + r"\b", text
    ):
        return False
    prefix = (
        r"(?:(?:clicky[, ]+)?(?:please\s+|por favor[, ]+)?)"
        r"(?:(?:can|could|would|will) you\s+|(?:puedes|podrías|podrias)\s+)?"
        r"(?:please\s+|por favor[, ]+)?"
    )
    writing = (
        r"(?:write|handwrite|add|leave|put|insert|escribe|escriba|escribir|anota|anotar|añade|agrega)\b"
        r"[^.!?;]{0,100}\b(?:note|notes|explanation|answer|solution|steps|calculation|"
        r"down|here|inknotes|notebook|equation|nota|notas|explicación|respuesta|"
        r"solución|pasos|cálculo|ecuación|aquí|cuaderno)\b"
    )
    annotation = (
        r"(?:circle|underline|bracket|annotate|mark|draw|rodea|encierra|subraya|"
        r"anota|marca|marcar|dibuja|dibujar|rodear|encerrar|subrayar)\b[^.!?;]{0,100}\b"
        r"(?:term|terms|equation|mistake|error|row|column|matrix|vector|fraction|"
        r"numerator|denominator|symbol|arrow|circle|bracket|diagram|graph|this|that|"
        r"término|términos|ecuación|fila|columna|matriz|fracción|numerador|"
        r"denominador|símbolo|flecha|círculo|corchete|diagrama|gráfica|esto|eso)\b"
    )
    for sentence in re.split(r"[.!?;\n]+", text):
        command = re.sub(r"^" + prefix, "", sentence.strip(" \u00bf\u00a1"), count=1)
        if re.match(r"(?:explain|explica|expl\u00edcame|explicame)\s+(?:how|why|what|c\u00f3mo|como|por qu\u00e9|por que)\b", command):
            continue
        command = re.sub(
            r"^(?:explain|explica|expl\u00edcame|explicame)\b[^.!?;]{0,100}?\b(?:and|y)\s+",
            "", command, count=1,
        )
        # A pen/color selection is an instrument for the following explicit
        # annotation, not a general permission to execute arbitrary commands.
        command = re.sub(
            r"^(?:use (?:your|the|a) (?:blue |green |red |colored )?(?:pencil|pen) to|"
            r"(?:usa|utiliza) (?:tu|el|un) (?:l\u00e1piz|lapiz|bol\u00edgrafo)(?: azul| verde| rojo)? para)\s+",
            "", command, count=1,
        )
        if re.match(r"(?:" + writing + "|" + annotation + ")", command):
            return True
    return False


def read_editor(target):
    """Read only the captured editor after its focused identity is checked."""
    import uiautomation as auto
    from dictation.windows_insertion import _focused_control
    with auto.UIAutomationInitializerInThread():
        control = _focused_control(auto, target)
        pattern = control.GetValuePattern()
        if pattern is None or pattern.IsReadOnly:
            raise RuntimeError("The selected editor cannot be verified")
        return pattern.Value


class TutorNotes:
    def __init__(self, targets, insertion, reader=read_editor):
        self.targets = targets
        self.insertion = insertion
        self.reader = reader
        self.pending = {}
        self.prefix = uuid.uuid4().hex

    def capture(self, sequence):
        decision = self.targets.capture()
        if decision.allowed and decision.lease is not None:
            # This first release is scoped to the notebook requested by the
            # user, not every editor that happens to be focused during speech.
            if decision.lease.application_name.casefold() != "inknotes.exe":
                return
            try:
                # Capture only a fresh note, never an existing selected answer.
                if self.reader(decision.lease) == "":
                    self.pending[sequence] = decision.lease
            except Exception:
                pass

    def discard(self, sequence):
        self.pending.pop(sequence, None)

    def ready(self, sequence):
        return sequence in self.pending

    def write(self, sequence, text):
        target = self.pending.pop(sequence, None)
        if target is None:
            return "Choose the Text tool in InkNotes, click an empty place on the page, then hold Ctrl+Win and ask me to write the explanation there."
        try:
            if len(text) > 8000:
                return "This explanation is too long for one note insertion. The complete answer remains here in Clicky."
            if not self.targets.revalidate(target).allowed or self.reader(target) != "":
                return "The note destination changed. Your explanation is still here; nothing was typed."
            result = self.insertion.insert_explicit(ExplicitInsertionRequest(
                run_id=f"tutor-note-{self.prefix}-{sequence}", target=target, text=text,
            ))
            if result.preview is not None:
                self.insertion.discard_preview(result.preview)
            if result.status is InsertionStatus.VERIFIED_INSERTED:
                return "The explanation was inserted in the selected note."
            if result.status is InsertionStatus.ATTEMPTED_UNVERIFIED:
                return "The explanation was typed into the selected note. Check the page before asking me to write it again; saving has not been verified."
            return "I could not insert the note. The explanation remains here in Clicky."
        except Exception:
            return "I could not verify the note insertion. Check the page before retrying; the explanation remains here."
