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


_DRAWN_LETTER = re.compile(
    r"^(?:(?:draw|sketch|trace|dibuja|dibujar|traza|trazar)\b"
    r"\s+(?:(?:the|a|an|this|that|these|those|my|your|la|el|los|las|una?|este|esta|mi|tu)\s+)?"
    r"(?:(?:hand[- ]?written|handwrit\w*|hand[- ]?lettered)\s+)?"
    r"(?:letter|letters|word|words|letra|letras|palabra|palabras)\b"
    r"(?!\s+(?:to|for|about|from|para|por|sobre)\b)|"
    r"(?:draw|sketch|trace|dibuja|dibujar|traza|trazar)\b\s+"
    r"(?:(?:the|a|an|this|that|these|those|my|your|la|el|los|las|una?|este|esta|mi|tu)\s+)?"
    r"(?:(?:hand[- ]?written|handwrit\w*|hand[- ]?lettered)\s+)?"
    r"(?:(?:clean(?:er)?|clear(?:er)?|neat(?:er)?|better|more\s+readable|more\s+legible)\s+)?"
    r"(?:version|versions|copy|copies)\b[^.!?;]{0,100}\b"
    r"(?:letter|letters|word|words|letra|letras|palabra|palabras)\b|"
    r"(?:draw|sketch|trace|dibuja|dibujar|traza|trazar)\b\s+"
    r"(?:(?:the|a|an|this|that|these|those|my|your|la|el|los|las|una?|este|esta|mi|tu)\s+)?"
    r"(?:(?:clean(?:er)?|clear(?:er)?|neat(?:er)?|better|more\s+readable|more\s+legible)\s+)?"
    r"(?:hand[- ]?written|handwrit\w*|hand[- ]?lettered)\s+"
    r"(?:version|versions|copy|copies)\b|"
    r"(?:draw|sketch|trace|dibuja|dibujar|traza|trazar)\b\s+"
    r"(?:(?:the|a|an|this|that|these|those|my|your|la|el|los|las|una?|este|esta|mi|tu)\s+)?"
    r"(?:same|these|those)\s+(?:(?:one|two|three|both|each|same)\s+)?"
    r"(?:(?:hand[- ]?written|handwrit\w*|hand[- ]?lettered)\s+)?"
    r"(?:word|words|letter|letters|palabra|palabras|letra|letras)\b|"
    r"(?:copy|copied|copies|copying|copia\w*|copiar\w*)\b\s+"
    r"(?:(?:the|a|an|this|that|these|those|my|your|la|el|los|las|una?|este|esta|mi|tu)\s+)?"
    r"(?:(?:hand[- ]?written|handwrit\w*|hand[- ]?lettered)\s+)?"
    r"(?:letter|letters|word|words|letra|letras|palabra|palabras)\b|"
    r"(?:hand[- ]?letter|handwrit\w*|write|escrib\w*)\b\s+"
    r"(?:(?:the|a|an|this|that|these|those|my|your|la|el|los|las|una?|este|esta|mi|tu)\s+)?"
    r"(?:(?:hand[- ]?written|handwrit\w*|hand[- ]?lettered)\s+)?"
    r"(?:letter|letters|word|words|letra|letras|palabra|palabras)\b"
    r"(?!\s+(?:to|for|about|from|para|por|sobre)\b)|"
    r"hand[- ]?letter\b\s+(?:(?:the|a|an|this|that|these|those|my|your|la|el|los|las|una?|este|esta|mi|tu)\s+)?"
    r"(?:word|words|palabra|palabras)\b)",
    re.IGNORECASE,
)

_DRAWING_METHOD = re.compile(
    r"^(?:explain\b[^.!?;]{0,100}\b(?:using|with)\s+"
    r"(?:(?:real|colored|blue|green|red)\s+)*(?:pen|pencil)\s+(?:traces|strokes)\b|"
    r"use\s+(?:a |an |the )?(?:circle|bracket|arrow|circles|brackets|arrows)\b"
    r"[^.!?;]{0,100}\b(?:around|beside|under|over|to|on)\b)"
)


def _is_drawn_letter_command(command: str) -> bool:
    """Return true only for a direct glyph/hand-letter imperative clause."""
    return bool(_DRAWN_LETTER.match(command.strip()))


def _iter_accepted_commands(text: str):
    """Yield direct notebook commands after the shared intent filtering."""
    text = text.casefold().replace("’", "'").strip(" ¿¡")
    # Ignore quoted instructions and reported speech, including sentence breaks
    # inside a quotation. Those words describe someone else's request.
    text = re.sub(r'"[^"\n]*"|\u201c[^\u201d]*\u201d|\u00ab[^\u00bb]*\u00bb', '', text)
    actions = (
        r"(?:writ\w*|handwrit\w*|hand[- ]?letter\w*|copy|cop\w*|add|leave|put|insert|circl\w*|underlin\w*|"
        r"trac\w*|sketch\w*|bracket\w*|annotat\w*|mark\w*|draw\w*|escrib\w*|anot\w*|"
        r"dibuj\w*|marc\w*|rode\w*|encerr\w*|subray\w*|a\u00f1ad\w*|agreg\w*)"
    )
    # Reject negated drawing/writing, while permitting constraints such as
    # "without covering my work" or "do not erase my original strokes".
    # A request to avoid font outlines is an implementation constraint on an
    # already explicit glyph command, rather than a request to avoid drawing.
    negation_text = re.sub(
        r"\b(?:don't|do not|never|no|nunca|jam\u00e1s|sin|avoid)"
        r"\s+(?:(?:ever|please|actually|ever again|por favor)\s+)?"
        r"(?:trace|trac\w*|draw|dibuj\w*|dibuja\w*|"
        r"hand[- ]?letter|handwrit\w*|escrib\w*)\s+"
        r"(?:(?:the|a|an|la|el|los|las|una?)\s+)?"
        r"(?:font|fonts|typeface|typefaces|fuente|fuentes)\s+"
        r"(?:outline|outlines|contour|contours|contorno|contornos)\b",
        " ",
        text,
    )
    if re.search(
        r"\b(?:don't|do not|never|not|no|nunca|jam\u00e1s|sin|without|avoid)"
        r"\s+(?:(?:ever|please|actually|ever again|por favor)\s+)?" + actions + r"\b", negation_text
    ):
        return
    prefix = (
        r"(?:(?:clicky[, ]+)?(?:please\s+|por favor[, ]+)?)"
        r"(?:(?:can|could|would|will) you\s+|(?:puedes|podrías|podrias)\s+)?"
        r"(?:please\s+|por favor[, ]+)?"
    )
    writing = (
        r"(?:write|handwrite|add|leave|put|insert|escribe|escriba|escribir|anota|anotar|añade|agrega)\b"
        r"[^.!?;]{0,100}\b(?:pen traces|pen strokes|circles|arrows|note|notes|annotation|annotations|explanation|answer|solution|steps|calculation|"
        r"down|here|inknotes|notebook|equation|nota|notas|explicación|respuesta|"
        r"solución|pasos|cálculo|ecuación|aquí|cuaderno)\b"
    )
    annotation = (
        r"(?:trace|sketch|circle|underline|bracket|annotate|mark|draw|rodea|encierra|subraya|"
        r"anota|marca|marcar|dibuja|dibujar|traza|trazar|rodear|encerrar|subrayar)\b[^.!?;]{0,100}\b"
        r"(?:trace|traces|stroke|strokes|path|paths|arrows|circles|shape|shapes|term|terms|equation|mistake|error|row|column|matrix|vector|fraction|"
        r"numerator|denominator|symbol|arrow|circle|bracket|diagram|graph|steps|work|calculation|letter|letters|word|"
        r"this|that|trace|traces|stroke|strokes|"
        r"término|términos|ecuación|fila|columna|matriz|fracción|numerador|"
        r"denominador|símbolo|flecha|círculo|corchete|diagrama|gráfica|letra|letras|palabra|esto|eso)\b"
    )
    reported_continuation = False
    for sentence in re.split(r"[.!?;\n]+", text):
        reported = re.search(r"\b(?:said|says|told me|dijo|dice|escribi[oó])\b", sentence)
        written_command = re.search(
            r"\b(?:i|he|she|they|teacher|student|yo|él|ella|maestro|maestra|profesor|profesora)\s+"
            r"(?:wrote|escribi[oó])\s*:?\s*(?:" + actions + r"|explain|explica)\b",
            sentence,
        )
        if reported or written_command:
            # A colon introduces unquoted multi-sentence reported instructions.
            reported_continuation = ':' in sentence
            continue
        if reported_continuation:
            continue
        command = re.sub(r"^" + prefix, "", sentence.strip(" \u00bf\u00a1"), count=1)
        # A short leading page-location phrase still addresses Clicky
        # directly; keep it out of the action grammar.
        command = re.sub(
            r"^(?:(?:under|above|below|beside|next to|near|on|by|inside|outside|"
            r"debajo de|encima de|junto a|al lado de|cerca de|sobre|bajo|arriba de)"
            r"\s+[^,]{1,180},\s*)",
            "", command, count=1,
        )
        if re.match(r"(?:explain|explica|expl\u00edcame|explicame)\s+(?:how|why|what|c\u00f3mo|como|por qu\u00e9|por que)\b", command):
            continue
        # A direct review/check/compare request can coordinate an explicit
        # annotation action. Do not promote hypothetical or instructional prose.
        if re.match(r"^(?:explain|review|check|compare|inspect|explica|expl\u00edcame|explicame)\b", command):
            for conjunction in re.finditer(r"\b(?:and|y)\s+", command[:240]):
                lead = command[:conjunction.start()]
                candidate = command[conjunction.end():].strip()
                if re.search(r"\b(?:how|why|should|would|could|instruction|instructions|meaning)\b", lead):
                    continue
                # Checking a person's permission, obligation or intention is
                # discussion, not a coordinated command addressed to Clicky.
                if re.search(
                    r"\b(?:whether|if)\s+(?:i|we|you|he|she|they|the student|the learner)\s+"
                    r"(?:can|may|must|need(?:s)?\s+to|have\s+to|want(?:s)?\s+to|am\s+allowed\s+to|are\s+allowed\s+to)\b",
                    lead,
                ):
                    continue
                if re.match(r"(?:" + writing + "|" + annotation + ")", candidate) or _is_drawn_letter_command(candidate):
                    command = candidate
                    break
        # A pen/color selection is an instrument for the following explicit
        # annotation, not a general permission to execute arbitrary commands.
        command = re.sub(
            r"^(?:use (?:your|the|a) (?:blue |green |red |colored )?(?:pencil|pen) to|"
            r"(?:usa|utiliza) (?:tu|el|un) (?:l\u00e1piz|lapiz|bol\u00edgrafo)(?: azul| verde| rojo)? para)\s+",
            "", command, count=1,
        )
        drawing_method = _DRAWING_METHOD.match(command)
        if drawing_method and not re.search(r"\b(?:how|why|without|not|never)\b", command[:drawing_method.end()]):
            yield command
            continue
        if re.match(annotation, command) or re.match(writing, command) or _is_drawn_letter_command(command):
            yield command


def _is_pen_command(command: str) -> bool:
    if _DRAWING_METHOD.match(command) or _is_drawn_letter_command(command):
        return True
    drawing_verb = re.match(
        r"(?:trace|sketch|circle|underline|bracket|draw|rodea|encierra|subraya|"
        r"dibuja|dibujar|traza|trazar|rodear|encerrar|subrayar)\b", command,
    )
    explicit_shape = re.search(
        r"\b(?:pen|pencil) (?:traces|strokes)\b|"
        r"\b(?:circle|circles|arrow|arrows|path|paths|bracket|brackets|"
        r"flecha|flechas|c\u00edrculo|c\u00edrculos|trazos|corchete|corchetes)\b", command,
    )
    # A topic noun in ordinary note prose is not a drawing command.
    # Generic annotate/mark requires an explicit instrumental shape.
    shape_action = re.match(r"(?:add|put|insert)\b", command)
    shape_instrument = re.match(r"(?:annotate|mark|anota|marca)\b", command) and re.search(
        r"\b(?:with|using|con)\s+(?:a |an |the |un |una )?(?:blue |red |green )?"
        r"(?:circle|arrow|path|bracket|flecha|c\u00edrculo|trazos|corchete)\b", command,
    )
    topic_only = re.search(r"\b(?:about|regarding|discussing|sobre|acerca)\b", command)
    return bool(drawing_verb or (explicit_shape and not topic_only and (shape_action or shape_instrument)))


def note_requested(text: str, *, _pen_only: bool = False) -> bool:
    """Recognize explicit notebook writing/annotation requests, not discussion."""
    for command in _iter_accepted_commands(text):
        if not _pen_only or _is_pen_command(command):
            return True
    return False


def pen_trace_requested(text: str) -> bool:
    """Use exactly the same accepted imperative clauses as note routing."""
    return note_requested(text, _pen_only=True)


def drawn_letter_requested(text: str) -> bool:
    """Recognize explicit letter glyph requests that require model pen paths."""
    return any(_is_drawn_letter_command(command) for command in _iter_accepted_commands(text))


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
