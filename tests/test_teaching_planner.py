import asyncio
import base64
import copy
import json
import unittest
from automation.inknotes_mcp import write_explanation, planning_page

JPEG_FIXTURE = base64.b64decode('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAACAAIDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q==')
IMAGE = {'type':'image','mimeType':'image/jpeg','data':base64.b64encode(JPEG_FIXTURE).decode()}
LESSON_PLAN = {'schema': 'clicky.lesson_plan', 'version': 1, 'components': [{
    'component_id': 'lesson-main',
    'region': {'x': 0, 'y': 0, 'width': 1000, 'height': 1000},
    'required_labels': [], 'required_symbols': [], 'required_objects': ['sentence'],
    'symbol_count': None, 'symbol_sequence': [], 'dimension_label': None, 'exact_text': None,
}]}
def result(page):
    return {'content':[{'type':'text','text':json.dumps(page)}, IMAGE]}

class Client:
    def __init__(self):
        self.page = dict(notebook_id='n',page_id='p',revision=0,width=1000,height=1000,
                          saved=False,has_save_location=True,template='Blank',annotations=[],strokes=[],
                          handwritten_notes=[],teaching_annotations=[],cartesian_planes=[])
        self.calls=[]
        self.change_before_write=False
    async def request(self, method):
        schemas = {
            'inknotes_draw_curves': {'paths': {}, 'pen_width': {}, 'color': {}, 'description': {}},
            'inknotes_draw_strokes': {'strokes': {}, 'pen_width': {}, 'color': {}, 'description': {}},
            'inknotes_read_page': {'region': {}},
            'inknotes_read_ink': {'region': {}, 'max_strokes': {}, 'max_points': {}},
            'inknotes_create_page': {'page_name': {}},
            'inknotes_annotate': {'shape': {}, 'target_bounds': {}, 'padding': {}, 'color': {}},
            'inknotes_write_at': {'text': {}, 'x': {}, 'y': {}, 'width': {}, 'color': {}},
            'inknotes_draw_path': {'points': {}, 'pen_width': {}, 'color': {}, 'description': {}},
            'inknotes_remove_annotation': {'annotation_id': {}},
            'inknotes_save': {},
            'inknotes_add_handwriting': {'text': {}, 'new_page_if_needed': {}},
        }
        return {'tools': [{'name': name, 'inputSchema': {'properties': schemas[name]}}
                          for name in schemas]}
    async def call(self,name,arguments=None):
        self.calls.append((name,dict(arguments or {})))
        if name=='inknotes_read_page':
            if self.change_before_write and len(self.calls)==2: self.page['revision']+=1
            snapshot = copy.deepcopy(self.page)
            region = (arguments or {}).get('region')
            if region:
                snapshot['image_coordinates'] = {'space': 'page', 'units': 'WPF_DIP',
                    'crop': region, 'scale': 1, 'image_width': 100, 'image_height': 100}
            else:
                snapshot['image_coordinates'] = {'space': 'page', 'units': 'WPF_DIP',
                    'crop': {'x': 0, 'y': 0, 'width': snapshot['width'], 'height': snapshot['height']},
                    'scale': 1, 'image_width': snapshot['width'], 'image_height': snapshot['height']}
            return result(snapshot)
        self.page['revision']+=1
        if name=='inknotes_save': self.page['saved']=True
        else:
            self.page['teaching_annotations'].append({'id':'a','complete':True})
        return result({'annotation_id':'a','page':self.page})


class LetterClient(Client):
    """Native-like fixture with annotation bounds and crop coordinates."""
    def __init__(self, crop_scales=(1,), crop_regions=None, include_curves=True):
        super().__init__()
        self.crop_scales = iter(crop_scales)
        self.crop_regions = iter(crop_regions) if crop_regions is not None else None
        self.include_curves = include_curves
        self._annotation_number = 0

    async def request(self, method):
        catalog = await super().request(method)
        if not self.include_curves:
            catalog['tools'] = [tool for tool in catalog['tools'] if tool['name'] != 'inknotes_draw_curves']
        return catalog

    @staticmethod
    def _bounds(arguments):
        points = []
        if 'strokes' in arguments:
            points = [point for stroke in arguments['strokes'] for point in stroke]
        elif 'paths' in arguments:
            for path in arguments['paths']:
                points.append(path['start'])
                for segment in path['segments']:
                    points.append(segment['end'])
                    points.extend(segment.get(key) for key in ('control1', 'control2') if key in segment)
        if not points:
            return {'x': 10, 'y': 10, 'width': 20, 'height': 20}
        xs, ys = [point['x'] for point in points], [point['y'] for point in points]
        return {'x': min(xs), 'y': min(ys), 'width': max(1, max(xs) - min(xs)),
                'height': max(1, max(ys) - min(ys))}

    async def call(self, name, arguments=None):
        arguments = dict(arguments or {})
        self.calls.append((name, arguments))
        if name == 'inknotes_read_page':
            if arguments.get('region'):
                scale = next(self.crop_scales, 1)
                requested = arguments['region']
                crop = (next(self.crop_regions) if self.crop_regions is not None else requested)
                snapshot = copy.deepcopy(self.page)
                snapshot['image_coordinates'] = {'space': 'page', 'units': 'WPF_DIP',
                    'crop': crop, 'scale': scale, 'image_width': 100, 'image_height': 100}
                return result(snapshot)
            snapshot = copy.deepcopy(self.page)
            snapshot['image_coordinates'] = {'space': 'page', 'units': 'WPF_DIP',
                'crop': {'x': 0, 'y': 0, 'width': self.page['width'], 'height': self.page['height']},
                'scale': 1, 'image_width': self.page['width'], 'image_height': self.page['height']}
            return result(snapshot)
        self.page['revision'] += 1
        if name == 'inknotes_save':
            self.page['saved'] = True
            return result({'page':copy.deepcopy(self.page)})
        self._annotation_number += 1
        annotation_id = f'a{self._annotation_number}'
        bounds = self._bounds(arguments)
        self.page['teaching_annotations'].append({'id':annotation_id, 'complete':True, **bounds})
        self.page['strokes'].extend([
            {'stroke_id':f'{annotation_id}-{index}', 'annotation_id':annotation_id,
             'bounds':copy.deepcopy(bounds), 'color':arguments.get('color','#16A34A')}
            for index, _ in enumerate(arguments.get('strokes', arguments.get('paths', [None])))
        ])
        return result({'annotation_id':annotation_id, 'page':copy.deepcopy(self.page)})


class MotionReferenceClient(LetterClient):
    """Read-only source-ink fixture with unmodified native pen points."""
    async def call(self, name, arguments=None):
        arguments = dict(arguments or {})
        if name == 'inknotes_read_ink':
            self.calls.append((name, arguments))
            snapshot = copy.deepcopy(self.page)
            return {'content': [{'type': 'text', 'text': json.dumps({
                'page': snapshot,
                'region': arguments['region'],
                'coordinate_space': 'page',
                'source': 'original_native_ink',
                'sampling': 'exact_complete_strokes',
                'truncated': False,
                'timing': 'unavailable',
                'timestamps_available': False,
                'pressure_stored': True,
                'stroke_count': 1,
                'point_count': 3,
                'strokes': [{
                    'stroke_id': 'learner-black-7', 'source_stroke_index': 7, 'content_hash': 'source-hash',
                    'bounds': {'x': 10, 'y': 10, 'width': 30, 'height': 20},
                    'color': '#000000', 'pen_up_after': True,
                    'points': [{'source_point_index': 0, 'x': 10, 'y': 10, 'pressure_factor': .3},
                               {'source_point_index': 1, 'x': 20, 'y': 30, 'pressure_factor': .6},
                               {'source_point_index': 2, 'x': 40, 'y': 10, 'pressure_factor': .4}],
                }],
            })}], 'isError': False}
        return await super().call(name, arguments)


class NewPageMotionClient(MotionReferenceClient):
    """Native create-page receipt fixture that preserves original source state."""
    async def call(self, name, arguments=None):
        arguments = dict(arguments or {})
        if name == 'inknotes_create_page':
            self.calls.append((name, arguments))
            source_page = copy.deepcopy(self.page)
            self.page = dict(notebook_id='n', page_id='new-page', revision=0, width=1000, height=1000,
                             saved=False, has_save_location=True, template='Blank', annotations=[], strokes=[],
                             handwritten_notes=[], teaching_annotations=[], cartesian_planes=[])
            return result({'status': 'page_created', 'source_page': source_page,
                           'page': copy.deepcopy(self.page), 'metadata': {
                               'source_page_id': source_page['page_id'], 'created_page_id': 'new-page',
                               'original_preserved': True, 'empty_ink': True,
                           }})
        return await super().call(name, arguments)

class Provider:
    def __init__(self,commands): self.commands=iter(commands);self.inputs=[];self.reader_calls=[]
    async def stream_response(self,prompt,images,history,system,model=None):
        if 'clicky.lesson_plan' in prompt:
            yield json.dumps(LESSON_PLAN)
            return
        if 'clicky.teaching_output_observation' in prompt:
            self.reader_calls.append((prompt, images, history, system, model))
            yield json.dumps({
                'schema': 'clicky.teaching_output_observation', 'version': 1,
                'visible_text': 'Rows alpha times plus minus equals A',
                'labels': ['Rows', 'A'],
                'symbols': ['alpha', 'times', 'plus', 'minus', 'equals'],
                # The independent reader records the entries in a visible
                # vector/matrix separately from all standalone symbols.
                'entry_symbol_sequence': ['alpha', 'times', 'plus', 'minus', 'equals'],
                'objects': ['sentence', 'row_vector', 'column_vector', 'matrix', 'arrow', 'enclosure'],
                'uncertainties': [],
            })
            return
        self.inputs.append((json.loads(prompt),images,system))
        command = next(self.commands)
        if isinstance(command, dict) and command.get('tool') in {
                'inknotes_add_handwriting', 'inknotes_annotate', 'inknotes_write_at',
                'inknotes_draw_path', 'inknotes_draw_strokes', 'inknotes_draw_curves'}:
            command = {**command, 'component_id': command.get('component_id', 'lesson-main')}
        yield json.dumps(command)

DONE={'done':True,'checklist':dict(mathematics=True,targets=True,legibility=True,complete=True),'assessment':'Correct blue circle and explanation, readable.'}
WRITE={'tool':'inknotes_write_at','arguments':{'text':'2+2=4','x':10,'y':10,'width':200},'narration':'Two plus two equals four.'}
DRAW_STROKES={
    'tool':'inknotes_draw_strokes',
    'arguments':{
        'strokes':[
            [{'x':100,'y':100},{'x':100,'y':140}],
            [{'x':100,'y':120},{'x':120,'y':100},{'x':120,'y':140}],
        ],
        'pen_width':3,
        'color':'#16A34A',
        'description':'letter A centerline paths',
    },
}
DRAW_CURVES={
    'tool':'inknotes_draw_curves',
    'arguments':{
        'paths':[
            {'start':{'x':200,'y':100},'segments':[
                {'kind':'cubic','control1':{'x':210,'y':90},'control2':{'x':230,'y':90},'end':{'x':240,'y':100}},
                {'kind':'line','end':{'x':240,'y':140}},
            ]},
            {'start':{'x':260,'y':140},'segments':[
                {'kind':'line','end':{'x':280,'y':100}},
                {'kind':'line','end':{'x':300,'y':140}},
            ]},
        ],
        'pen_width':4,
        'color':'#16A34A',
        'description':'short curved letter label',
    },
}
class TeachingTests(unittest.IsolatedAsyncioTestCase):
    def test_exact_copy_mode_requires_affirmative_command(self):
        from automation.inknotes_mcp import _explicit_exact_copy_requested
        self.assertFalse(_explicit_exact_copy_requested('Redraw this problem to explain it, not an exact copy of the source.'))
        self.assertFalse(_explicit_exact_copy_requested('Do not make a literal transcription.'))
        self.assertTrue(_explicit_exact_copy_requested('Make an exact copy of this vector.'))
        self.assertTrue(_explicit_exact_copy_requested('Use a verbatim transcription.'))

    def test_new_blank_page_live_teaching_request_is_not_lettering_gated(self):
        from automation.inknotes_mcp import _explicit_exact_copy_requested, _explicit_new_page_requested
        question = (
            'Use the source notebook as context for what I am learning: row vectors versus column vectors. '
            'On a NEW BLANK PAGE, DRAW a short clearer lesson with actual native pen curves. '
            'Preserve all previous pages and attempts. This is a teaching explanation, not an exact copy of the source. '
            'Required visible content: one horizontal vector [1 2 3] with a handwritten label "row" and dimension "1 x 3"; '
            'one vertical vector containing 1, 2, 3 with a handwritten label "col" and dimension "3 x 1".'
        )
        self.assertTrue(_explicit_new_page_requested(question))
        self.assertFalse(_explicit_exact_copy_requested(question))

    async def test_images_revisions_callbacks_and_readback(self):
        client=Client();provider=Provider([WRITE,{'tool':'inknotes_save','arguments':{}},DONE]);events=[]
        async def event(value):events.append(value)
        status=await write_explanation(client,provider,'m','Explain','2+2=4',lambda:True,on_event=event)
        self.assertIn('model inspected',status);self.assertIn('notebook is saved',status)
        self.assertTrue(all(images for _,images,_ in provider.inputs))
        self.assertEqual(next(event for event in events if event['type'] == 'step')['narration'],'Two plus two equals four.')
        verification = next(item for item in events if item['type'] == 'verification')
        self.assertEqual(verification['assessment'], DONE['assessment'])
        writes=[args for name,args in client.calls if name=='inknotes_write_at']
        self.assertEqual(writes[0]['revision'],0)
        self.assertTrue(writes[0]['operation_id'])

    async def test_existing_source_pixels_cannot_satisfy_terminal_completion(self):
        """A post-write crop may show source text, so it cannot prove attribution."""
        source_matching_plan = copy.deepcopy(LESSON_PLAN)
        source_matching_plan['components'][0]['required_labels'] = ['source equation']
        source_matching_plan['components'][0]['required_objects'] = ['sentence']

        class SourceMatchingProvider(Provider):
            async def stream_response(self, prompt, images, history, system, model=None):
                if 'clicky.lesson_plan' in prompt:
                    yield json.dumps(source_matching_plan)
                    return
                if 'clicky.teaching_output_observation' in prompt:
                    self.reader_calls.append((prompt, images, history, system, model))
                    yield json.dumps({
                        'schema': 'clicky.teaching_output_observation', 'version': 1,
                        'visible_text': 'source equation', 'labels': ['source equation'],
                        'symbols': [], 'entry_symbol_sequence': [], 'objects': ['sentence'],
                        'uncertainties': [],
                    })
                    return
                async for chunk in super().stream_response(prompt, images, history, system, model):
                    yield chunk

        client = Client()
        # This is text-only source content in InkNotes' native annotations
        # collection. A reader that saw only the final image would report the
        # required label despite the new annotation adding something else.
        client.page['annotations'].append({'id': 'learner-source', 'text': 'source equation'})
        provider = SourceMatchingProvider([WRITE, {'tool': 'inknotes_save', 'arguments': {}}, DONE])
        events = []

        async def event(value):
            events.append(value)

        status = await write_explanation(
            client, provider, 'm', 'Explain this source equation here', 'source equation',
            lambda: True, on_event=event,
        )

        self.assertIn('source ink', status)
        self.assertIn('attribution was not verified', status)
        self.assertEqual(provider.reader_calls, [])
        verification = next(item for item in events if item['type'] == 'verification')
        self.assertFalse(verification['complete'])
        self.assertFalse(verification['independent_output_reader'])

    async def test_visual_assessment_event_is_bounded(self):
        assessment = 'x' * 2000
        done = {**DONE, 'assessment': assessment}
        events = []

        async def event(value):
            events.append(value)

        status = await write_explanation(
            Client(), Provider([WRITE, {'tool': 'inknotes_save', 'arguments': {}}, done]),
            'm', 'Explain', '2+2=4', lambda: True, on_event=event,
        )

        verification = next(item for item in events if item['type'] == 'verification')
        self.assertEqual(len(verification['assessment']), 1200)
        self.assertIn('model inspected', status)
    async def test_learner_change_stops_stale_plan(self):
        client=Client();client.change_before_write=True
        status=await write_explanation(client,Provider([WRITE]),'m','Explain','x',lambda:True)
        self.assertIn('changed',status)
        self.assertFalse(any(n=='inknotes_write_at' for n,_ in client.calls))
    async def test_refuses_removal_of_other_ink(self):
        provider=Provider([{'tool':'inknotes_remove_annotation','arguments':{'annotation_id':'learner'}}])
        with self.assertRaisesRegex(RuntimeError,'Refusing to remove'):
            await write_explanation(Client(),provider,'m','Explain','x',lambda:True)
    async def test_duplicate_command_not_reapplied(self):
        client=Client()
        await write_explanation(client,Provider([WRITE,WRITE,DONE]),'m','Explain','x',lambda:True)
        self.assertEqual(sum(n=='inknotes_write_at' for n,_ in client.calls),1)
    async def test_no_checklist_does_not_claim_visual_verification(self):
        status=await write_explanation(Client(),Provider([WRITE,{'done':True}]),'m','Explain','x',lambda:True)
        self.assertIn('have not been verified',status)
    async def test_cancel_during_model_stream_prevents_write(self):
        active=True
        class CancelProvider:
            async def stream_response(self,*args,**kwargs):
                if 'clicky.lesson_plan' in args[0]:
                    yield json.dumps(LESSON_PLAN)
                    return
                nonlocal active
                active=False
                yield json.dumps(WRITE)
        client=Client()
        status=await write_explanation(client,CancelProvider(),'m','Explain','x',lambda:active)
        self.assertIn('stopped',status)
        self.assertFalse(any(n=='inknotes_write_at' for n,_ in client.calls))
    async def test_enclosure_page_edge_rejection_keeps_target_during_repair(self):
        class EnclosureClient(Client):
            async def call(self, name, arguments=None):
                if name == 'inknotes_annotate' and arguments['padding'] == 64:
                    self.calls.append((name, dict(arguments)))
                    return {'isError':True,'content':[{'type':'text','text':
                        'Enclosure does not fit inside the page after padding and pen width.'}]}
                return await super().call(name, arguments)
        target={'x':800,'y':100,'width':180,'height':30}
        commands=[{'tool':'inknotes_annotate','arguments':{
            'shape':'enclosure','target_bounds':target,'padding':padding}}
            for padding in (64, 4)]
        provider=Provider(commands + [{'tool':'inknotes_save','arguments':{}}, DONE])
        client=EnclosureClient()
        status=await write_explanation(client,provider,'m',
            'Draw a pencil enclosure around the whole vector','draft',lambda:True)
        attempts=[args for name,args in client.calls if name=='inknotes_annotate']
        self.assertEqual(len(attempts),2)
        self.assertTrue(all(a['target_bounds']==target for a in attempts))
        self.assertTrue(all(a['shape']=='enclosure' and a['revision']==0 for a in attempts))
        self.assertIn('repair_instruction',provider.inputs[1][0]['last_result'])
        self.assertEqual(provider.inputs[1][0]['retained_pen_annotation_count'],0)
        self.assertEqual(provider.inputs[2][0]['retained_pen_annotation_count'],1)
        self.assertIn('notebook is saved',status)
    async def test_timeout_returns_uncertain_status_without_verification(self):
        events=[]
        shape={'tool':'inknotes_annotate','arguments':{
            'shape':'ellipse','target_bounds':{'x':10,'y':10,'width':20,'height':20}}}
        class PartialThenSlowProvider:
            def __init__(self): self.calls=0
            async def stream_response(self,*args,**kwargs):
                if 'clicky.lesson_plan' in args[0]:
                    yield json.dumps(LESSON_PLAN)
                    return
                self.calls += 1
                if self.calls == 1:
                    yield json.dumps({**shape, 'component_id': 'lesson-main'})
                    return
                await asyncio.sleep(1)
                yield json.dumps(DONE)
        async def event(value): events.append(value)
        client=Client()
        status=await write_explanation(client,PartialThenSlowProvider(),'m',
                                       'Explain and draw pen traces here','answer',
                                       lambda:True,on_event=event,timeout_seconds=0.05)
        self.assertIn('time limit',status)
        self.assertIn('completion and saving were not verified',status)
        self.assertFalse(any(item['type']=='verification' for item in events))
        self.assertEqual(sum(n=='inknotes_annotate' for n,_ in client.calls),1)
        self.assertFalse(any(n=='inknotes_save' for n,_ in client.calls))
    async def test_baseline_preserves_complete_note(self):
        client=Client()
        await write_explanation(client,Provider([{'tool':'inknotes_add_handwriting','arguments':{'text':'short'}},{'done':True}]),'m','Write','complete explanation',lambda:True,mode='baseline')
        self.assertEqual(next(a for n,a in client.calls if n=='inknotes_add_handwriting')['text'],'complete explanation')
    async def test_cancel_during_preflight_prevents_mutation(self):
        active=True
        class CancellingClient(Client):
            async def call(self,name,arguments=None):
                nonlocal active
                value=await super().call(name,arguments)
                if len(self.calls)==2: active=False
                return value
        client=CancellingClient()
        await write_explanation(client,Provider([WRITE]),'m','Explain','x',lambda:active)
        self.assertFalse(any(n=='inknotes_write_at' for n,_ in client.calls))
    async def test_atomic_rejection_can_be_corrected(self):
        class RejectClient(Client):
            rejected=False
            async def call(self,name,arguments=None):
                if name=='inknotes_write_at' and not self.rejected:
                    self.rejected=True
                    return {'isError':True,'content':[{'type':'text','text':'Rectangle overlaps learner ink'}]}
                return await super().call(name,arguments)
        client=RejectClient();provider=Provider([WRITE,WRITE,DONE])
        status=await write_explanation(client,provider,'m','Explain','x',lambda:True)
        self.assertIn('model inspected',status)
        self.assertIn('repair_instruction',provider.inputs[1][0]['last_result'])
    async def test_save_after_another_write_is_not_suppressed(self):
        client=Client()
        second={'tool':'inknotes_write_at','arguments':{'text':'4+4=8','x':20,'y':80,'width':200}}
        save={'tool':'inknotes_save','arguments':{}}
        await write_explanation(client,Provider([WRITE,save,second,save,DONE]),'m','Explain','x',lambda:True)
        self.assertEqual(sum(n=='inknotes_save' for n,_ in client.calls),2)
    async def test_crop_keeps_full_page_for_assessment_turn(self):
        client=Client();provider=Provider([WRITE,{'tool':'inknotes_read_page','arguments':{'region':{'x':0,'y':0,'width':20,'height':20}}},DONE,DONE])
        status=await write_explanation(client,provider,'m','Explain','x',lambda:True)
        self.assertIn('model inspected',status)
        self.assertEqual(len(provider.inputs),3)
        self.assertEqual([view['kind'] for view in provider.inputs[-1][0]['current_view_images']],
                         ['current_full_page', 'current_detail_crop'])
    async def test_expected_page_mismatch_prevents_planning(self):
        client=Client();provider=Provider([])
        status=await write_explanation(client,provider,'m','Explain','x',lambda:True,
                                      expected_page={'notebook_id':'n','page_id':'old','revision':0})
        self.assertIn('No ink was added',status)
        self.assertEqual(provider.inputs,[])
    async def test_nonvision_provider_gets_only_fullnote_without_images(self):
        client=Client();provider=Provider([{'tool':'inknotes_add_handwriting','arguments':{'text':'short'}},{'done':True}])
        status=await write_explanation(client,provider,'m','Explain','full answer',lambda:True,supports_vision=False)
        self.assertTrue(all(not images for _,images,_ in provider.inputs))
        self.assertNotIn('inknotes_annotate',provider.inputs[0][2])
        self.assertIn('text fallback',status)
        self.assertEqual(next(a for n,a in client.calls if n=='inknotes_add_handwriting')['text'],'full answer')
    def test_dense_page_anchors_cover_late_spatial_regions(self):
        strokes=[{'stroke_id':str(i),'bounds':{'x':i%20,'y':i//20,'width':1,'height':1}} for i in range(280)]
        strokes += [{'stroke_id':'late','bounds':{'x':950,'y':950,'width':10,'height':10}}]
        view=planning_page({'width':1000,'height':1000,'strokes':strokes})
        self.assertEqual(len(view['strokes']),160)
        self.assertIn('late',[item['stroke_id'] for item in view['strokes']])
        self.assertEqual(view['stroke_coverage']['intersecting_count'],281)
        self.assertTrue(view['strokes_truncated'])
    def test_crop_returns_late_anchors_and_preserves_page_coordinates(self):
        strokes=[{'stroke_id':str(i),'bounds':{'x':10,'y':10,'width':1,'height':1}} for i in range(280)]
        strokes += [{'stroke_id':'late','bounds':{'x':950,'y':950,'width':10,'height':10}}]
        transform={'crop':{'x':900,'y':900,'width':100,'height':100},'scale':1}
        view=planning_page({'width':1000,'height':1000,'image_coordinates':transform,'strokes':strokes})
        self.assertEqual([item['stroke_id'] for item in view['strokes']],['late'])
        self.assertEqual(view['strokes'][0]['bounds']['x'],950)
        self.assertFalse(view['strokes_truncated'])
        self.assertEqual(view['image_coordinates'],transform)
    def test_long_stroke_marks_every_intersected_occupancy_cell(self):
        view=planning_page({'width':100,'height':100,'strokes':[
            {'stroke_id':'long','bounds':{'x':1,'y':10,'width':98,'height':2}}]})
        cells=view['stroke_coverage']['cells']
        self.assertEqual(len(cells),4)
        self.assertTrue(all(cell['stroke_count']==1 for cell in cells))
        self.assertEqual(view['stroke_coverage']['intersecting_count'],1)
        self.assertEqual(len(view['strokes']),1)
    def test_crop_includes_crossing_stroke(self):
        view=planning_page({'image_coordinates':{'crop':{'x':10,'y':10,'width':10,'height':10}},
            'strokes':[{'stroke_id':'cross','bounds':{'x':5,'y':15,'width':10,'height':1}}]})
        self.assertEqual(view['stroke_coverage']['intersecting_count'],1)
    async def test_ambiguous_handwriting_clarification_performs_no_mutation(self):
        client=Client();events=[]
        async def event(value): events.append(value)
        status=await write_explanation(client,Provider([{'clarify':'Is the symbol beside the fraction a letter or a digit?'}]),
            'm','Explain','draft interpretation',lambda:True,on_event=event)
        self.assertIn('No ink was added',status)
        self.assertTrue(all(name=='inknotes_read_page' for name,_ in client.calls))
        clarification = next(event for event in events if event['type'] == 'clarification')
        self.assertFalse(clarification['complete'])
    async def test_requested_pen_drawing_cannot_complete_with_text_only(self):
        events=[]
        async def event(value): events.append(value)
        status=await write_explanation(Client(),Provider([WRITE,DONE]),'m','Draw pen strokes to explain this equation','answer',lambda:True,on_event=event)
        self.assertIn('requested pen drawing is incomplete',status)
        self.assertFalse(any(event['type']=='verification' for event in events))
    async def test_requested_pen_shape_can_pass_structural_and_visual_checks(self):
        status=await write_explanation(Client(),Provider([{'tool':'inknotes_annotate','arguments':{'shape':'ellipse','target_bounds':{'x':1,'y':1,'width':20,'height':20}}},DONE]),
            'm','Circle this term','answer',lambda:True)
        self.assertIn('model inspected',status)
        self.assertNotIn('pen drawing is incomplete',status)

    async def test_drawn_letter_requires_draw_strokes_receipt(self):
        enclosure={'tool':'inknotes_annotate','arguments':{
            'shape':'ellipse','target_bounds':{'x':1,'y':1,'width':20,'height':20}}}
        events=[]
        async def event(value): events.append(value)
        status=await write_explanation(
            Client(), Provider([enclosure,DONE]), 'm',
            'Draw the letter A', 'answer', lambda:True, on_event=event,
        )
        self.assertIn('requested drawn letter is incomplete',status)
        self.assertFalse(any(item['type']=='verification' for item in events))

    async def test_drawn_letter_uses_batched_centerline_paths_and_receipt(self):
        client=LetterClient(include_curves=False)
        provider=Provider([DRAW_STROKES,DONE,DONE])
        status=await write_explanation(
            client, provider, 'm', 'Draw the letter A',
            'answer', lambda:True,
        )
        self.assertIn('model inspected',status)
        self.assertNotIn('requested drawn letter is incomplete',status)
        self.assertTrue(provider.inputs[0][0]['explicit_drawn_letter_required'])
        self.assertEqual(provider.inputs[0][0]['retained_drawn_letter_count'],0)
        self.assertIn('pen-down point arrays',provider.inputs[0][2])
        self.assertIn('centerline pen paths',provider.inputs[0][2])
        draw_calls=[args for name,args in client.calls if name=='inknotes_draw_strokes']
        self.assertEqual(len(draw_calls),1)
        self.assertEqual(draw_calls[0]['strokes'],DRAW_STROKES['arguments']['strokes'])
        self.assertEqual(draw_calls[0]['pen_width'],3)
        self.assertEqual(draw_calls[0]['color'],'#16A34A')
        self.assertEqual(draw_calls[0]['description'],'letter A centerline paths')
        self.assertEqual(draw_calls[0]['notebook_id'],'n')
        self.assertEqual(draw_calls[0]['page_id'],'p')
        self.assertEqual(draw_calls[0]['revision'],0)
        self.assertTrue(draw_calls[0]['operation_id'])
        crops=[args['region'] for name,args in client.calls
               if name=='inknotes_read_page' and args.get('region')]
        self.assertEqual(len(crops),3)
        # Component evidence is read first and again at completion.  The
        # lettering-specific crop remains the middle readback.
        self.assertEqual(crops[1],{'x':94.0,'y':94.0,'width':32.0,'height':52.0})

    async def test_cancel_drawn_letter_during_model_stream_prevents_write(self):
        active=True
        class CancelProvider:
            async def stream_response(self,*args,**kwargs):
                if 'clicky.lesson_plan' in args[0]:
                    yield json.dumps(LESSON_PLAN)
                    return
                nonlocal active
                active=False
                yield json.dumps(DRAW_STROKES)
        client=Client()
        status=await write_explanation(
            client, CancelProvider(), 'm', 'Draw the letter A',
            'answer', lambda:active,
        )
        self.assertIn('stopped',status)
        self.assertFalse(any(name=='inknotes_draw_strokes' for name,_ in client.calls))

    async def test_curves_keep_model_geometry_and_pair_crop_with_full_page(self):
        client = LetterClient()
        provider = Provider([DRAW_CURVES, DONE, DONE])
        status = await write_explanation(client, provider, 'm', 'Draw the letters in my handwriting',
                                         'answer', lambda: True)
        self.assertIn('model inspected', status)
        calls = [args for name, args in client.calls if name == 'inknotes_draw_curves']
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['paths'], DRAW_CURVES['arguments']['paths'])
        self.assertEqual(provider.inputs[1][0]['retained_drawn_letter_crop_reviewed_count'], 1)
        self.assertEqual(provider.inputs[1][0]['page']['image_coordinates']['crop']['width'], 1000)
        current_views = provider.inputs[1][0]['current_view_images']
        self.assertEqual([view['kind'] for view in current_views],
                         ['current_full_page', 'current_detail_crop'])
        self.assertEqual(provider.inputs[1][0]['current_detail_page']
                         ['image_coordinates']['scale'], 1)
        # One original full-page reference follows the two current views.
        self.assertEqual(len(provider.inputs[1][1]), 3)

    async def test_native_source_motion_is_bounded_exact_and_survives_to_drawing_turn(self):
        client = MotionReferenceClient()
        source_region = {'x': 10, 'y': 10, 'width': 40, 'height': 30}
        read_ink = {'tool': 'inknotes_read_ink', 'arguments': {
            'region': source_region, 'max_strokes': 128, 'max_points': 12000,
        }}
        provider = Provider([read_ink, DRAW_CURVES, DONE])
        status = await write_explanation(client, provider, 'm',
                                         'Draw the letters in my handwriting',
                                         'answer', lambda: True)
        self.assertIn('model inspected', status)
        read_call = next(args for name, args in client.calls if name == 'inknotes_read_ink')
        self.assertEqual(read_call, {'region': source_region, 'max_strokes': 24, 'max_points': 2048})
        reference = provider.inputs[1][0]['source_motion_references'][0]
        self.assertEqual(reference['source_page_identity']['page_id'], 'p')
        self.assertEqual(reference['ink']['sampling'], 'exact_complete_strokes')
        self.assertEqual(reference['ink']['timing'], 'unavailable')
        self.assertFalse(reference['ink']['timestamps_available'])
        self.assertEqual(reference['ink']['strokes'][0]['points'], [
            {'source_point_index': 0, 'x': 10, 'y': 10, 'pressure_factor': .3},
            {'source_point_index': 1, 'x': 20, 'y': 30, 'pressure_factor': .6},
            {'source_point_index': 2, 'x': 40, 'y': 10, 'pressure_factor': .4},
        ])
        self.assertIn('inknotes_read_ink', provider.inputs[0][2])
        self.assertIn('Do not copy their coordinates', provider.inputs[0][2])

    async def test_flat_native_ink_region_is_repaired_without_aborting(self):
        client = MotionReferenceClient()
        source_region = {'x': 10, 'y': 10, 'width': 40, 'height': 30}
        malformed = {'tool': 'inknotes_read_ink', 'arguments': dict(source_region)}
        valid = {'tool': 'inknotes_read_ink', 'arguments': {'region': source_region}}
        provider = Provider([malformed, valid, DRAW_CURVES, DONE])

        status = await write_explanation(client, provider, 'm',
                                         'Draw the letters in my handwriting',
                                         'answer', lambda: True)

        self.assertIn('model inspected', status)
        read_calls = [args for name, args in client.calls if name == 'inknotes_read_ink']
        self.assertEqual(read_calls, [{'region': source_region, 'max_strokes': 24, 'max_points': 2048}])
        repair = provider.inputs[1][0]['last_result']
        self.assertIn('nested exactly', repair['instruction'])
        self.assertIn('arguments.region', repair['instruction'])

    async def test_explicit_new_page_preserves_original_references_and_rebinds_drawing(self):
        client = NewPageMotionClient()
        client.page['strokes'] = [{'stroke_id': 'learner-black-7',
                                   'bounds': {'x': 10, 'y': 10, 'width': 30, 'height': 20}}]
        source_region = {'x': 10, 'y': 10, 'width': 40, 'height': 30}
        source_crop = {'tool': 'inknotes_read_page', 'arguments': {'region': source_region}}
        source_motion = {'tool': 'inknotes_read_ink', 'arguments': {'region': source_region}}
        create = {'tool': 'inknotes_create_page', 'arguments': {'page_name': 'Handwriting attempts'}}
        provider = Provider([source_crop, source_motion, create, DRAW_CURVES, DONE])
        status = await write_explanation(
            client, provider, 'm',
            'Draw the letters in my handwriting on a new page.', 'answer', lambda: True,
        )
        self.assertIn('model inspected', status)
        create_call = next(args for name, args in client.calls if name == 'inknotes_create_page')
        self.assertEqual(create_call['notebook_id'], 'n')
        self.assertEqual(create_call['page_id'], 'p')
        self.assertEqual(create_call['revision'], 0)
        self.assertTrue(create_call['operation_id'])
        draw_call = next(args for name, args in client.calls if name == 'inknotes_draw_curves')
        self.assertEqual(draw_call['page_id'], 'new-page')
        self.assertEqual(draw_call['revision'], 0)
        draw_turn = provider.inputs[3][0]
        self.assertEqual(draw_turn['page']['page_id'], 'new-page')
        self.assertEqual(draw_turn['source_motion_references'][0]
                         ['source_page_identity']['page_id'], 'p')
        self.assertEqual([item['kind'] for item in draw_turn['source_reference_images']],
                         ['original_full_page', 'original_crop'])
        catalog = json.loads(provider.inputs[0][2].split('Tools: ', 1)[1])
        self.assertIn('inknotes_create_page', {tool['name'] for tool in catalog})

    async def test_new_blank_page_scene_request_blocks_source_page_drawing_until_creation(self):
        from automation.inknotes_mcp import _explicit_new_page_requested

        question = (
            'Draw handwritten letters and redraw this ENTIRE page on a NEW blank page using native pen curves. '
            'Use the original full-page image and close-ups as your handwriting examples; do not request or export '
            'raw source pen trajectories. Create the new page after inspecting the source, then immediately begin '
            'drawing. Recreate both large black headings, the vertical bracket with six marks, the horizontal bracket '
            'with seven marks, all blue explanatory sentences, the red box and arrow, red and green row vector labels, '
            'and the bottom question. Keep the layout and colors, with clearer handwriting inspired by the original. '
            'Draw in small progressive batches until the whole scene is present. No fonts, text tools, or prose-only '
            'substitute. Keep imperfect attempts visible; do not undo them. Preserve the source page. Save your progress '
            'and inspect it. Do not stop after two words or ask me to say next.'
        )
        self.assertTrue(_explicit_new_page_requested(question))
        client = NewPageMotionClient()
        client.page['strokes'] = [{'stroke_id': 'learner-black-7',
                                   'bounds': {'x': 10, 'y': 10, 'width': 30, 'height': 20}}]
        source_region = {'x': 10, 'y': 10, 'width': 40, 'height': 30}
        source_crop = {'tool': 'inknotes_read_page', 'arguments': {'region': source_region}}
        source_motion = {'tool': 'inknotes_read_ink', 'arguments': {'region': source_region}}
        create = {'tool': 'inknotes_create_page', 'arguments': {'page_name': 'Scene progression'}}
        # Muse proposes a valid curve batch too early. The planner must retain
        # the source evidence and request creation instead of mutating page p.
        provider = Provider([source_crop, source_motion, DRAW_CURVES, create, DRAW_CURVES, DONE])

        status = await write_explanation(client, provider, 'm', question, 'answer', lambda: True)

        self.assertIn('model inspected', status)
        draw_calls = [args for name, args in client.calls if name == 'inknotes_draw_curves']
        self.assertEqual(len(draw_calls), 1)
        create_index = next(index for index, (name, _) in enumerate(client.calls)
                            if name == 'inknotes_create_page')
        draw_index = next(index for index, (name, _) in enumerate(client.calls)
                          if name == 'inknotes_draw_curves')
        self.assertLess(create_index, draw_index)
        self.assertEqual(draw_calls[0]['page_id'], 'new-page')
        repair = provider.inputs[3][0]['last_result']
        self.assertIn('No content was added', repair['error'])
        self.assertIn('inknotes_create_page', repair['instruction'])

    async def test_new_page_is_not_available_without_explicit_request(self):
        client = NewPageMotionClient()
        provider = Provider([{'tool': 'inknotes_create_page', 'arguments': {}}])
        with self.assertRaisesRegex(RuntimeError, 'unavailable notebook tool'):
            await write_explanation(client, provider, 'm', 'Draw the letters', 'answer', lambda: True)
        self.assertFalse(any(name == 'inknotes_create_page' for name, _ in client.calls))

    async def test_explicit_letters_cannot_use_font_writing_tool(self):
        client = LetterClient()
        provider = Provider([WRITE])
        with self.assertRaisesRegex(RuntimeError, 'unavailable notebook tool'):
            await write_explanation(client, provider, 'm', 'Draw the letters', 'answer', lambda: True)
        self.assertFalse(any(name == 'inknotes_write_at' for name, _ in client.calls))
        catalog = json.loads(provider.inputs[0][2].split('Tools: ', 1)[1])
        self.assertTrue({'inknotes_write_at', 'inknotes_add_handwriting'}.isdisjoint(
            {tool['name'] for tool in catalog}))

    async def test_downscaled_letter_crop_cannot_finish(self):
        client = LetterClient(crop_scales=(0.5, 0.5, 0.5))
        provider = Provider([DRAW_CURVES, DONE])
        status = await write_explanation(client, provider, 'm', 'Draw the letters',
                                         'answer', lambda: True, max_steps=2)
        self.assertIn('incomplete', status)
        self.assertEqual(provider.inputs[1][0]['retained_drawn_letter_crop_reviewed_count'], 0)

    async def test_schema_valid_flattened_mutation_is_canonicalized_without_regeneration(self):
        flattened = {
            'tool': 'inknotes_draw_curves', 'component_id': 'lesson-main',
            'paths': DRAW_CURVES['arguments']['paths'], 'pen_width': 4,
            'color': '#16A34A', 'description': 'coherent flattened label',
        }
        client = LetterClient()
        events = []

        async def event(value):
            events.append(value)

        provider = Provider([flattened, DONE, DONE])

        status = await write_explanation(
            client, provider, 'm', 'Draw the letters', 'answer', lambda: True, on_event=event,
        )

        self.assertIn('model inspected', status)
        draw_calls = [args for name, args in client.calls if name == 'inknotes_draw_curves']
        self.assertEqual(len(draw_calls), 1)
        self.assertEqual(draw_calls[0]['paths'], DRAW_CURVES['arguments']['paths'])
        self.assertEqual(draw_calls[0]['pen_width'], 4)
        self.assertEqual(draw_calls[0]['color'], '#16A34A')
        self.assertEqual(draw_calls[0]['description'], 'coherent flattened label')
        self.assertEqual([item for item in events if item['type'] == 'command_normalized'], [{
            'type': 'command_normalized', 'tool': 'inknotes_draw_curves', 'component_id': 'lesson-main',
        }])

    async def test_unknown_or_mixed_flattened_fields_are_rejected_before_dispatch(self):
        malformed_commands = [
            {
                'tool': 'inknotes_draw_curves', 'component_id': 'lesson-main',
                'paths': DRAW_CURVES['arguments']['paths'], 'bogus': 'not in the native schema',
            },
            {
                'tool': 'inknotes_draw_curves', 'component_id': 'lesson-main',
                'arguments': {'paths': DRAW_CURVES['arguments']['paths']}, 'color': '#16A34A',
            },
        ]
        for malformed in malformed_commands:
            with self.subTest(command=sorted(malformed)):
                client = LetterClient()
                provider = Provider([malformed, DRAW_CURVES, DONE, DONE])
                status = await write_explanation(
                    client, provider, 'm', 'Draw the letters', 'answer', lambda: True,
                )
                self.assertIn('model inspected', status)
                draw_calls = [args for name, args in client.calls if name == 'inknotes_draw_curves']
                self.assertEqual(len(draw_calls), 1)
                self.assertEqual(draw_calls[0]['description'], DRAW_CURVES['arguments']['description'])
                repair = provider.inputs[1][0]['last_result']
                self.assertIn('envelope was rejected before any native operation', repair['error'])

    async def test_malformed_envelope_budget_resets_after_successful_native_command(self):
        malformed = {
            'tool': 'inknotes_draw_curves', 'component_id': 'lesson-main',
            'paths': DRAW_CURVES['arguments']['paths'], 'unexpected': True,
        }
        valid_flat = {
            'tool': 'inknotes_draw_curves', 'component_id': 'lesson-main',
            'paths': DRAW_CURVES['arguments']['paths'], 'pen_width': 4,
            'color': '#16A34A', 'description': 'valid command breaks rejection run',
        }
        client = LetterClient()
        provider = Provider([malformed, valid_flat, malformed, malformed, malformed])

        status = await write_explanation(
            client, provider, 'm', 'Draw the letters', 'answer', lambda: True,
        )

        self.assertIn('three malformed envelopes', status)
        self.assertEqual(len(provider.inputs), 5)
        self.assertEqual(len([name for name, _ in client.calls if name == 'inknotes_draw_curves']), 1)

    async def test_final_component_crop_must_match_final_revision(self):
        class StaleFinalComponentCropClient(LetterClient):
            def __init__(self):
                super().__init__()
                self.component_reads = 0

            async def call(self, name, arguments=None):
                arguments = dict(arguments or {})
                full_component_region = {'x': 0, 'y': 0, 'width': 1000, 'height': 1000}
                if name == 'inknotes_read_page' and arguments.get('region') == full_component_region:
                    self.component_reads += 1
                    # The first component crop is the post-mutation snapshot.
                    # The second is the required final crop at DONE; make it
                    # stale to prove cached evidence cannot complete a task.
                    if self.component_reads >= 2:
                        self.calls.append((name, arguments))
                        stale = copy.deepcopy(self.page)
                        stale['revision'] = max(0, stale['revision'] - 1)
                        stale['image_coordinates'] = {
                            'space': 'page', 'units': 'WPF_DIP',
                            'crop': full_component_region, 'scale': 1,
                            'image_width': 100, 'image_height': 100,
                        }
                        return result(stale)
                return await super().call(name, arguments)

        client = StaleFinalComponentCropClient()
        provider = Provider([DRAW_CURVES, DONE, DONE])
        status = await write_explanation(
            client, provider, 'm', 'Draw the letters', 'answer', lambda: True,
        )

        self.assertIn('completion evidence is incomplete', status)
        self.assertGreaterEqual(client.component_reads, 2)
        self.assertEqual(provider.reader_calls, [])

    async def test_second_word_uses_paired_full_page_and_crop_without_reissuing(self):
        client = LetterClient()
        second = copy.deepcopy(DRAW_CURVES)
        second['arguments']['description'] = 'second distinct word'
        second['arguments']['paths'][0]['start']['x'] += 80
        provider = Provider([DRAW_CURVES, second, DONE, DONE])
        status = await write_explanation(client, provider, 'm', 'Draw the letters',
                                         'answer', lambda: True)
        self.assertIn('model inspected', status)
        self.assertEqual(len([name for name, _ in client.calls if name == 'inknotes_draw_curves']), 2)
        second_turn = provider.inputs[1][0]
        self.assertEqual(second_turn['page']['image_coordinates']['crop']['width'], 1000)
        self.assertEqual([view['kind'] for view in second_turn['current_view_images']],
                         ['current_full_page', 'current_detail_crop'])
        self.assertEqual(second_turn['current_detail_page']['image_coordinates']['scale'], 1)
        self.assertEqual(second_turn['retained_drawn_letter_crop_reviewed_count'], 1)
        # The immediate next response performs the second drawing.  A prior
        # crop used to force a full-page restoration and make Muse regenerate
        # this valid command, wasting a drawing turn.
        self.assertEqual(len(provider.inputs), 3)
        self.assertEqual(provider.inputs[2][0]['retained_drawn_letter_crop_reviewed_count'], 2)

    async def test_incomplete_json_is_not_applied_and_smaller_retry_can_finish(self):
        class PartialProvider(Provider):
            async def stream_response(self, prompt, images, history, system, model=None):
                if 'clicky.lesson_plan' in prompt:
                    async for chunk in super().stream_response(prompt, images, history, system, model=model):
                        yield chunk
                    return
                if 'clicky.teaching_output_observation' in prompt:
                    async for chunk in super().stream_response(prompt, images, history, system, model=model):
                        yield chunk
                    return
                self.inputs.append((json.loads(prompt), images, system))
                command = next(self.commands)
                if isinstance(command, dict) and command.get('tool') in {'inknotes_draw_curves', 'inknotes_draw_strokes'}:
                    command = {**command, 'component_id': 'lesson-main'}
                yield command if isinstance(command, str) else json.dumps(command)
        client = LetterClient()
        provider = PartialProvider(['{"tool":"inknotes_draw_curves","arguments":{"paths":[',
                                    DRAW_CURVES, DONE, DONE])
        status = await write_explanation(client, provider, 'm', 'Draw the letters',
                                         'answer', lambda: True)
        self.assertIn('model inspected', status)
        self.assertIn('No operation was applied', provider.inputs[1][0]['last_result']['error'])
        self.assertEqual(len([name for name, _ in client.calls if name == 'inknotes_draw_curves']), 1)

    async def test_repeated_incomplete_json_stops_without_mutation(self):
        class BrokenProvider:
            async def stream_response(self, *args, **kwargs):
                if 'clicky.lesson_plan' in args[0]:
                    yield json.dumps(LESSON_PLAN)
                    return
                yield '{"tool":"inknotes_draw_curves","arguments":'
        client = LetterClient()
        status = await write_explanation(client, BrokenProvider(), 'm', 'Draw the letters',
                                         'answer', lambda: True)
        self.assertIn('three rejected responses', status)
        self.assertTrue(all(name == 'inknotes_read_page' for name, _ in client.calls))

    def test_crop_evidence_requires_relevant_bounds_image_and_explicit_scale(self):
        from automation.inknotes_mcp import _native_crop_matches
        region = {'x': 100, 'y': 100, 'width': 50, 'height': 50}
        valid = {'image_coordinates': {'crop': region, 'scale': 1}}
        self.assertTrue(_native_crop_matches(valid, region, [IMAGE]))
        self.assertFalse(_native_crop_matches(valid, region, []))
        self.assertFalse(_native_crop_matches({'image_coordinates': {'crop': region}}, region, [IMAGE]))
        for scale in (True, float('nan'), 0.8):
            with self.subTest(scale=scale):
                self.assertFalse(_native_crop_matches(
                    {'image_coordinates': {'crop': region, 'scale': scale}}, region, [IMAGE]))
        self.assertFalse(_native_crop_matches(
            {'image_coordinates': {'crop': {'x': 0, 'y': 0, 'width': 10, 'height': 10}, 'scale': 1}},
            region, [IMAGE]))

    async def test_provider_length_finish_retries_without_dispatching_even_parseable_prefix(self):
        class LimitError(RuntimeError):
            finish_reason = 'length'
        class DrawingProvider(Provider):
            async def stream_response(self, *args, **kwargs):
                prompt = args[0]
                if 'clicky.lesson_plan' in prompt:
                    async for chunk in super().stream_response(*args, **kwargs):
                        yield chunk
                    return
                if 'clicky.teaching_output_observation' in prompt:
                    async for chunk in super().stream_response(*args, **kwargs):
                        yield chunk
                    return
                raise AssertionError('Lettering must use its scoped drawing stream')
                yield ''
            async def stream_drawing_response(self, prompt, images, history, system, model=None):
                self.inputs.append((json.loads(prompt), images, system))
                if len(self.inputs) == 1:
                    yield json.dumps({**DRAW_CURVES, 'component_id': 'lesson-main'})
                    raise LimitError('output limit')
                command = next(self.commands)
                if isinstance(command, dict) and command.get('tool') == 'inknotes_draw_curves':
                    command = {**command, 'component_id': 'lesson-main'}
                yield json.dumps(command)
        client = LetterClient()
        provider = DrawingProvider([DRAW_CURVES, DONE, DONE])
        status = await write_explanation(client, provider, 'm', 'Draw the letters',
                                         'answer', lambda: True)
        self.assertIn('model inspected', status)
        self.assertEqual(len([name for name, _ in client.calls if name == 'inknotes_draw_curves']), 1)

    async def test_modern_lettering_catalog_uses_curves_instead_of_sparse_point_paths(self):
        provider = Provider([DRAW_STROKES])
        client = LetterClient()
        with self.assertRaisesRegex(RuntimeError, 'unavailable notebook tool'):
            await write_explanation(client, provider, 'm', 'Draw the letters', 'answer', lambda: True)
        catalog = json.loads(provider.inputs[0][2].split('Tools: ', 1)[1])
        self.assertIn('inknotes_draw_curves', {tool['name'] for tool in catalog})
        self.assertNotIn('inknotes_draw_strokes', {tool['name'] for tool in catalog})
        self.assertFalse(any(name == 'inknotes_draw_strokes' for name, _ in client.calls))

    async def test_original_reference_images_survive_crops_with_bounded_memory(self):
        client = LetterClient()
        client.page['strokes'] = [{'stroke_id': 'learner', 'bounds': {'x': 10, 'y': 10, 'width': 150, 'height': 30}}]
        reads = [{'tool': 'inknotes_read_page', 'arguments': {
            'region': {'x': i * 20, 'y': 10, 'width': 40, 'height': 40}}} for i in range(6)]
        provider = Provider(reads + [DRAW_CURVES, DRAW_CURVES, DONE, DONE])
        status = await write_explanation(client, provider, 'm', 'Draw the letters', 'answer', lambda: True)
        self.assertIn('source ink', status)
        references = provider.inputs[6][0]['source_reference_images']
        self.assertEqual(len(references), 2)
        self.assertEqual(references[0]['kind'], 'original_full_page')
        self.assertEqual([item['image_coordinates']['crop']['x'] for item in references[1:]], [100])
        # The current full page remains attached alongside the last native
        # detail crop, then the bounded original references follow.
        self.assertEqual(len(provider.inputs[6][1]), 4)
        self.assertEqual(provider.inputs[-1][0]['source_reference_images'], references)

    async def test_removed_pen_shape_does_not_satisfy_drawing_request(self):
        status=await write_explanation(Client(),Provider([{'tool':'inknotes_annotate','arguments':{'shape':'ellipse'}},
            {'tool':'inknotes_remove_annotation','arguments':{'annotation_id':'a'}},DONE]),'m','Circle this term','answer',lambda:True)
        self.assertIn('requested pen drawing is incomplete',status)
    def test_geometry_is_bounded_and_retains_transform(self):
        page={'strokes':[{'stroke_id':str(i)} for i in range(500)],'image_coordinates':{'space':'page'}}
        bounded=planning_page(page)
        self.assertEqual(len(bounded['strokes']),160)
        self.assertTrue(bounded['strokes_truncated'])
        self.assertEqual(bounded['image_coordinates'],page['image_coordinates'])

if __name__=='__main__':unittest.main()
