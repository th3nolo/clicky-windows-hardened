import asyncio
import base64
import json
import unittest
from automation.inknotes_mcp import write_explanation, planning_page

IMAGE = {'type':'image','mimeType':'image/jpeg','data':base64.b64encode(b'jpeg-fixture').decode()}
def result(page):
    return {'content':[{'type':'text','text':json.dumps(page)}, IMAGE]}

class Client:
    def __init__(self):
        self.page = dict(notebook_id='n',page_id='p',revision=0,width=1000,height=1000,
                         saved=False,has_save_location=True,handwritten_notes=[],teaching_annotations=[])
        self.calls=[]
        self.change_before_write=False
    async def request(self, method):
        return {'tools':[{'name':n,'inputSchema':{}} for n in ['inknotes_read_page','inknotes_annotate','inknotes_write_at','inknotes_remove_annotation','inknotes_save','inknotes_add_handwriting']]}
    async def call(self,name,arguments=None):
        self.calls.append((name,dict(arguments or {})))
        if name=='inknotes_read_page':
            if self.change_before_write and len(self.calls)==2: self.page['revision']+=1
            return result(self.page)
        self.page['revision']+=1
        if name=='inknotes_save': self.page['saved']=True
        else:
            self.page['teaching_annotations'].append({'id':'a','complete':True})
        return result({'annotation_id':'a','page':self.page})

class Provider:
    def __init__(self,commands): self.commands=iter(commands);self.inputs=[]
    async def stream_response(self,prompt,images,history,system,model=None):
        self.inputs.append((json.loads(prompt),images,system))
        yield json.dumps(next(self.commands))

DONE={'done':True,'checklist':dict(mathematics=True,targets=True,legibility=True,complete=True),'assessment':'Correct blue circle and explanation, readable.'}
WRITE={'tool':'inknotes_write_at','arguments':{'text':'2+2=4','x':10,'y':10,'width':200},'narration':'Two plus two equals four.'}
class TeachingTests(unittest.IsolatedAsyncioTestCase):
    async def test_images_revisions_callbacks_and_readback(self):
        client=Client();provider=Provider([WRITE,{'tool':'inknotes_save','arguments':{}},DONE]);events=[]
        async def event(value):events.append(value)
        status=await write_explanation(client,provider,'m','Explain','2+2=4',lambda:True,on_event=event)
        self.assertIn('model inspected',status);self.assertIn('notebook is saved',status)
        self.assertTrue(all(images for _,images,_ in provider.inputs))
        self.assertEqual(events[0]['narration'],'Two plus two equals four.')
        writes=[args for name,args in client.calls if name=='inknotes_write_at']
        self.assertEqual(writes[0]['revision'],0)
        self.assertTrue(writes[0]['operation_id'])
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
                nonlocal active
                active=False
                yield json.dumps(WRITE)
        client=Client()
        status=await write_explanation(client,CancelProvider(),'m','Explain','x',lambda:active)
        self.assertIn('stopped',status)
        self.assertFalse(any(n=='inknotes_write_at' for n,_ in client.calls))
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
    async def test_crop_requires_full_page_assessment_turn(self):
        client=Client();provider=Provider([WRITE,{'tool':'inknotes_read_page','arguments':{'region':{'x':0,'y':0,'width':20,'height':20}}},DONE,DONE])
        status=await write_explanation(client,provider,'m','Explain','x',lambda:True)
        self.assertIn('model inspected',status)
        self.assertEqual(len(provider.inputs),4)
        self.assertIn('FULL PAGE',provider.inputs[-1][0]['last_result']['instruction'])
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
    def test_geometry_is_bounded_and_retains_transform(self):
        page={'strokes':[{'stroke_id':str(i)} for i in range(500)],'image_coordinates':{'space':'page'}}
        bounded=planning_page(page)
        self.assertEqual(len(bounded['strokes']),160)
        self.assertTrue(bounded['strokes_truncated'])
        self.assertEqual(bounded['image_coordinates'],page['image_coordinates'])

if __name__=='__main__':unittest.main()
