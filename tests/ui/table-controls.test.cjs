'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
function controls(){
 const context=vm.createContext({Date});
 for(const file of ['management-key-controls.js','management-table-controls.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../../internal/dashboard',file),'utf8'),context);
 return vm.runInContext('({KeyControls,TableControls})',context);
}
test('key search covers names and IDs, combines status, sorts active first and never mutates records',()=>{
 const {TableControls:t}=controls();const now=Date.parse('2026-10-31T12:00:00Z');
 const keys=[{id:'old',name:'Laptop',status:'revoked'},{id:'expired',name:'Laptop',status:'active',expiresAt:'2026-10-30T00:00:00Z'},
 {id:'active-2',name:'Laptop',status:'active',expiresAt:'2026-11-01T00:00:00Z'},{id:'active-1',name:'Desktop',status:'active'}];
 assert.deepEqual(Array.from(t.filterKeys(keys,' LAPTOP ','all',now),k=>k.id),['active-2','old','expired']);
 for(const status of ['active','expired','revoked'])assert.equal(t.filterKeys(keys,'laptop',status,now).length,1);
 assert.equal(t.filterKeys(keys,'ACTIVE-1','active',now)[0].name,'Desktop');
 assert.equal(t.filterKeys(keys,'missing','all',now).length,0);
 assert.equal(keys[1].status,'active');assert.equal(keys[0].id,'old');
});
test('pagination clamps empty and shortened results and reports exact page boundaries',()=>{
 const t=controls().TableControls;
 let p=t.page(Array.from({length:11},(_,i)=>i),5,5);assert.equal(p.offset,5);assert.deepEqual(Array.from(p.rows),[5,6,7,8,9]);assert.equal(p.hasMore,true);
 p=t.page([1,2,3,4,5],10,5);assert.equal(p.offset,0);assert.equal(p.hasMore,false);
 p=t.page([],5,5);assert.equal(p.offset,0);assert.equal(p.rows.length,0);
 assert.throws(()=>t.page([1,2,3],0,0),/invalid page size/i);
 assert.throws(()=>t.page([1,2,3],0,-1),/invalid page size/i);
 assert.throws(()=>t.page([1,2,3],0,NaN),/invalid page size/i);
});
test('key loader returns the complete server-side list and rejects malformed responses',async()=>{
 const t=controls().TableControls;const calls=[];
 const keys=await t.loadKeys(async url=>{calls.push(url);return {data:[{id:'first'},{id:'second'}]};});
 assert.equal(keys.length,2);assert.match(calls[0],/\/me\/keys$/);
 await assert.rejects(t.loadKeys(async()=>({data:null})),/invalid/i);
 await assert.rejects(t.loadKeys(async()=>({data:[{id:'ok'},{no:'id'}]})),/invalid key metadata/i);
 await assert.rejects(t.loadKeys(async()=>({data:[{id:'ok'}],has_more:true})),/truncated/i);
 await assert.rejects(t.loadKeys(async()=>{throw new Error('HTTP 503');}),/503/);
});
