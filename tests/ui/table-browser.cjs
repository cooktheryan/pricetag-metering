'use strict';
// Browser behavior tests against deterministic, credential-free API fixtures.
// Run with Playwright available through NODE_PATH; no live services are touched.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const dir=path.join(__dirname,'../../internal/dashboard');
const controls=['management-key-controls.js','management-table-controls.js'].map(f=>fs.readFileSync(path.join(dir,f),'utf8')).join('\n');
const personal=fs.readFileSync(path.join(dir,'account.html'),'utf8').replace('/* ACCOUNT_KEY_CONTROLS */',controls);
const tick=()=>new Promise(r=>setTimeout(r,0));
(async()=>{
 const browser=await chromium.launch();let checks=0;
 try{
  const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));

  let keys=Array.from({length:53},(_,i)=>({id:'key-'+i,name:'Client '+String(i).padStart(2,'0'),status:'active',username:'alice',expirationDate:'2099-01-01T00:00:00Z'}));
  keys.push({id:'revoked',name:'Old laptop',status:'revoked'}, {id:'expired',name:'Expired laptop',status:'active',expirationDate:'2000-01-01T00:00:00Z'}, {id:'html',name:'<img src=x onerror=alert(1)>',status:'revoked'});
  let fail=false,blocked=false,requests=0,creates=0,releaseCreate;
  await page.route('https://fixture.invalid/**',async route=>{
   const url=new URL(route.request().url()),method=route.request().method();
   if(url.pathname==='/account')return route.fulfill({contentType:'text/html',body:personal});
   if(url.pathname==='/api/v1/whoami')return route.fulfill({json:{user:'alice',display_name:'Alice',keyServiceEnabled:true,impersonating:blocked}});
   if(url.pathname==='/api/v1/me/keys'&&method==='POST'){
    creates++;const input=route.request().postDataJSON();
    await new Promise(r=>releaseCreate=r);
    keys.push({id:'created',name:input.name,status:'active',expirationDate:'2099-01-01T00:00:00Z'});
    return route.fulfill({json:{id:'created',key:'fixture-only-key'}});
   }
   if(url.pathname==='/api/v1/me/keys'&&method==='GET')return fail?route.fulfill({status:503,body:'unavailable'}):route.fulfill({json:{data:keys}});
   if(url.pathname.startsWith('/api/v1/me/keys/')&&method==='DELETE'){
    requests++;keys.find(k=>k.id===url.pathname.split('/').pop()).status='revoked';return route.fulfill({status:204});
   }
   if(url.pathname.endsWith('/summary'))return route.fulfill({json:{overview:{},quota:{limit_usd:5,spent_usd:1}}});
   if(url.pathname.endsWith('/models')||url.pathname.endsWith('/recent'))return route.fulfill({json:[]});
   return route.fulfill({status:404});
  });
  await page.goto('https://fixture.invalid/account?tab=keys');
  await page.locator('#key-pages .page-label').getByText('Page 1 of 11 · 53 results',{exact:true}).waitFor();
  assert.equal(await page.locator('#key-rows tr').count(),5);
  assert.equal(await page.locator('#account-impersonation').isVisible(),false);checks++;
  await page.locator('#key-pages').getByRole('button',{name:'Next',exact:true}).click();assert.match(await page.locator('#key-pages').textContent(),/Page 2 of 11/);
  await page.locator('#key-search').fill('client 52');await page.getByText('Client 52',{exact:true}).waitFor();
  assert.match(await page.locator('#key-pages').textContent(),/Page 1 of 1 · 1 results/);checks++;
  await page.locator('#key-state').selectOption('expired');assert.equal(await page.locator('#key-rows tr').count(),0);
  await page.locator('#key-search').fill('');await page.getByText('Expired laptop',{exact:true}).waitFor();
  assert.equal(await page.locator('#key-rows button').count(),0);
  await page.locator('#key-state').selectOption('revoked');await page.getByText('Old laptop',{exact:true}).waitFor();
  assert.equal(await page.locator('#key-rows img').count(),0);assert.equal(await page.locator('#key-rows tr').count(),2);
  await page.locator('#key-state').selectOption('all');assert.equal(await page.locator('#key-rows .pill').first().textContent(),'active');
  await page.locator('#key-size').selectOption('20');assert.equal(await page.locator('#key-rows tr').count(),20);checks++;
  await page.locator('#key-state').selectOption('active');await page.locator('#key-search').fill('key-52');await page.getByText('Client 52',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Revoke',exact:true}).click();
  await page.locator('#revoke-overlay').getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(requests,0);
  await page.getByRole('button',{name:'Revoke',exact:true}).click();await page.locator('#revoke-confirm').click();
  await page.waitForFunction(()=>document.querySelectorAll('#key-rows tr').length===0);
  assert.equal(requests,1);await page.locator('#key-state').selectOption('revoked');await page.getByText('Client 52',{exact:true}).waitFor();checks++;
  fail=true;await page.locator('#keys-refresh').click();await page.getByText('Could not load your keys.',{exact:true}).waitFor();
  fail=false;await page.locator('#keys-refresh').click();await page.getByText('Client 52',{exact:true}).waitFor();checks++;
  await page.locator('#create-btn').click();await page.locator('#key-name').fill('New device');
  await page.locator('#key-expiry').selectOption('custom');await page.locator('#custom-expiry').fill('24h');
  await page.locator('#create-submit').evaluate(b=>{b.click();b.click();});
  await page.waitForFunction(()=>document.querySelector('#create-submit').disabled);
  const createDeadline=Date.now()+15000;while(!releaseCreate){if(Date.now()>createDeadline)throw new Error('key creation request was not emitted');await tick();}assert.equal(creates,1);releaseCreate();
  await page.locator('#reveal-step').waitFor();assert.equal((await page.content()).includes('fixture-only-key'),false);
  const pending=page.waitForEvent('download');await page.locator('#reveal-download').click();
  const download=await pending;assert.equal(download.suggestedFilename(),'alice-New-device-pricetag.key');await download.delete();
  await page.locator('#reveal-saved').check();await page.locator('#reveal-done').click();checks++;
  blocked=true;await page.reload();await page.locator('#account-impersonation').waitFor();
  assert.equal(await page.locator('#create-btn').isDisabled(),true);assert.equal(await page.locator('#key-rows button').count(),0);checks++;
  blocked=false;await page.reload();await page.locator('#key-pages').waitFor();
  const shots=fs.mkdtempSync(path.join(os.tmpdir(),'pricetag-account-'));
  await page.screenshot({path:path.join(shots,'account-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
  await page.screenshot({path:path.join(shots,'account-mobile.png'),fullPage:true});checks++;
  assert.deepEqual(errors,[]);
  const admin=await browser.newPage();admin.on('pageerror',e=>errors.push(e.message));
  const fragments=['users','keys','budgets','prices'].map(name=>fs.readFileSync(path.join(dir,'management-admin-'+name+'.html'),'utf8')).join('');
  const script=fs.readFileSync(path.join(dir,'management-admin-script.html'),'utf8').replace('/* KEY_CONTROLS */',controls);
  const adminHTML='<html><meta charset="utf-8"><body>'+fragments+'<p id="status" hidden></p><div id="partner-detail-body"></div><script>const activeTab="people",partnerUsersAll=[];const notices=[];function showToast(message,kind){notices.push({message,kind});}function loadPartnerUsers(){}</script>'+script+'</body></html>';
  let budgets=Array.from({length:6},(_,i)=>({principal:'member-'+i,monthly_usd:5,updated_at:'2026-10-31T00:00:00Z'}));
  const prices=Array.from({length:12},(_,i)=>({Model:'model-'+i,Provider:'fixture',InputCost:1,OutputCost:2,CacheWriteCost:0,CacheReadCost:0}));
  let staleBudget,holdBudget=false;
  await admin.route('https://fixture.invalid/**',async route=>{
   const u=new URL(route.request().url());
   if(u.pathname==='/admin')return route.fulfill({contentType:'text/html',body:adminHTML});
   if(u.pathname.endsWith('/users'))return route.fulfill({json:[{logins:['member-0'],tags:{first_name:'Member'},active:true}]});
   if(u.pathname.endsWith('/prices'))return route.fulfill({json:prices});
   if(u.pathname.endsWith('/keys'))return route.fulfill({json:{keys}});
   if(u.pathname.endsWith('/budgets')){
    if(route.request().method()==='DELETE'){budgets=budgets.filter(b=>b.principal!==route.request().postDataJSON().subject);return route.fulfill({json:{}});}
    const term=u.searchParams.get('search')||'',offset=Number(u.searchParams.get('offset')),size=Number(u.searchParams.get('limit')||20);
    const filtered=budgets.filter(b=>b.principal.includes(term)),data=filtered.slice(offset,offset+size);
    if(holdBudget&&offset===5){holdBudget=false;await new Promise(r=>staleBudget=r);}
    return route.fulfill({json:{data,has_more:offset+size<filtered.length,default_monthly_usd:5}});
   }
   return route.fulfill({status:404});
  });
  await admin.goto('https://fixture.invalid/admin');
  await admin.locator('#listPrices').click();await admin.locator('#pricePages .page-label').getByText('Page 1 of 3 · 12 results',{exact:true}).waitFor();
  await admin.locator('#pricePages').getByRole('button',{name:'Next'}).click();assert.match(await admin.locator('#pricePages').textContent(),/Page 2/);
  await admin.locator('#priceSearch input').fill('MODEL-11');await admin.getByText('model-11',{exact:true}).waitFor();assert.match(await admin.locator('#pricePages').textContent(),/Page 1 of 1/);
  await admin.locator('#priceSearch input').fill('missing');await admin.getByText('No matching models.',{exact:true}).waitFor();
  await admin.locator('#priceSearch input').fill('');await admin.locator('#pricePageSize').selectOption('20');await admin.getByText('model-0',{exact:true}).waitFor();assert.match(await admin.locator('#pricePages').textContent(),/Page 1 of 1/);checks++;
  await admin.locator('#listBudgets').click();await admin.locator('#budgetPages .page-label').getByText('Page 1',{exact:true}).waitFor();
  assert.equal(await admin.locator('#budgets tr').count(),6);
  await admin.locator('#budgetPages').getByRole('button',{name:'Next'}).click();await admin.locator('#budgetPages .page-label').getByText('Page 2',{exact:true}).waitFor();
  assert.equal(await admin.evaluate(()=>notices.filter(n=>n.kind==='success').length),0);
  admin.once('dialog',d=>d.accept());await admin.locator('#budgets').getByRole('button',{name:'Remove override'}).click();
  await admin.locator('#budgetPages .page-label').getByText('Page 1',{exact:true}).waitFor();assert.equal(await admin.locator('#budgets tr').count(),6);checks++;
  await admin.locator('#budgetSearch input').fill('member-4');await admin.waitForFunction(()=>document.querySelectorAll('#budgets tr').length===2);
  assert.match(await admin.locator('#budgetPages').textContent(),/Page 1/);
  await admin.locator('#budgetSearch input').fill('missing');await admin.getByText('No matching overrides.',{exact:true}).waitFor();checks++;
  budgets.push({principal:'member-5',monthly_usd:5,updated_at:'2026-10-31T00:00:00Z'});
  await admin.locator('#budgetSearch input').fill('');await admin.waitForFunction(()=>document.querySelectorAll('#budgets tr').length===6);
  holdBudget=true;await admin.locator('#budgetPages').getByRole('button',{name:'Next'}).click();
  const staleDeadline=Date.now()+15000;while(!staleBudget){if(Date.now()>staleDeadline)throw new Error('stale budget response was not held');await tick();}
  await admin.locator('#budgetSearch input').fill('member-0');await admin.waitForFunction(()=>document.querySelectorAll('#budgets tr').length===2);
  staleBudget();await new Promise(r=>setTimeout(r,100));assert.match(await admin.locator('#budgets').textContent(),/member-0/);assert.doesNotMatch(await admin.locator('#budgets').textContent(),/member-5/);checks++;
  await admin.evaluate(()=>loadManagedUserKeys({user_id:'fixture-user',logins:['alice']}));
  const detail=admin.locator('#partner-detail-body');
  await detail.getByText(/Page 1 of /).waitFor();
  await detail.getByRole('button',{name:'Next',exact:true}).click();assert.match(await detail.textContent(),/Page 2 of /);
  await detail.getByLabel('Search name or key ID',{exact:true}).fill('key-51');
  assert.match(await detail.textContent(),/Page 1 of 1/);assert.equal(await detail.locator('tr').count(),2);checks++;
  assert.deepEqual(errors,[]);
  console.log('PASS: '+checks+' personal-key and administration-table browser scenarios');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
