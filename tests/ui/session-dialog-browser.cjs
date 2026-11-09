'use strict';
// Synthetic origin/session fixture; no gateway, user credentials or services.
const {chromium}=require('playwright');
const http=require('node:http');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const component=fs.readFileSync(path.join(__dirname,'../../internal/dashboard/session-view-dialog.html'),'utf8');
const html='<html><body><h1>Administration</h1><a id="view" href="/admin/impersonate?as=alice">View Alice</a> '+
 '<a id="self" href="/admin/impersonate?as=admin">My view as user</a> '+
 '<a id="team" href="/admin/impersonate?as=alice&to=/manager">View team</a> '+
 '<a id="back" href="/admin/impersonate">Back to admin view</a>'+component+'</body></html>';
(async()=>{
 const writes=[];let confirmationGets=0,base;const errors=[];
 const server=http.createServer((request,response)=>{
  const url=new URL(request.url,base);
  if(url.pathname==='/admin/impersonate'){
   if(request.method==='GET'){confirmationGets++;response.end('Fallback confirmation');return;}
   assert.equal(request.method,'POST');assert.equal(request.headers.origin,base);
   writes.push({as:url.searchParams.get('as'),to:url.searchParams.get('to')});
   response.writeHead(302,{location:url.searchParams.get('to')==='/manager'?'/manager':'/dashboard'});response.end();return;
  }
  response.writeHead(200,{'Content-Type':'text/html'});response.end(html);
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));base='http://127.0.0.1:'+server.address().port;
 let browser,checks=0;
 try{
  browser=await chromium.launch();const page=await browser.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base+'/admin');
  const dialog=page.getByRole('dialog',{name:'Change dashboard view'});
  await page.locator('#view').click();await dialog.waitFor();
  assert.equal(new URL(page.url()).pathname,'/admin');assert.equal(writes.length,0);assert.equal(confirmationGets,0);
  assert.match(await dialog.textContent(),/personal usage as alice/);
  assert.equal(await page.evaluate(()=>document.activeElement.id),'session-view-cancel');
  await dialog.getByRole('button',{name:'Cancel'}).click();assert.equal(await dialog.isVisible(),false);
  assert.equal(await page.evaluate(()=>document.activeElement.id),'view');assert.equal(writes.length,0);checks++;
  await page.locator('#self').click();assert.match(await dialog.textContent(),/personal usage as admin/);
  await page.keyboard.press('Escape');assert.equal(await dialog.isVisible(),false);assert.equal(writes.length,0);checks++;
  await page.locator('#team').click();assert.match(await dialog.textContent(),/team usage as alice/);
  await Promise.all([page.waitForURL('**/manager'),dialog.getByRole('button',{name:'Continue'}).click()]);
  assert.deepEqual(writes.at(-1),{as:'alice',to:'/manager'});checks++;
  await page.locator('#back').click();assert.match(await dialog.textContent(),/Return to your administrator/);
  assert.equal(await page.locator('#session-view-scope').isVisible(),false);
  await Promise.all([page.waitForURL('**/dashboard'),dialog.getByRole('button',{name:'Continue'}).click()]);
  assert.deepEqual(writes.at(-1),{as:null,to:null});checks++;
  // URL-derived identity is text only and return destinations stay allowlisted.
  await page.locator('#view').evaluate(link=>link.href='/admin/impersonate?as='+encodeURIComponent('<img src=x onerror=alert(1)>')+'&to=https://attacker.invalid');
  await page.locator('#view').click();assert.equal(await dialog.locator('img').count(),0);
  assert.match(await dialog.textContent(),/<img src=x onerror=alert\(1\)>/);
  assert.equal(new URL(await page.locator('#session-view-form').getAttribute('action'),page.url()).searchParams.has('to'),false);
  await dialog.getByRole('button',{name:'Cancel'}).click();checks++;
  await page.locator('#self').click();const before=writes.length;
  await Promise.all([page.waitForEvent('framenavigated'),page.locator('#session-view-form').evaluate(form=>{form.requestSubmit();form.requestSubmit();})]);
  await page.waitForLoadState();assert.equal(writes.length,before+1);checks++;
  // Alternate navigation still uses the server's GET confirmation fallback.
  await page.locator('#view').evaluate(link=>link.target='_blank');
  const popupPromise=page.waitForEvent('popup');await page.locator('#view').click();const popup=await popupPromise;
  await popup.waitForLoadState();assert.equal(confirmationGets,1);assert.equal(writes.length,before+1);await popup.close();checks++;
  await page.locator('#self').click();
  await page.screenshot({path:'/tmp/pricetag-view-dialog-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>{const rect=document.getElementById('session-view-dialog').getBoundingClientRect();return rect.left>=16&&rect.right<=window.innerWidth-16;}),true);
  await page.screenshot({path:'/tmp/pricetag-view-dialog-mobile.png',fullPage:true});checks++;
  assert.deepEqual(errors,[]);
  console.log('PASS: '+checks+' impersonation confirmation browser scenarios');
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
