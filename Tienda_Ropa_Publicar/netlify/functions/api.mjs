import {getStore} from '@netlify/blobs';
import {configured,equal,token,authorized,sameOrigin,validate} from '../../server/security.mjs';
import seed from '../../server/seed.json' with {type:'json'};
const json=(d,status=200,headers={})=>new Response(JSON.stringify(d),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store',...headers}});
export default async function(req,context){try{const url=new URL(req.url),action=url.searchParams.get('action')||'catalog';
if(req.method==='GET'&&action==='session')return json({authenticated:authorized(req),configured:configured()});
if(!['GET','POST','PUT','DELETE'].includes(req.method))return json({error:'Método no permitido'},405);
if(req.method!=='GET'&&!sameOrigin(req))return json({error:'Origen no permitido'},403);
if(action==='session'&&req.method==='POST'){if(!configured())return json({error:'Configura ADMIN_USER, ADMIN_PASSWORD y SESSION_SECRET en Netlify.'},503);let {user,password}=await req.json();if(!equal(user,process.env.ADMIN_USER)||!equal(password,process.env.ADMIN_PASSWORD))return json({error:'Usuario o contraseña incorrectos'},401);return json({ok:true},200,{'Set-Cookie':'__Host-atelier='+token()+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800'})}
if(action==='session'&&req.method==='DELETE')return json({ok:true},200,{'Set-Cookie':'__Host-atelier=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'});
if(action!=='catalog')return json({error:'No encontrado'},404);
const store=getStore({name:'atelier-catalog',consistency:'strong'});
if(req.method==='GET')return json(await store.get('catalog',{type:'json'})||{...seed,revision:0});
if(req.method==='PUT'){if(!authorized(req))return json({error:'Inicia sesión nuevamente'},401);const body=await req.text();if(Buffer.byteLength(body)>4000000)return json({error:'Catálogo demasiado grande. Reduce las fotos o cantidad de productos.'},413);const d=validate(JSON.parse(body));const current=await store.getWithMetadata('catalog',{type:'json'});if((current?.data?.revision||0)!==d.revision)return json({error:'El catálogo cambió. Recarga antes de editar.'},409);const next={settings:d.settings,products:d.products,revision:Date.now()};const result=await store.setJSON('catalog',next,current?{onlyIfMatch:current.etag}:{onlyIfNew:true});if(result?.modified===false)return json({error:'Otra edición guardó primero. Recarga la página.'},409);return json(next)}return json({error:'Método no permitido'},405)
}catch(e){console.error('API error',e.message);return json({error:'No se pudo completar la operación. Revisa la configuración o el formato del catálogo.'},500)}}
export const config={rateLimit:{windowLimit:60,windowSize:60,aggregateBy:['ip','domain']}};
