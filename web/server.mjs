import http from 'node:http';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');
const port = Number(process.env.PORT || 4173);
const command = process.env.SBPF_EYE_BIN || path.resolve(root, '../bridge/target/release/sbpf-eye-web-bridge');
const argTemplate = JSON.parse(process.env.SBPF_EYE_ARGS_JSON || '["{file}","--stream"]');
const contentTypes = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
function send(res,status,body,type='application/json'){res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(type==='application/json'?JSON.stringify(body):body)}
async function execute(bytes){
  const dir=await mkdtemp(path.join(os.tmpdir(),'sbpf-eye-'));
  const file=path.join(dir,'input.so');
  try {
    await writeFile(file,bytes);
    return await new Promise(resolve=>{
      const args=argTemplate.map(x=>x.replaceAll('{file}',file));
      let stdout='',stderr='',killed=false,outputLimited=false,lastReport=null;
      const child=spawn(command,args,{shell:false,stdio:['ignore','pipe','pipe']});
      const timeout=setTimeout(()=>{killed=true;child.kill('SIGKILL')},30000);
      child.stdout.setEncoding('utf8');
      child.stdout.on('data',c=>{
        stdout+=c;
        let newline;
        while((newline=stdout.indexOf('\n'))!==-1){
          const line=stdout.slice(0,newline); stdout=stdout.slice(newline+1);
          try{lastReport=JSON.parse(line)}catch{}
        }
        if(stdout.length>64*1024*1024){outputLimited=true;stdout='';child.kill('SIGKILL')}
      });
      child.stderr.on('data',c=>{stderr+=c.toString();if(stderr.length>1e6){outputLimited=true;child.kill('SIGKILL')}});
      child.on('error',e=>{clearTimeout(timeout);resolve({ok:false,error:e.message})});
      child.on('close',code=>{
        clearTimeout(timeout);
        let json=lastReport;try{json=JSON.parse(stdout)}catch{}
        const error=outputLimited?'Analysis output exceeded 64 MiB limit':killed?'Analysis timed out after 30 seconds':code!==0?`Analysis process exited (${code})`:null;
        if(json?.schemaVersion===1 && error){
          json.stages=json.stages.filter(s=>s.status!=='pending');
          json.stages.push({name:'analysis',engine:'sbpfEye',status:'error',message:error+'; low-level checkpoint retained'});
        }
        resolve({ok:json?.schemaVersion===1,exitCode:code,timedOut:killed,outputLimited,error,stderr:stderr.slice(0,1e6),json});
      });
    });
  } finally {await rm(dir,{recursive:true,force:true})}
}
const server = http.createServer(async (req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(req.method==='POST'&&url.pathname==='/api/analyze'){
    let parts=[],size=0;try{
      for await(const part of req){size+=part.length;if(size>8*1024*1024){send(res,413,{error:'Binary exceeds 8 MiB limit'});return}parts.push(part)}
      const bytes=Buffer.concat(parts);
      send(res,200,await execute(bytes));
    }catch(e){send(res,500,{error:String(e.message||e)})}return;
  }
  if(req.method!=='GET'){send(res,405,{error:'Method not allowed'});return}
  try{const pathname=url.pathname==='/'?'/index.html':decodeURIComponent(url.pathname);const resolved=path.resolve(root,'.'+pathname);if(!resolved.startsWith(root+path.sep)){send(res,403,{error:'Forbidden'});return}const data=await readFile(resolved);send(res,200,data,contentTypes[path.extname(resolved)]||'application/octet-stream')}catch{send(res,404,{error:'Not found'})}
});
server.listen(port,'127.0.0.1',()=>console.log(`sbpf-eye web running at http://127.0.0.1:${server.address().port}`));
