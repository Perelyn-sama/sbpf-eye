const TYPES={0:'NULL',1:'PROGBITS',2:'SYMTAB',3:'STRTAB',4:'RELA',5:'HASH',6:'DYNAMIC',7:'NOTE',8:'NOBITS',9:'REL',11:'DYNSYM',14:'INIT_ARRAY',15:'FINI_ARRAY'};
const R_BPF={0:'R_BPF_NONE',1:'R_BPF_64_64',2:'R_BPF_64_ABS64',3:'R_BPF_64_ABS32',4:'R_BPF_64_NODYLD32',8:'R_BPF_64_RELATIVE',10:'R_BPF_64_32'};
const hex=n=>'0x'+n.toString(16).padStart(4,'0');
export function parseELF(bytes){
  if(bytes.length<64||bytes[0]!==127||String.fromCharCode(...bytes.slice(1,4))!=='ELF')throw Error('Not an ELF file');
  if(bytes[4]!==2)throw Error('Only ELF64 is supported in this MVP');
  if(bytes[5]!==1)throw Error('Only little-endian ELF64 is supported');
  const dv=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  const inBounds=(off,len=1)=>Number.isSafeInteger(off)&&off>=0&&Number.isSafeInteger(len)&&len>=0&&off<=bytes.length&&len<=bytes.length-off;
  const check=(off,len)=>{if(!inBounds(off,len))throw Error('ELF offset out of bounds: '+hex(off))};
  const u16=o=>(check(o,2),dv.getUint16(o,true));const u32=o=>(check(o,4),dv.getUint32(o,true));
  const u64=o=>{check(o,8);const n=dv.getBigUint64(o,true);if(n>BigInt(Number.MAX_SAFE_INTEGER))throw Error('ELF integer exceeds safe JavaScript precision');return Number(n)};
  const str=(base,size,off)=>{if(off>=size)return '<invalid>';let end=base+off;const limit=Math.min(base+size,bytes.length);if(!inBounds(end,0))return '<invalid>';while(end<limit&&bytes[end]!==0)end++;return new TextDecoder().decode(bytes.slice(base+off,end))};
  const header={type:u16(16),machine:u16(18),version:u32(20),entry:u64(24),programOffset:u64(32),sectionOffset:u64(40),flags:u32(48),headerSize:u16(52),programEntrySize:u16(54),programCount:u16(56),sectionEntrySize:u16(58),sectionCount:u16(60),sectionNamesIndex:u16(62)};
  if(header.sectionCount>0&&header.sectionEntrySize<64)throw Error('Invalid section-header entry size');
  if(header.programCount>0&&header.programEntrySize<56)throw Error('Invalid program-header entry size');
  const sections=[];for(let i=0;i<header.sectionCount;i++){
    const o=header.sectionOffset+i*header.sectionEntrySize;check(o,64);
    const s={index:i,nameOffset:u32(o),type:u32(o+4),flags:u64(o+8),address:u64(o+16),offset:u64(o+24),size:u64(o+32),link:u32(o+40),info:u32(o+44),alignment:u64(o+48),entrySize:u64(o+56)};
    if(s.type!==8)check(s.offset,s.size);sections.push(s)
  }
  const names=sections[header.sectionNamesIndex];for(const s of sections)s.name=names&&names.type===3?str(names.offset,names.size,s.nameOffset):`section_${s.index}`;
  const segments=[];for(let i=0;i<header.programCount;i++){const o=header.programOffset+i*header.programEntrySize;check(o,56);segments.push({index:i,type:u32(o),flags:u32(o+4),offset:u64(o+8),vaddr:u64(o+16),paddr:u64(o+24),fileSize:u64(o+32),memorySize:u64(o+40),alignment:u64(o+48)})}
  const symbolTables=new Map(),symbols=[];
  for(const s of sections.filter(s=>s.type===2||s.type===11)){
    const tab=[],namesSec=sections[s.link];if(!namesSec||!s.entrySize||s.entrySize<24)continue;
    const n=Math.min(Math.floor(s.size/s.entrySize),200000);
    for(let i=0;i<n;i++){const o=s.offset+i*s.entrySize;const sym={index:i,table:s.name,name:str(namesSec.offset,namesSec.size,u32(o)),binding:bytes[o+4]>>4,visibility:bytes[o+5]&3,type:bytes[o+4]&15,sectionIndex:u16(o+6),value:u64(o+8),size:u64(o+16)};tab.push(sym);symbols.push(sym)}symbolTables.set(s.index,tab)
  }
  const relocations=[];for(const s of sections.filter(s=>s.type===4||s.type===9)){
    const stride=s.entrySize||(s.type===4?24:16);if(stride<(s.type===4?24:16))continue;
    const tab=symbolTables.get(s.link)||[];const n=Math.min(Math.floor(s.size/stride),200000);
    for(let i=0;i<n;i++){const o=s.offset+i*stride;const info=dv.getBigUint64(o+8,true);const symbolIndex=Number(info>>32n);const type=Number(info&0xffffffffn);const addend=s.type===4?(check(o+16,8),dv.getBigInt64(o+16,true).toString()):null;
      relocations.push({section:s.name,index:i,offset:u64(o),type,typeName:R_BPF[type]||`UNKNOWN(${type})`,symbolIndex,symbol:tab[symbolIndex]?.name||'',addend,targetSection:sections[s.info]?.name||'',entryOffset:o});}
  }
  return {header,sections,segments,symbols,relocations,isBPF:header.machine===247,bytes};
}
export function dumpHex(bytes,offset,length=256){const out=[];const end=Math.min(bytes.length,offset+length);for(let p=offset;p<end;p+=16){const part=bytes.slice(p,Math.min(p+16,end));out.push({offset:p,hex:[...part].map(b=>b.toString(16).padStart(2,'0')).join(' '),ascii:[...part].map(b=>b>=32&&b<127?String.fromCharCode(b):'·').join('')})}return out}
export function parsePaste(value){const s=value.trim();if(!s)throw Error('Paste hexadecimal or base64 bytes');if(/^(?:0x)?[\da-fA-F\s,:_-]+$/.test(s)){const h=s.replace(/0x/gi,'').replace(/[\s,:_-]/g,'');if(h.length%2)throw Error('Hex must contain an even number of digits');return Uint8Array.from(h.match(/../g)||[],x=>parseInt(x,16))}try{return Uint8Array.from(atob(s.replace(/\s/g,'')),c=>c.charCodeAt(0))}catch{throw Error('Paste valid hex or base64')}}
