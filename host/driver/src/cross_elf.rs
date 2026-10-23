//! Closed input/output formats for the Windows-hosted Linux x64 linker.
//! In particular, objects cannot introduce linker scripts, dependency lists,
//! LTO plugins or undefined library imports.
use std::io;
fn invalid()->io::Error {io::Error::new(io::ErrorKind::InvalidInput,"unsupported or malformed Kelft cross-link ELF")}
fn u16_at(b:&[u8],at:usize)->io::Result<u16>{Ok(u16::from_le_bytes(b.get(at..at+2).ok_or_else(invalid)?.try_into().unwrap()))}
fn u32_at(b:&[u8],at:usize)->io::Result<u32>{Ok(u32::from_le_bytes(b.get(at..at+4).ok_or_else(invalid)?.try_into().unwrap()))}
fn u64_at(b:&[u8],at:usize)->io::Result<u64>{Ok(u64::from_le_bytes(b.get(at..at+8).ok_or_else(invalid)?.try_into().unwrap()))}
fn range(b:&[u8],start:u64,size:u64)->io::Result<&[u8]>{
 let end=start.checked_add(size).ok_or_else(invalid)?;
 if end>b.len() as u64 {return Err(invalid());}Ok(&b[start as usize..end as usize])
}
fn header(b:&[u8],kind:u16)->io::Result<()> {
 if b.len()<64||b.len()>64<<20||b[..16]!=[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0]||u16_at(b,16)?!=kind||u16_at(b,18)?!=62||u32_at(b,20)?!=1||u32_at(b,48)?!=0||u16_at(b,52)?!=64 {return Err(invalid());}Ok(())
}
fn name(table:&[u8],at:u32)->io::Result<&[u8]>{
 let tail=table.get(at as usize..).ok_or_else(invalid)?;let end=tail.iter().position(|b|*b==0).ok_or_else(invalid)?;
 if end>4096{return Err(invalid());}Ok(&tail[..end])
}
pub fn validate_object(b:&[u8])->io::Result<()> {
 header(b,1)?;
 if u64_at(b,24)?!=0||u64_at(b,32)?!=0||u16_at(b,54)?!=0||u16_at(b,56)?!=0||u16_at(b,58)?!=64||u16_at(b,60)?!=11||u16_at(b,62)?!=9{return Err(invalid());}
 let table=u64_at(b,40)?;if table<64||table%8!=0||table.checked_add(11*64)!=Some(b.len() as u64){return Err(invalid());}
 let at=table as usize;let names=range(b,u64_at(b,at+9*64+24)?,u64_at(b,at+9*64+32)?)?;
 let expected:[(&[u8],u32,u64,u64,u32,u32,u64);11]=[
  (b"",0,0,0,0,0,0),(b".text",1,6,16,0,0,0),(b".rodata",1,2,8,0,0,0),
  (b".kelft.native",1,2,1,0,0,0),(b".eh_frame",1,2,8,0,0,0),
  (b".rela.text",4,0,8,7,1,24),(b".rela.eh_frame",4,0,8,7,4,24),
  (b".symtab",2,0,8,8,2,24),(b".strtab",3,0,1,0,0,0),
  (b".shstrtab",3,0,1,0,0,0),(b".note.GNU-stack",1,0,1,0,0,0)];
 let mut sections:Vec<&[u8]>=vec![];let mut previous=64;
 for (index,(label,kind,flags,align,link,info,entry)) in expected.into_iter().enumerate(){
  let s=at+index*64;let start=u64_at(b,s+24)?;let size=u64_at(b,s+32)?;
  if name(names,u32_at(b,s)?)?!=label||u32_at(b,s+4)?!=kind||u64_at(b,s+8)?!=flags||u64_at(b,s+16)?!=0||u32_at(b,s+40)?!=link||u32_at(b,s+44)?!=info||u64_at(b,s+48)?!=align||u64_at(b,s+56)?!=entry {return Err(invalid());}
  if index==0 {if start!=0||size!=0{return Err(invalid());}}
  else {let end=start.checked_add(size).ok_or_else(invalid)?;if start<previous||start%align!=0||end>table||entry!=0&&size%entry!=0{return Err(invalid());}previous=end;}
  sections.push(range(b,start,size)?);
 }
 if sections[1].is_empty()||!sections[10].is_empty()||sections[7].len()<48||sections[7][..24]!=[0;24]||sections[8].first()!=Some(&0)||names.first()!=Some(&0){return Err(invalid());}
 let sym=sections[7];let strings=sections[8];let mut start_symbol=false;
 for (index,s) in sym.chunks_exact(24).enumerate().skip(1){
  let section=u16_at(s,6)?;let value=u64_at(s,8)?;let size=u64_at(s,16)?;
  if index==1 {if s!=[0,0,0,0,3,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]{return Err(invalid());}continue;}
  let symbol=name(strings,u32_at(s,0)?)?;
  if symbol.is_empty()||!symbol.iter().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'_'|b'.'|b'$'))||s[5]!=0||!matches!((s[4],section),(0x12,1)|(0x11,2))||value.checked_add(size).is_none_or(|end|end>sections[section as usize].len() as u64){return Err(invalid());}
  if symbol==b"_start" {if start_symbol||section!=1{return Err(invalid());}start_symbol=true;}
 }
 if !start_symbol{return Err(invalid());}
 for (reloc,target) in [(5,1),(6,4)] {
  for r in sections[reloc].chunks_exact(24){let offset=u64_at(r,0)?;let info=u64_at(r,8)?;
   if offset.checked_add(4).is_none_or(|end|end>sections[target].len() as u64)||!matches!(info as u32,2|4)||info>>32==0||info>>32>=sym.len() as u64/24{return Err(invalid());}
  }
 }Ok(())
}
pub fn validate_executable(b:&[u8])->io::Result<()> {
 header(b,2)?;let ph=u64_at(b,32)?;let count=u16_at(b,56)?;
 if ph<64||u16_at(b,54)?!=56||count==0||count>32{return Err(invalid());}
 let programs=range(b,ph,u64::from(count)*56)?;let entry=u64_at(b,24)?;let mut entry_mapped=false;let mut stack=false;let mut loads=vec![];
 for p in programs.chunks_exact(56){
  let kind=u32_at(p,0)?;let flags=u32_at(p,4)?;let file=u64_at(p,8)?;let address=u64_at(p,16)?;let size=u64_at(p,32)?;let memory=u64_at(p,40)?;let align=u64_at(p,48)?;
  if flags&!7!=0||flags&3==3||size>memory{return Err(invalid());}
  range(b,file,size)?;
  match kind {
   1=>{let end=address.checked_add(memory).ok_or_else(invalid)?;
    if address<4096||end>0x800000000000||align<4096||!align.is_power_of_two()||address%align!=file%align||loads.iter().any(|(a,z)|address<*z&&*a<end){return Err(invalid());}
    loads.push((address,end));if flags&1!=0&&entry>=address&&entry-address<size{entry_mapped=true;}
   },
   0x6474e551=>{if stack||flags!=6||size!=0||memory!=0{return Err(invalid());}stack=true;},
   6|0x6474e550|0x6474e552=>{},
   _=>return Err(invalid()), // No interpreter, dynamic dependencies or TLS.
  }
 }
 if !entry_mapped||!stack{return Err(invalid());}Ok(())
}

#[cfg(test)]mod tests {
 use super::*;
 #[test]fn malformed_elf_never_panics(){
  for size in 0..1024 {let b=vec![0;size];assert!(validate_object(&b).is_err());assert!(validate_executable(&b).is_err());}
 }
 fn put16(b:&mut [u8],at:usize,n:u16){b[at..at+2].copy_from_slice(&n.to_le_bytes());}
 fn put32(b:&mut [u8],at:usize,n:u32){b[at..at+4].copy_from_slice(&n.to_le_bytes());}
 fn put64(b:&mut [u8],at:usize,n:u64){b[at..at+8].copy_from_slice(&n.to_le_bytes());}
 fn object()->Vec<u8>{
  let labels=["",".text",".rodata",".kelft.native",".eh_frame",".rela.text",".rela.eh_frame",".symtab",".strtab",".shstrtab",".note.GNU-stack"];
  let mut names=vec![0];let mut ids=vec![];for label in labels{ids.push(if label.is_empty(){0}else{let id=names.len();names.extend_from_slice(label.as_bytes());names.push(0);id});}
  let mut symbols=vec![0;72];symbols[28]=3;put16(&mut symbols,30,1);put32(&mut symbols,48,1);symbols[52]=0x12;put16(&mut symbols,54,1);put64(&mut symbols,64,1);
  let data=[vec![],vec![0xc3],vec![],vec![],vec![],vec![],vec![],symbols,b"\0_start\0".to_vec(),names,vec![]];
  let align=[0,16,8,1,8,8,8,8,1,1,1];let mut b=vec![0;64];let mut offsets=vec![];
  for (i,part) in data.iter().enumerate(){if i==0{offsets.push(0);continue;}while b.len()%align[i]!=0{b.push(0);}offsets.push(b.len());b.extend_from_slice(part);}
  while b.len()%8!=0{b.push(0);}let table=b.len();b.resize(table+11*64,0);
  b[..7].copy_from_slice(&[127,69,76,70,2,1,1]);put16(&mut b,16,1);put16(&mut b,18,62);put32(&mut b,20,1);put64(&mut b,40,table as u64);put16(&mut b,52,64);put16(&mut b,58,64);put16(&mut b,60,11);put16(&mut b,62,9);
  for i in 0..11{let at=table+i*64;put32(&mut b,at,ids[i] as u32);put32(&mut b,at+4,[0,1,1,1,1,4,4,2,3,3,1][i]);put64(&mut b,at+8,[0,6,2,2,2,0,0,0,0,0,0][i]);put64(&mut b,at+24,offsets[i] as u64);put64(&mut b,at+32,data[i].len() as u64);put32(&mut b,at+40,if matches!(i,5|6){7}else if i==7{8}else{0});put32(&mut b,at+44,if i==5{1}else if i==6{4}else if i==7{2}else{0});put64(&mut b,at+48,align[i] as u64);put64(&mut b,at+56,if matches!(i,5|6|7){24}else{0});}b
 }
 #[test]fn object_rejects_dependency_directives_imports_and_escaping_ranges(){
  let b=object();validate_object(&b).unwrap();let table=u64_at(&b,40).unwrap() as usize;
  let mut changed=b.clone();let label=changed.windows(13).position(|v|v==b".kelft.native").unwrap();changed[label..label+9].copy_from_slice(b".deplibs\0");assert!(validate_object(&changed).is_err());
  for (at,n) in [(table+64+8,7),(table+64+24,u64::MAX),(table+64+32,u64::MAX),(table+7*64+56,16),(table+10*64+8,2),(40,u64::MAX)]{
   let mut changed=b.clone();put64(&mut changed,at,n);assert!(validate_object(&changed).is_err(),"accepted object field {at}");
  }
  let sym=u64_at(&b,table+7*64+24).unwrap() as usize;
  let mut changed=b.clone();put16(&mut changed,sym+54,0);assert!(validate_object(&changed).is_err());
  for size in [0,63,b.len()-1]{assert!(validate_object(&b[..size]).is_err());}
 }
 #[test]fn executable_rejects_dynamic_loading_executable_stack_and_writable_code(){
  let mut b=vec![0;4096];b[..7].copy_from_slice(&[127,69,76,70,2,1,1]);put16(&mut b,16,2);put16(&mut b,18,62);put32(&mut b,20,1);put16(&mut b,52,64);
  put64(&mut b,24,0x200200);put64(&mut b,32,64);put16(&mut b,54,56);put16(&mut b,56,2);
  put32(&mut b,64,1);put32(&mut b,68,5);put64(&mut b,80,0x200000);put64(&mut b,96,4096);put64(&mut b,104,4096);put64(&mut b,112,4096);
  put32(&mut b,120,0x6474e551);put32(&mut b,124,6);validate_executable(&b).unwrap();
  for (at,n) in [(64,2),(64,3),(64,7),(68,7),(124,7),(120,1),(18,183),(56,33)]{
   let mut changed=b.clone();if matches!(at,18|56){put16(&mut changed,at,n as u16);}else{put32(&mut changed,at,n);}assert!(validate_executable(&changed).is_err(),"accepted field {at}={n}");
  }
  for (at,n) in [(24,0x400000),(32,u64::MAX),(96,u64::MAX),(104,4095),(112,3)]{
   let mut changed=b.clone();put64(&mut changed,at,n);assert!(validate_executable(&changed).is_err());
  }
 }
}
