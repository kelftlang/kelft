//! Fixed compiler object format and native slices of measured tool images.
//! Object load commands cannot delegate options, libraries or extra files.
use crate::native_target::Target;
use std::io;
fn bad()->io::Error{io::Error::new(io::ErrorKind::InvalidInput,"unsupported native Mach-O input")}
/// Private measured SDK names use Darwin components, including Perl's `::`.
/// Guest filesystem RPC keeps its separate portable path restrictions.
pub fn validate_sdk_relative(path:&str)->io::Result<()>{
 let bytes=path.as_bytes();
 if path.is_empty()||path.len()>4096||path.contains(['\\','\0'])||path.split('/').any(|part|part.is_empty()||part=="."||part=="..")||bytes.get(1)==Some(&b':')&&bytes[0].is_ascii_alphabetic(){return Err(io::Error::new(io::ErrorKind::InvalidInput,"normal relative Darwin SDK path required"));}Ok(())
}
#[cfg(test)]mod sdk_path_tests{
 use super::validate_sdk_relative;
 #[test]fn measured_darwin_names_preserve_colons_without_accepting_drive_paths(){
  for name in ["usr/share/man/man3/APR::Base64.3pm","Frameworks/hé 😀/Headers/header.h"]{validate_sdk_relative(name).unwrap();}
  for name in ["",".","..","/usr/lib","C:/SDK/file","C:drive","a\\b","a//b","a/../b","a/./b","a\0b"]{assert!(validate_sdk_relative(name).is_err(),"{name:?}");}
 }
}
fn word(b:&[u8],at:usize)->io::Result<usize>{Ok(u32::from_le_bytes(b.get(at..at+4).ok_or_else(bad)?.try_into().unwrap()) as usize)}
fn wide(b:&[u8],at:usize)->io::Result<usize>{usize::try_from(u64::from_le_bytes(b.get(at..at+8).ok_or_else(bad)?.try_into().unwrap())).map_err(|_|bad())}
fn cpu(target:Target)->io::Result<(usize,usize)>{match target{Target::MacosX64=>Ok((0x01000007,3)),Target::MacosArm64=>Ok((0x0100000c,0)),_=>Err(bad())}}
fn range(start:usize,size:usize,end:usize)->io::Result<()>{if start.checked_add(size).is_none_or(|n|n>end){return Err(bad());}Ok(())}
fn named(bytes:&[u8],name:&[u8])->bool{bytes.starts_with(name)&&bytes[name.len()..].iter().all(|b|*b==0)}
pub fn validate_object(bytes:&[u8],target:Target)->io::Result<()>{
 let(machine,subtype)=cpu(target)?;
 if bytes.len()<552||bytes.len()>64<<20||word(bytes,0)?!=0xfeedfacf||word(bytes,4)?!=machine||word(bytes,8)?!=subtype||word(bytes,12)?!=1||word(bytes,16)?!=4||word(bytes,20)?!=520||word(bytes,24)?!=0x2000||word(bytes,28)?!=0{return Err(bad());}
 if word(bytes,32)?!=0x19||word(bytes,36)?!=392||bytes[40..56]!=[0;16]||wide(bytes,56)?!=0||word(bytes,88)?!=7||word(bytes,92)?!=7||word(bytes,96)?!=4||word(bytes,100)?!=0{return Err(bad());}
 if word(bytes,424)?!=2||word(bytes,428)?!=24||word(bytes,448)?!=0xb||word(bytes,452)?!=80||word(bytes,528)?!=0x32||word(bytes,532)?!=24||word(bytes,536)?!=1||word(bytes,540)?!=14*65536||word(bytes,544)?<14*65536||word(bytes,548)?!=0{return Err(bad());}
 let symbols=word(bytes,432)?;let count=word(bytes,436)?;let strings=word(bytes,440)?;let string_size=word(bytes,444)?;
 if count==0||count>0xffffff||symbols<552||symbols%8!=0||symbols.checked_add(count.checked_mul(16).ok_or_else(bad)?)!=Some(strings)||strings.checked_add(string_size)!=Some(bytes.len())||string_size==0||*bytes.get(strings).ok_or_else(bad)?!=0{return Err(bad());}
 if word(bytes,456)?!=0||word(bytes,460)?!=0||word(bytes,464)?!=0||word(bytes,468)?.checked_add(word(bytes,476)?)!=Some(count)||word(bytes,472)?!=word(bytes,468)?||bytes[480..528]!=[0;48]{return Err(bad());}
 let mut previous_address=0;let mut previous_file=552;let mut sections=vec![];let mut relocations=vec![];
 for(index,(name,segment,alignment,flags))in [(b"__text".as_slice(),b"__TEXT".as_slice(),4,0x80000400),(b"__const",b"__TEXT",3,0),(b"__compact_unwind",b"__LD",3,0x02000000),(b"__kelft_native",b"__TEXT",0,0x10000000)].into_iter().enumerate(){
  let at=104+index*80;let address=wide(bytes,at+32)?;let length=wide(bytes,at+40)?;let offset=word(bytes,at+48)?;let reloc=word(bytes,at+56)?;let nreloc=word(bytes,at+60)?;
  if !named(&bytes[at..at+16],name)||!named(&bytes[at+16..at+32],segment)||word(bytes,at+52)?!=alignment||word(bytes,at+64)?!=flags||bytes[at+68..at+80]!=[0;12]||address<previous_address||offset<previous_file||offset%(1<<alignment)!=0{return Err(bad());}
  range(offset,length,symbols)?;if index==0&&(address!=0||length==0){return Err(bad());}
  if index==2&&(length%32!=0||nreloc!=length/32){return Err(bad());}
  if nreloc==0{if reloc!=0{return Err(bad());}}else{if reloc<552||reloc%4!=0{return Err(bad());}range(reloc,nreloc.checked_mul(8).ok_or_else(bad)?,symbols)?;relocations.push((reloc,nreloc,length,index));}
  sections.push((address,length));previous_address=address.checked_add(length).ok_or_else(bad)?;previous_file=offset+length;
 }
 if wide(bytes,64)?!=previous_address||wide(bytes,72)?!=word(bytes,152)?||wide(bytes,72)?.checked_add(wide(bytes,80)?)!=Some(previous_file){return Err(bad());}
 let mut end=previous_file;
 for(start,n,length,section)in relocations{if start<end{return Err(bad());}end=start+n*8;let mut previous=usize::MAX;
  for at in (start..end).step_by(8){let offset=word(bytes,at)?;let value=word(bytes,at+4)?;let symbol=value&0xffffff;let pcrel=value>>24&1;let width=value>>25&3;let external=value>>27&1;let kind=value>>28;
   if offset>=previous||symbol>=count||external!=1||width<2||offset.checked_add(1<<width).is_none_or(|n|n>length){return Err(bad());}previous=offset;
   let allowed=if section==2{kind==0&&width==3&&pcrel==0&&offset%32==0}else if section==0{width==2&&if target==Target::MacosX64{matches!(kind,1|2)&&pcrel==1}else{matches!(kind,2|3|4)&&pcrel==usize::from(kind!=4)&&offset%4==0}}else{false};if !allowed{return Err(bad());}
  }
 }
 for index in 0..count{let at=symbols+index*16;let name=word(bytes,at)?;let kind=bytes[at+4];let section=bytes[at+5] as usize;
  if name==0||name>=string_size||bytes[at+6..at+8]!=[0;2]{return Err(bad());}let text=&bytes[strings+name..];let length=text.iter().position(|b|*b==0).ok_or_else(bad)?;if length==0||length>4096||text[0]!=b'_'||!text[..length].iter().all(|b|b.is_ascii_alphanumeric()||*b==b'_'){return Err(bad());}
  let value=wide(bytes,at+8)?;if index<word(bytes,468)?{if kind!=15||!(1..=2).contains(&section){return Err(bad());}let(address,length)=sections[section-1];if value<address||value>address+length{return Err(bad());}}
  else if kind!=1||section!=0||value!=0{return Err(bad());}
 }
 Ok(())
}
/// Only parent-selected, hash-pinned tools may retain a universal container.
/// A native slice is mandatory; candidate images stay thin and native.
pub fn validate_tool(bytes:&[u8],target:Target)->io::Result<()>{
 validate_tool_bounded(bytes,target,64<<20)
}
pub(crate) fn validate_tool_bounded(bytes:&[u8],target:Target,maximum:usize)->io::Result<()>{
 if maximum>128<<20||bytes.len()<32||bytes.len()>maximum{return Err(bad());}let(machine,subtype)=cpu(target)?;
 let selected=if bytes[..4]==[0xca,0xfe,0xba,0xbe]{
  let be=|at:usize|->io::Result<usize>{Ok(u32::from_be_bytes(bytes.get(at..at+4).ok_or_else(bad)?.try_into().unwrap()) as usize)};let count=be(4)?;if count==0||count>32{return Err(bad());}let table=8+count*20;let mut ranges=vec![];let mut selected=None;
  for index in 0..count{let at=8+index*20;let start=be(at+8)?;let size=be(at+12)?;let alignment=be(at+16)?;if alignment>30||start<table||start%(1usize<<alignment)!=0||size<32{return Err(bad());}range(start,size,bytes.len())?;if ranges.iter().any(|(a,z)|start<*z&&*a<start+size){return Err(bad());}ranges.push((start,start+size));if be(at)?==machine&&be(at+4)?&0xffffff==subtype{if selected.is_some(){return Err(bad());}selected=Some(&bytes[start..start+size]);}}
  selected.ok_or_else(bad)?
 }else{bytes};
 target.validate_executable(selected)
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn tools_require_a_real_native_slice_and_nonoverlapping_container(){
  for target in [Target::MacosX64,Target::MacosArm64]{let(machine,subtype)=cpu(target).unwrap();let mut thin=vec![0u8;40];for(at,value)in [(0,0xfeedfacf),(4,machine),(8,subtype),(12,2),(16,1),(20,8),(32,0x1b),(36,8)]{thin[at..at+4].copy_from_slice(&(value as u32).to_le_bytes());}validate_tool(&thin,target).unwrap();let mut fat=vec![0;4096];fat[..4].copy_from_slice(&[0xca,0xfe,0xba,0xbe]);for(at,value)in [(4,1),(8,machine),(12,subtype),(16,4096),(20,40),(24,12)]{fat[at..at+4].copy_from_slice(&(value as u32).to_be_bytes());}fat.extend_from_slice(&thin);validate_tool(&fat,target).unwrap();assert!(validate_tool(&fat,if target==Target::MacosX64{Target::MacosArm64}else{Target::MacosX64}).is_err());fat[16..20].copy_from_slice(&8u32.to_be_bytes());assert!(validate_tool(&fat,target).is_err());}
 }
 #[test]fn truncated_objects_and_foreign_load_commands_fail_closed(){for n in 0..560{assert!(validate_object(&vec![0;n],Target::MacosX64).is_err());}assert!(validate_object(&vec![0;560],Target::LinuxX64).is_err());}
 #[test]fn real_writer_objects_pass_and_tool_option_injection_and_ranges_are_rejected(){
  let fixtures:serde_json::Value=serde_json::from_str(include_str!("../../tests/native-macos-object-vectors.json")).unwrap();
  for fixture in fixtures.as_array().unwrap(){let target=if fixture["profile"]=="macos-arm64"{Target::MacosArm64}else{Target::MacosX64};let hex=fixture["hex"].as_str().unwrap();let bytes=(0..hex.len()).step_by(2).map(|at|u8::from_str_radix(&hex[at..at+2],16).unwrap()).collect::<Vec<_>>();validate_object(&bytes,target).unwrap();
   for(at,value)in [(4,0x01000001u32),(12,2),(16,5),(24,0),(32,0x2d),(36,80),(96,5),(152,u32::MAX),(156,31),(160,u32::MAX),(164,u32::MAX),(168,0),(432,u32::MAX),(436,u32::MAX),(440,u32::MAX),(444,u32::MAX),(468,u32::MAX),(528,0x2d)]{let mut changed=bytes.clone();changed[at..at+4].copy_from_slice(&value.to_le_bytes());assert!(validate_object(&changed,target).is_err(),"accepted modified field at {at}");}
   for length in [0,32,104,552,bytes.len()-1]{assert!(validate_object(&bytes[..length],target).is_err());}
  }
 }
}
