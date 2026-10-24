//! Seal the fixed initial stack in a thin linked image and its ad-hoc page hashes.
//! Only the simple SHA-256 CodeDirectory emitted by the pinned linker is accepted.
use crate::native_target::Target;
use sha2::{Digest,Sha256};
use std::io;
fn invalid()->io::Error{io::Error::other("unsupported linked Mach-O stack/signature contract")}
fn le(bytes:&[u8],at:usize)->io::Result<usize>{Ok(u32::from_le_bytes(bytes.get(at..at+4).ok_or_else(invalid)?.try_into().unwrap()) as usize)}
fn be(bytes:&[u8],at:usize)->io::Result<usize>{Ok(u32::from_be_bytes(bytes.get(at..at+4).ok_or_else(invalid)?.try_into().unwrap()) as usize)}
pub fn seal_stack(bytes:&mut [u8],target:Target)->io::Result<()>{
 if bytes.len()>64<<20{return Err(invalid());}target.validate_executable(bytes)?;
 let commands=le(bytes,16)?;let end=32usize.checked_add(le(bytes,20)?).ok_or_else(invalid)?;
 if commands>4096||end>bytes.len(){return Err(invalid());}let mut at=32;let(mut stack,mut signature)=(None,None);
 for _ in 0..commands{let size=le(bytes,at+4)?;if size<8||size%8!=0||at.checked_add(size).is_none_or(|next|next>end){return Err(invalid());}
  match le(bytes,at)?{0x80000028=>{if size!=24||stack.replace(at+16).is_some(){return Err(invalid());}},0x1d=>{if size!=16||signature.replace((le(bytes,at+8)?,le(bytes,at+12)?)).is_some(){return Err(invalid());}},_=>{}}at+=size;
 }
 if at!=end{return Err(invalid());}let stack=stack.ok_or_else(invalid)?;
 let mut hashes=None;
 if let Some((start,size))=signature{
  if start<end||start.checked_add(size)!=Some(bytes.len())||size<20||be(bytes,start)?!=0xfade0cc0||be(bytes,start+8)?!=1||be(bytes,start+12)?!=0{return Err(invalid());}
  let length=be(bytes,start+4)?;if length>size||length<20||bytes[start+length..].iter().any(|b|*b!=0){return Err(invalid());}
  let offset=be(bytes,start+16)?;if !matches!(offset,20|24)||offset>length||bytes[start+20..start+offset].iter().any(|b|*b!=0){return Err(invalid());}let directory=start+offset;
  let directory_length=be(bytes,directory+4)?;
  if be(bytes,directory)?!=0xfade0c02||directory_length<88||offset+directory_length!=length||be(bytes,directory+8)?!=0x20400||be(bytes,directory+12)?!=0x20002{return Err(invalid());}
  let hash_offset=be(bytes,directory+16)?;let identifier=be(bytes,directory+20)?;let slots=be(bytes,directory+28)?;
  if be(bytes,directory+24)?!=0||be(bytes,directory+32)?!=start||bytes.get(directory+36..directory+40)!=Some(&[32,2,0,12])||be(bytes,directory+44)?!=0||be(bytes,directory+48)?!=0||slots!=start.div_ceil(4096)||identifier<88||identifier>=hash_offset||hash_offset<88||hash_offset.checked_add(slots*32)!=Some(directory_length){return Err(invalid());}
  if !bytes[directory+identifier..directory+hash_offset].contains(&0){return Err(invalid());}
  let table=directory+hash_offset;
  for slot in 0..slots{let begin=slot*4096;let digest=Sha256::digest(&bytes[begin..start.min(begin+4096)]);if bytes[table+slot*32..table+(slot+1)*32]!=digest[..]{return Err(invalid());}}
  hashes=Some((start,table,slots));
 }
 bytes[stack..stack+8].copy_from_slice(&(16u64<<20).to_le_bytes());
 if let Some((limit,table,slots))=hashes{for slot in 0..slots{let begin=slot*4096;let digest=Sha256::digest(&bytes[begin..limit.min(begin+4096)]);bytes[table+slot*32..table+(slot+1)*32].copy_from_slice(&digest);}}
 Ok(())
}

#[cfg(test)]mod tests{
 use super::*;
 fn fixture()->Vec<u8>{let mut b=vec![0u8;4244];for(at,value)in [(0,0xfeedfacfu32),(4,0x1000007),(8,3),(12,2),(16,2),(20,40),(32,0x80000028),(36,24),(56,0x1d),(60,16),(64,4096),(68,148)]{b[at..at+4].copy_from_slice(&value.to_le_bytes());}for(at,value)in [(4096,0xfade0cc0u32),(4100,148),(4104,1),(4112,20),(4116,0xfade0c02),(4120,128),(4124,0x20400),(4128,0x20002),(4132,96),(4136,88),(4144,1),(4148,4096)]{b[at..at+4].copy_from_slice(&value.to_be_bytes());}b[4152..4156].copy_from_slice(&[32,2,0,12]);b[4204]=b'k';let digest=Sha256::digest(&b[..4096]);b[4212..4244].copy_from_slice(&digest);b}
 #[test]fn stack_sealing_preserves_adhoc_hashes_and_rejects_changed_or_foreign_inputs(){
  let input=fixture();let mut sealed=input.clone();seal_stack(&mut sealed,Target::MacosX64).unwrap();assert_eq!(u64::from_le_bytes(sealed[48..56].try_into().unwrap()),16<<20);assert_eq!(&sealed[4212..4244],&Sha256::digest(&sealed[..4096])[..]);let prior=sealed.clone();seal_stack(&mut sealed,Target::MacosX64).unwrap();assert_eq!(sealed,prior);
  for at in [0,16,20,36,64,68,4096,4100,4104,4112,4120,4124,4128,4132,4136,4140,4144,4148,4152,4153,4155,4160,4164,4212]{let mut changed=input.clone();changed[at]^=1;assert!(seal_stack(&mut changed,Target::MacosX64).is_err(),"accepted changed offset {at}");}
  assert!(seal_stack(&mut input.clone(),Target::MacosArm64).is_err());
 }
}
