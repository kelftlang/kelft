//! Extended operations stay relative to retained directory descriptors.
use super::*;
use std::{ffi::CStr, mem};

fn stat(parent:&File,name:&str)->io::Result<libc::stat>{
    let name=CString::new(name).map_err(|_|invalid("invalid entry name"))?;
    let mut value=unsafe{mem::zeroed()};
    if unsafe{libc::fstatat(parent.as_raw_fd(),name.as_ptr(),&mut value,libc::AT_SYMLINK_NOFOLLOW)}<0{return Err(io::Error::last_os_error());}Ok(value)
}
fn names(file:&File)->io::Result<Vec<String>>{
    let fd=unsafe{libc::openat(file.as_raw_fd(),c".".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_CLOEXEC)};
    if fd<0{return Err(io::Error::last_os_error());}
    let raw=unsafe{libc::fdopendir(fd)};if raw.is_null(){unsafe{libc::close(fd)};return Err(io::Error::last_os_error());}
    struct Directory(*mut libc::DIR);impl Drop for Directory{fn drop(&mut self){unsafe{libc::closedir(self.0)};}}
    let dir=Directory(raw);let mut out=vec![];let mut budget=1<<20;
    loop{
        #[cfg(target_os="linux")]unsafe{*libc::__errno_location()=0;}
        #[cfg(target_os="macos")]unsafe{*libc::__error()=0;}
        let entry=unsafe{libc::readdir(dir.0)};
        if entry.is_null(){let error=io::Error::last_os_error();if error.raw_os_error()!=Some(0){return Err(error);}break;}
        let raw=unsafe{CStr::from_ptr((*entry).d_name.as_ptr())}.to_bytes();if matches!(raw,b"."|b".."){continue;}
        let name=std::str::from_utf8(raw).map_err(|_|invalid("unrepresentable directory entry"))?;
        if out.len()>=4096||name.len()>budget{return Err(invalid("directory entry budget"));}budget-=name.len();out.push(name.to_owned());
    }
    out.sort_by(|a,b|a.as_bytes().cmp(b.as_bytes()));Ok(out)
}
impl Broker{
    fn host_root(&self,token:u64,writing:bool)->io::Result<&Root>{let root=self.roots.get(&token).ok_or_else(denied)?;if if writing{!root.write}else{!root.read}{return Err(denied());}Ok(root)}
    fn host_directory(&self,token:u64,path:&str,writing:bool)->io::Result<File>{
        filesystem_channel::validate_relative(path)?;let root=self.host_root(token,writing)?;
        if path=="."&&root.leaf.is_none(){return root.directory.try_clone();}
        let(parent,leaf)=Self::target(root,path)?;directory(&parent,&leaf,Some(root.device))
    }
    pub fn host_list(&self,token:u64,path:&str)->io::Result<Vec<String>>{names(&self.host_directory(token,path,false)?)}
    pub fn host_metadata(&self,token:u64,path:&str)->io::Result<serde_json::Value>{
        let root=self.host_root(token,false)?;filesystem_channel::validate_relative(path)?;
        let value=if path=="."&&root.leaf.is_none(){let mut out=unsafe{mem::zeroed()};if unsafe{libc::fstat(root.directory.as_raw_fd(),&mut out)}<0{return Err(io::Error::last_os_error());}out}else{let(parent,leaf)=Self::target(root,path)?;stat(&parent,&leaf)?};
        if value.st_size<0{return Err(invalid("negative metadata size"));}
        let kind=match value.st_mode&libc::S_IFMT{libc::S_IFREG=>"file",libc::S_IFDIR=>"directory",libc::S_IFLNK=>"link",_=>"other"};
        Ok(serde_json::json!({"kind":kind,"sizeBytes":value.st_size.to_string()}))
    }
    pub fn host_temporary(&self,token:u64,path:&str,prefix:&str)->io::Result<String>{
        if prefix.is_empty()||prefix.len()>48||!prefix.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'_'|b'-')){return Err(invalid("invalid temporary prefix"));}
        let parent=self.host_directory(token,path,true)?;
        for _ in 0..32{let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|e|io::Error::other(e.to_string()))?;let name=format!("{prefix}{}",crate::host_channel::hex(&nonce));let raw=CString::new(name.as_bytes()).unwrap();
            if unsafe{libc::mkdirat(parent.as_raw_fd(),raw.as_ptr(),0o700)}==0{return Ok(name);}let error=io::Error::last_os_error();if error.kind()!=io::ErrorKind::AlreadyExists{return Err(error);}}
        Err(io::Error::new(io::ErrorKind::AlreadyExists,"temporary name budget"))
    }
    pub fn host_rename(&self,source:u64,path:&str,target:u64,destination:&str)->io::Result<()>{
        let a=self.host_root(source,true)?;let b=self.host_root(target,true)?;let(parent,name)=Self::target(a,path)?;let(output,leaf)=Self::target(b,destination)?;
        let value=stat(&parent,&name)?;if value.st_mode&libc::S_IFMT==libc::S_IFLNK{return Err(denied());}
        let name=CString::new(name).unwrap();let leaf=CString::new(leaf).unwrap();
        #[cfg(target_os="linux")]let result=unsafe{libc::syscall(libc::SYS_renameat2,parent.as_raw_fd(),name.as_ptr(),output.as_raw_fd(),leaf.as_ptr(),libc::RENAME_NOREPLACE)};
        #[cfg(target_os="macos")]let result=unsafe{libc::renameatx_np(parent.as_raw_fd(),name.as_ptr(),output.as_raw_fd(),leaf.as_ptr(),libc::RENAME_EXCL)};
        if result<0{return Err(io::Error::last_os_error());}Ok(())
    }
    pub fn host_remove(&self,token:u64,path:&str,recursive:bool)->io::Result<()>{
        let root=self.host_root(token,true)?;let(parent,leaf)=Self::target(root,path)?;
        struct Entry{parent:File,name:String,identity:(u64,u64),directory:bool}
        let mut pending=vec![(parent,leaf,0)];let mut entries=vec![];
        while let Some((parent,name,depth))=pending.pop(){
            if depth>64||entries.len()+pending.len()>=4096{return Err(invalid("removal traversal budget"));}
            let value=stat(&parent,&name)?;let kind=value.st_mode&libc::S_IFMT;if kind==libc::S_IFLNK{return Err(denied());}
            if value.st_dev as u64!=root.device{return Err(denied());}
            if kind==libc::S_IFDIR&&recursive{let node=directory(&parent,&name,Some(root.device))?;for child in names(&node)?{pending.push((node.try_clone()?,child,depth+1));}}
            entries.push(Entry{parent,name,identity:(value.st_dev as u64,value.st_ino as u64),directory:kind==libc::S_IFDIR});
        }
        for entry in entries.into_iter().rev(){let actual=stat(&entry.parent,&entry.name)?;if (actual.st_dev as u64,actual.st_ino as u64)!=entry.identity{return Err(denied());}let name=CString::new(entry.name).unwrap();if unsafe{libc::unlinkat(entry.parent.as_raw_fd(),name.as_ptr(),if entry.directory{libc::AT_REMOVEDIR}else{0})}<0{return Err(io::Error::last_os_error());}}
        Ok(())
    }
}

#[cfg(test)]mod tests{
    use super::*;use std::os::unix::ffi::OsStrExt;
    #[test]fn descriptor_helpers_preserve_large_sizes_and_outside_targets(){
        let mut nonce=[0;16];getrandom::fill(&mut nonce).unwrap();let root=std::env::temp_dir().join(format!("kelft-host-fs-{}",crate::host_channel::hex(&nonce)));std::fs::create_dir(&root).unwrap();
        let mut broker=Broker::default();let token=broker.add_root(&root,true,true).unwrap();let name=broker.host_temporary(token,".","case-").unwrap();let dir=root.join(&name);
        File::create(dir.join("large")).unwrap().set_len(4294967303).unwrap();std::fs::write(dir.join("preserved"),b"outside").unwrap();
        assert_eq!(broker.host_metadata(token,&format!("{name}/large")).unwrap()["sizeBytes"],"4294967303");assert!(broker.host_rename(token,&format!("{name}/large"),token,&format!("{name}/preserved")).is_err());
        std::os::unix::fs::symlink(&root,dir.join("escape")).unwrap();assert_eq!(broker.host_metadata(token,&format!("{name}/escape")).unwrap()["kind"],"link");assert!(broker.host_remove(token,&name,true).is_err());assert_eq!(std::fs::read(dir.join("preserved")).unwrap(),b"outside");
        let malformed=std::ffi::OsStr::from_bytes(b"bad-\xff");std::fs::write(dir.join(malformed),b"data").unwrap();assert!(broker.host_list(token,&name).is_err());std::fs::remove_file(dir.join(malformed)).unwrap();std::fs::remove_file(dir.join("escape")).unwrap();broker.host_remove(token,&name,true).unwrap();drop(broker);std::fs::remove_dir(root).unwrap();
    }
}
