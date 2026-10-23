//! Private inherited-pipe protocol. Neither files nor environment variables carry
//! execution receipts or keys. The parent must authorize the role and target
//! before executing a decoded request. An invalid/truncated frame poisons the
//! connection: its supervisor must close both ends and terminate the worker.
use std::io::{self, Read, Write};
pub const IMAGE_LIMIT: usize = 64 << 20;
pub const TEXT_LIMIT: usize = 1 << 20;
pub const STREAM_LIMIT: usize = 16 << 20;
pub const ARGUMENT_LIMIT: usize = 4095;
pub const ROOT_LIMIT: usize = 131064;
#[derive(Debug, PartialEq)]
pub struct Request {
    pub target: String,
    pub args: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub image: Vec<u8>,
}
#[derive(Debug, PartialEq)]
pub struct Response {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn word(input: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4]; input.read_exact(&mut bytes)?; Ok(u32::from_le_bytes(bytes))
}
fn signature(input: &mut impl Read, expected: &[u8; 4]) -> io::Result<bool> {
    let mut bytes = [0; 4];
    let first=loop { match input.read(&mut bytes[..1]) {
        Err(error) if error.kind()==io::ErrorKind::Interrupted => continue,
        result => break result?,
    }};
    match first { 0 => return Ok(false), 1 => {}, _ => unreachable!() }
    input.read_exact(&mut bytes[1..])?;
    if &bytes != expected { return Err(invalid("private artifact channel signature")); }
    Ok(true)
}
fn text(input: &mut impl Read, budget: &mut usize, maximum: usize) -> io::Result<String> {
    let size = word(input)? as usize;
    if size > maximum || size > *budget { return Err(invalid("private artifact text bound")); }
    *budget -= size;
    let mut bytes = vec![0; size]; input.read_exact(&mut bytes)?;
    if bytes.contains(&0) { return Err(invalid("private artifact NUL argument")); }
    String::from_utf8(bytes).map_err(|_| invalid("private artifact UTF-8"))
}
fn texts(input: &mut impl Read, budget: &mut usize, maximum: usize, text_limit: usize) -> io::Result<Vec<String>> {
    let count = word(input)? as usize;
    if count > maximum { return Err(invalid("private artifact vector bound")); }
    (0..count).map(|_|text(input, budget, text_limit)).collect()
}
pub fn read_request(input: &mut impl Read) -> io::Result<Option<Request>> {
    if !signature(input, b"KAR1")? { return Ok(None); }
    let mut budget = TEXT_LIMIT;
    let target = text(input, &mut budget, 128)?;
    let args = texts(input, &mut budget, 4096, ARGUMENT_LIMIT)?;
    let read = texts(input, &mut budget, 128, ROOT_LIMIT)?;
    let write = texts(input, &mut budget, 128, ROOT_LIMIT)?;
    let size = word(input)? as usize;
    if size > IMAGE_LIMIT { return Err(invalid("private artifact image bound")); }
    let mut image = vec![0; size]; input.read_exact(&mut image)?;
    Ok(Some(Request { target, args, read, write, image }))
}
fn write_word(output: &mut impl Write, value: usize) -> io::Result<()> {
    let value = u32::try_from(value).map_err(|_|invalid("private artifact length overflow"))?;
    output.write_all(&value.to_le_bytes())
}
fn write_text(output: &mut impl Write, value: &str, budget: &mut usize, maximum: usize) -> io::Result<()> {
    if value.len() > maximum || value.len() > *budget || value.contains('\0') { return Err(invalid("private artifact text bound")); }
    *budget -= value.len(); write_word(output, value.len())?; output.write_all(value.as_bytes())
}
fn write_texts(output: &mut impl Write, values: &[String], budget: &mut usize, maximum: usize, text_limit: usize) -> io::Result<()> {
    if values.len() > maximum { return Err(invalid("private artifact vector bound")); }
    write_word(output, values.len())?;
    for value in values { write_text(output, value, budget, text_limit)?; }
    Ok(())
}
fn validate_request(request: &Request) -> io::Result<()> {
    if request.image.len() > IMAGE_LIMIT || request.target.len() > 128 ||
        request.args.len() > 4096 || request.read.len() > 128 || request.write.len() > 128 {
        return Err(invalid("private artifact request bound"));
    }
    let mut budget = TEXT_LIMIT;
    for (text, maximum) in std::iter::once((&request.target,128)).chain(
        request.args.iter().map(|s|(s,ARGUMENT_LIMIT)).chain(request.read.iter().chain(&request.write).map(|s|(s,ROOT_LIMIT)))) {
        if text.len() > maximum || text.len() > budget || text.contains('\0') {
            return Err(invalid("private artifact text bound"));
        }
        budget -= text.len();
    }
    Ok(())
}
fn valid_status(status: i32) -> bool { (-4..=255).contains(&status) }
pub fn write_request(output: &mut impl Write, request: &Request) -> io::Result<()> {
    // Validate the entire request before writing a frame. A local validation
    // error cannot leave a half-request that poisons the next transaction.
    validate_request(request)?;
    output.write_all(b"KAR1")?; let mut budget = TEXT_LIMIT;
    write_text(output, &request.target, &mut budget, 128)?;
    write_texts(output, &request.args, &mut budget, 4096, ARGUMENT_LIMIT)?;
    write_texts(output, &request.read, &mut budget, 128, ROOT_LIMIT)?;
    write_texts(output, &request.write, &mut budget, 128, ROOT_LIMIT)?;
    write_word(output, request.image.len())?; output.write_all(&request.image)?; output.flush()
}
pub fn read_response(input: &mut impl Read) -> io::Result<Response> {
    if !signature(input, b"KAS1")? { return Err(invalid("missing private artifact response")); }
    let status = word(input)? as i32;
    if !valid_status(status) { return Err(invalid("private artifact status")); }
    let out = word(input)? as usize; let err = word(input)? as usize;
    if out > STREAM_LIMIT || err > STREAM_LIMIT - out { return Err(invalid("private artifact output bound")); }
    let mut stdout = vec![0; out]; let mut stderr = vec![0; err];
    input.read_exact(&mut stdout)?; input.read_exact(&mut stderr)?;
    if std::str::from_utf8(&stdout).is_err() || std::str::from_utf8(&stderr).is_err() { return Err(invalid("private artifact output UTF-8")); }
    Ok(Response { status, stdout, stderr })
}
pub fn write_response(output: &mut impl Write, response: &Response) -> io::Result<()> {
    if !valid_status(response.status) || response.stdout.len() > STREAM_LIMIT || response.stderr.len() > STREAM_LIMIT - response.stdout.len() ||
        std::str::from_utf8(&response.stdout).is_err() || std::str::from_utf8(&response.stderr).is_err() {
        return Err(invalid("private artifact output bound or UTF-8"));
    }
    output.write_all(b"KAS1")?; output.write_all(&response.status.to_le_bytes())?;
    write_word(output, response.stdout.len())?; write_word(output, response.stderr.len())?;
    output.write_all(&response.stdout)?; output.write_all(&response.stderr)?; output.flush()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_and_exact_bytes_survive_short_reads_and_writes() {
        let request = Request { target:"native-windows-x86_64-v1".into(),args:vec!["hé😀\"\\".into()],read:vec!["C:\\project with spaces".into()],write:vec![],image:vec![0,255,127,1] };
        let mut bytes=vec![]; write_request(&mut bytes,&request).unwrap();
        struct Short<'a>(&'a [u8]); impl Read for Short<'_> { fn read(&mut self,out:&mut [u8])->io::Result<usize>{let n=out.len().min(1).min(self.0.len());out[..n].copy_from_slice(&self.0[..n]);self.0=&self.0[n..];Ok(n)} }
        let mut input=Short(&bytes);assert_eq!(read_request(&mut input).unwrap(),Some(request));assert_eq!(read_request(&mut input).unwrap(),None);
        let response=Response{status:255,stdout:"hé😀\0".as_bytes().into(),stderr:b"stderr".into()};let mut bytes=vec![];write_response(&mut bytes,&response).unwrap();assert_eq!(read_response(&mut Short(&bytes)).unwrap(),response);
    }
    #[test]
    fn rejects_truncation_before_execution_and_large_claims_before_allocation() {
        let request=Request{target:"native-macos-arm64-v1".into(),args:vec![],read:vec![],write:vec![],image:vec![1,2,3]};let mut bytes=vec![];write_request(&mut bytes,&request).unwrap();
        for end in 1..bytes.len(){assert!(read_request(&mut &bytes[..end]).is_err(),"prefix {end}");}
        let at=bytes.len()-request.image.len()-4;bytes[at..at+4].copy_from_slice(&u32::MAX.to_le_bytes());assert!(read_request(&mut bytes.as_slice()).is_err());
        assert!(read_request(&mut &b"BAD!"[..]).is_err());
        let mut invalid=b"KAS1".to_vec();invalid.extend_from_slice(&0u32.to_le_bytes());invalid.extend_from_slice(&u32::MAX.to_le_bytes());invalid.extend_from_slice(&1u32.to_le_bytes());assert!(read_response(&mut invalid.as_slice()).is_err());
    }
    #[test]
    fn invalid_local_requests_never_publish_a_partial_frame() {
        let base=Request{target:"native-windows-arm64-v1".into(),args:vec![],read:vec![],write:vec![],image:vec![]};
        for mode in 0..5 {
            let mut request=Request{target:base.target.clone(),args:vec![],read:vec![],write:vec![],image:vec![]};
            match mode {
                0=>request.args.push("bad\0argument".into()),
                1=>request.args.push("x".repeat(ARGUMENT_LIMIT+1)),
                2=>request.read.push("x".repeat(ROOT_LIMIT+1)),
                3=>request.args=vec!["x".repeat(ARGUMENT_LIMIT);257],
                _=>request.target="x".repeat(129),
            }
            let mut output=vec![];assert!(write_request(&mut output,&request).is_err());assert!(output.is_empty());
        }
        let request=Request{target:base.target,args:vec![],read:vec!["é".repeat(4000)],write:vec![],image:vec![]};
        let mut output=vec![];write_request(&mut output,&request).unwrap();assert_eq!(read_request(&mut output.as_slice()).unwrap(),Some(request));
    }
    #[test]
    fn response_status_and_utf8_are_checked_in_both_directions() {
        for status in [-5,256,i32::MAX] {
            let response=Response{status,stdout:vec![],stderr:vec![]};let mut output=vec![];
            assert!(write_response(&mut output,&response).is_err());assert!(output.is_empty());
            output.extend_from_slice(b"KAS1");output.extend_from_slice(&status.to_le_bytes());output.extend_from_slice(&[0;8]);
            assert!(read_response(&mut output.as_slice()).is_err());
        }
        let response=Response{status:0,stdout:vec![0xff],stderr:vec![]};assert!(write_response(&mut vec![],&response).is_err());
        let mut output=b"KAS1".to_vec();output.extend_from_slice(&0i32.to_le_bytes());output.extend_from_slice(&1u32.to_le_bytes());output.extend_from_slice(&0u32.to_le_bytes());output.push(0xff);assert!(read_response(&mut output.as_slice()).is_err());
    }

}
