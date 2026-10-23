use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use wasmtime_wasi::{
    cli::{IsTerminal, StdoutStream},
    p2::{OutputStream, Pollable, StreamError, pipe::MemoryOutputPipe},
};

#[derive(Clone)]
pub struct Capture {
    pipe: MemoryOutputPipe,
    limit: usize,
    overflow: Arc<AtomicBool>,
}
impl Capture {
    pub fn new(limit: usize) -> Self {
        Self {
            pipe: MemoryOutputPipe::new(limit),
            limit,
            overflow: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn contents(&self) -> bytes::Bytes {
        self.pipe.contents()
    }
    pub fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::Relaxed)
    }
}
impl IsTerminal for Capture {
    fn is_terminal(&self) -> bool {
        false
    }
}
impl StdoutStream for Capture {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        self.pipe.async_stream()
    }
}
#[async_trait::async_trait]
impl Pollable for Capture {
    async fn ready(&mut self) {}
}
#[async_trait::async_trait]
impl OutputStream for Capture {
    fn write(&mut self, bytes: bytes::Bytes) -> Result<(), StreamError> {
        if bytes.len() > self.limit - self.contents().len() {
            self.overflow.store(true, Ordering::Relaxed);
        }
        self.pipe.write(bytes)
    }
    fn flush(&mut self) -> Result<(), StreamError> {
        self.pipe.flush()
    }
    fn check_write(&mut self) -> Result<usize, StreamError> {
        if self.contents().len() >= self.limit {
            self.overflow.store(true, Ordering::Relaxed);
        }
        self.pipe.check_write()
    }
}
