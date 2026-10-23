//! Measured native diagnostics. This collector never issues a certificate.
#[cfg(target_os = "windows")]
mod platform {
    use kelft_wasi::{native_target::Target, windows_process::AppContainerSid,
        windows_snapshot::Image, windows_supervisor::{self, Limits}};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{ffi::c_void, io, net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs}, time::Duration};
    type Error = Box<dyn std::error::Error>;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAlloc(address: *const c_void, size: usize, kind: u32, protection: u32) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
    }
    fn reservation_worker() -> Result<Value, Error> {
        let small = unsafe { VirtualAlloc(std::ptr::null(), 4096, 0x3000, 4) };
        if small.is_null() { return Err(io::Error::last_os_error().into()); }
        unsafe { small.cast::<u8>().write_volatile(42) };
        if unsafe { VirtualFree(small, 0, 0x8000) } == 0 { return Err(io::Error::last_os_error().into()); }
        let large = unsafe { VirtualAlloc(std::ptr::null(), 2usize << 30, 0x2000, 1) };
        let error = if large.is_null() { io::Error::last_os_error().raw_os_error() } else { None };
        if !large.is_null() && unsafe { VirtualFree(large, 0, 0x8000) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(json!({"smallCommitPositive": true, "reservationBytes": 2u64 << 30,
            "oversizedReservationSucceeded": !large.is_null(), "reservationError": error,
            "totalVirtualAddressSpaceBoundVerified": false}))
    }
    fn network_worker(endpoints: &[String]) -> Result<Value, Error> {
        if endpoints.len() != 2 { return Err("two fixed literal network endpoints required".into()); }
        let mut direct = vec![];
        for endpoint in endpoints {
            let address: std::net::SocketAddrV4 = endpoint.parse()?;
            let result = kelft_wasi::windows_network_probe::connect(address)?;
            direct.push(json!({"endpoint":endpoint,"result":result}));
        }
        Ok(json!({
            "directNetworkProtocol":"afd-tli-ipv4-tcp/1", "directNetworkAuthorizationDenied":direct.iter().all(|r|r["result"]["authorization_denied"]==true),"directNetwork":direct}))
    }
    fn endpoint_worker()->Result<Value,Error>{
        use kelft_wasi::windows_network_probe::{Endpoint,open_endpoint};
        let profiles=Endpoint::ALL.into_iter().map(open_endpoint).collect::<io::Result<Vec<_>>>()?;
        Ok(json!({"protocol":"afd-tli-ipv4-ipv6-tcp-udp/2","authorizationDenied":profiles.iter().all(|row|row.authorization_denied),"profiles":profiles}))
    }
    fn endpoint_positives()->Result<Value,Error>{
        use kelft_wasi::windows_network_probe::{Endpoint,open_endpoint};
        let profiles=Endpoint::ALL.into_iter().map(open_endpoint).collect::<io::Result<Vec<_>>>()?;
        if profiles.iter().any(|row|!row.opened){return Err(format!("native endpoint positive failed: {profiles:?}").into());}
        let message=b"native-udp-roundtrip-control";
        for address in ["127.0.0.1:0","[::1]:0"]{
            let receiver=std::net::UdpSocket::bind(address)?;let sender=std::net::UdpSocket::bind(address)?;
            for socket in [&receiver,&sender]{socket.set_read_timeout(Some(Duration::from_secs(2)))?;socket.set_write_timeout(Some(Duration::from_secs(2)))?;}
            sender.connect(receiver.local_addr()?)?;if sender.send(message)?!=message.len(){return Err("incomplete UDP positive send".into());}
            let mut bytes=[0;128];let(n,peer)=receiver.recv_from(&mut bytes)?;if &bytes[..n]!=message||peer!=sender.local_addr()?{return Err("UDP positive peer/content differs".into());}
            if receiver.send_to(message,peer)?!=message.len(){return Err("incomplete UDP positive reply".into());}let n=sender.recv(&mut bytes)?;if &bytes[..n]!=message{return Err("UDP positive reply differs".into());}
        }
        let listener=TcpListener::bind((std::net::Ipv6Addr::LOCALHOST,0))?;let stream=TcpStream::connect_timeout(&listener.local_addr()?,Duration::from_secs(2))?;let(_,peer)=listener.accept()?;if peer!=stream.local_addr()?{return Err("IPv6 TCP positive peer differs".into());}
        Ok(json!({"endpointOpens":profiles,"udpRoundtrips":2,"ipv6TcpConnections":1}))
    }
    fn winsock_worker(endpoints: &[String]) -> Result<Value, Error> {
        if endpoints.len()!=2 {return Err("two fixed literal Winsock endpoints required".into());}
        let mut results = vec![];
        for endpoint in endpoints {
            let address: SocketAddr = endpoint.parse()?;
            let result = TcpStream::connect_timeout(&address, Duration::from_secs(2));
            let code = result.as_ref().err().and_then(io::Error::raw_os_error);
            results.push(json!({"endpoint": endpoint, "connected": result.is_ok(), "error": code,
                "authorizationDenied": code == Some(10013)}));
        }
        Ok(json!({"networkAuthorizationDenied":results.iter().all(|r|r["authorizationDenied"]==true),"endpoints":results}))
    }
    fn commit_attempt(size: usize) -> Result<(), io::Error> {
        // MEM_COMMIT charges the commit budget without touching 2 GiB of RAM.
        let allocation = unsafe { VirtualAlloc(std::ptr::null(),size,0x3000,4) };
        if allocation.is_null() {return Err(io::Error::last_os_error());}
        unsafe {allocation.cast::<u8>().write_volatile(42);}
        if unsafe {VirtualFree(allocation,0,0x8000)}==0 {return Err(io::Error::last_os_error());}
        Ok(())
    }
    fn commit_worker() -> Result<Value, Error> {
        commit_attempt(4096)?;
        let result=commit_attempt(2usize<<30);
        Ok(json!({"smallCommitPositive":true,"requestedCommittedBytes":2u64<<30,
            "oversizedCommitSucceeded":result.is_ok(),"commitErrno":result.err().and_then(|error|error.raw_os_error())}))
    }
    fn positive(address: &SocketAddr) -> io::Result<()> {
        TcpStream::connect_timeout(address, Duration::from_secs(5)).map(drop)
    }
    fn direct_positive(address: &SocketAddr) -> Result<(),Error> {
        let SocketAddr::V4(address)=address else{return Err("fixed IPv4 native network control required".into());};
        let result=kelft_wasi::windows_network_probe::connect(*address)?;
        if !result.connected{return Err(format!("direct network positive control failed: {result:?}").into());}Ok(())
    }
    fn collect() -> Result<Value, Error> {
        let system = std::env::var("SystemRoot")?;
        let bytes = std::fs::read(std::env::current_exe()?)?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        let mut observations = vec![];
        let run = |arguments: Vec<String>| -> Result<Value, Error> {
            let identity = AppContainerSid::fresh()?;
            let image = Image::new(&bytes, &digest, &identity)?;
            let result = windows_supervisor::run(&image, &identity, &system, &arguments,
                Limits { wall_ms: 15000, memory_bytes: 1 << 30, output_bytes: 65536 }, &[], vec![])?;
            if result.exit != Some(0) || result.failure.is_some() || !result.stderr.is_empty() {
                return Err(format!("isolated diagnostic failed: {:?}: {}{}", result.failure,
                    String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr)).into());
            }
            Ok(json!({"worker": serde_json::from_slice::<Value>(&result.stdout)?,
                "processCommitLimitBytes": result.usage.process_commit_limit_bytes,
                "jobCommitLimitBytes": result.usage.job_commit_limit_bytes,
                "peakJobCommittedBytes": result.usage.peak_job_memory_bytes,
                "elapsedMs": result.usage.elapsed_ms}))
        };
        observations.push(json!({"mechanism": "virtual-address-space", "result": run(vec!["--worker-reservation".into()])?}));
        let committed=(|| -> Result<Value, Error> {
            commit_attempt(2usize<<30)?;
            let result=run(vec!["--worker-commit".into()])?;
            commit_attempt(2usize<<30)?;
            Ok(json!({"hostPositiveControls":2,"result":result}))
        })();
        observations.push(match committed {
            Ok(result)=>json!({"mechanism":"committed-memory","state":"observed","result":result}),
            Err(error)=>json!({"mechanism":"committed-memory","state":"infrastructure-failed","error":error.to_string()})
        });
        let network = (|| -> Result<Value, Error> {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let local = listener.local_addr()?;
            let mut remote = None;
            for address in ("api.github.com",443).to_socket_addrs()?.take(8) {
                if address.is_ipv4() && !address.ip().is_loopback() && positive(&address).is_ok() {
                    remote = Some(address); break;
                }
            }
            let remote = remote.ok_or("external network positive control unavailable")?;
            positive(&local)?;
            direct_positive(&local)?; direct_positive(&remote)?;
            let result = run(vec!["--worker-network".into(),local.to_string(),remote.to_string()])?;
            // Winsock catalog initialization is an independent diagnostic. Its
            // failure cannot prevent the native driver authorization probe.
            let winsock = match run(vec!["--worker-winsock-network".into(),local.to_string(),remote.to_string()]) {
                Ok(result)=>json!({"state":"observed","result":result}),
                Err(error)=>json!({"state":"infrastructure-failed","error":error.to_string()})
            };
            positive(&local)?; positive(&remote)?;
            direct_positive(&local)?; direct_positive(&remote)?;
            Ok(json!({"hostPositiveControls": 4, "directDriverPositiveControls":4, "remoteHost": "api.github.com", "winsockObservation":winsock, "result": result}))
        })();
        observations.push(match network {
            Ok(result) => json!({"mechanism": "network", "state": "observed", "result": result}),
            Err(error) => json!({"mechanism": "network", "state": "infrastructure-failed", "error": error.to_string(), "networkAuthorizationDenied": false})
        });
        let endpoints=(||->Result<Value,Error>{let before=endpoint_positives()?;let result=run(vec!["--worker-endpoints".into()])?;let after=endpoint_positives()?;Ok(json!({"before":before,"after":after,"result":result,"hostEndpointPositiveControls":8,"udpRoundtripPositiveControls":4,"ipv6TcpPositiveControls":2}))})();
        observations.push(match endpoints{Ok(result)=>json!({"mechanism":"network-endpoints","state":"observed","result":result}),Err(error)=>json!({"mechanism":"network-endpoints","state":"infrastructure-failed","error":error.to_string()})});
        Ok(json!({"schema": "kelft-windows-isolation-diagnostics/1", "profile": Target::current()?.id(),
            "state": "observed", "imageSHA256": digest, "observations": observations,
            "totalVirtualAddressSpaceBoundVerified": false, "certified": false, "releaseEligible": false}))
    }
    pub fn main() -> Result<(), Error> {
        let arguments = std::env::args().skip(1).collect::<Vec<_>>();
        let result = match arguments.first().map(String::as_str) {
            Some("--worker-reservation") if arguments.len() == 1 => reservation_worker()?,
            Some("--worker-commit") if arguments.len() == 1 => commit_worker()?,
            Some("--worker-network") => network_worker(&arguments[1..])?,
            Some("--worker-endpoints") if arguments.len()==1 => endpoint_worker()?,
            Some("--worker-winsock-network") => winsock_worker(&arguments[1..])?,
            Some("--collect") if arguments.len() == 1 => collect()?,
            _ => return Err("expected --collect on a native Windows host".into())
        };
        println!("{result}"); Ok(())
    }
    #[cfg(test)]mod tests {
        use super::*;
        #[test]fn private_catalog_independent_worker(){
            let Ok(endpoint)=std::env::var("KELFT_DIRECT_WORKER_ENDPOINT")else{return;};
            let result=network_worker(&[endpoint.clone(),endpoint]).unwrap();
            assert_eq!(result["directNetworkAuthorizationDenied"],true);println!("catalog-independent-worker-ok");
        }
        #[test]fn network_worker_finishes_without_a_winsock_catalog(){
            let listener=TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).unwrap();let address=listener.local_addr().unwrap();direct_positive(&address).unwrap();
            let bytes=std::fs::read(std::env::current_exe().unwrap()).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));let identity=AppContainerSid::fresh().unwrap();let image=Image::new(&bytes,&digest,&identity).unwrap();
            let args=["--exact","platform::tests::private_catalog_independent_worker","--nocapture"].map(String::from);
            let result=windows_supervisor::run(&image,&identity,&std::env::var("SystemRoot").unwrap(),&args,Limits{wall_ms:15000,memory_bytes:1<<30,output_bytes:65536},&[("KELFT_DIRECT_WORKER_ENDPOINT".into(),address.to_string())],vec![]).unwrap();
            assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(result.failure.is_none());assert!(String::from_utf8_lossy(&result.stdout).contains("catalog-independent-worker-ok"));direct_positive(&address).unwrap();
        }
    }
}
#[cfg(target_os = "windows")]
fn main() { if let Err(error) = platform::main() { eprintln!("error[K0600]: {error}"); std::process::exit(125); } }
#[cfg(not(target_os = "windows"))]
fn main() { eprintln!("native Windows execution required"); std::process::exit(125); }
