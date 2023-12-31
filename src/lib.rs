use std::error::Error;
use std::ffi::{c_int, c_uchar, c_void};
use std::io::{self, Read, Write};
use std::mem::{ManuallyDrop, MaybeUninit};
use std::pin::Pin;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
mod ffi;
use ffi::*;

pub mod alpn {
    pub struct Alpn(pub(crate) *mut *const std::ffi::c_char);
    unsafe impl Send for Alpn {}
    unsafe impl Sync for Alpn {}
    const NULL: *const u8 = std::ptr::null();
    pub const H1: Alpn = Alpn(&[b"http/1.1\0" as _, NULL] as *const _ as _);
    pub const H2: Alpn = Alpn(&[b"h2\0" as _, NULL] as *const _ as _);
    pub const H1H2: Alpn = Alpn(&[b"http/1.1\0" as _, b"h2\0" as _, NULL] as *const _ as _);
    pub const H2H1: Alpn = Alpn(&[b"h2\0" as _, b"http/1.1\0" as _, NULL] as *const _ as _);
}

struct Instance {
    entropy: mbedtls_entropy_context,
    ctr_drbg: mbedtls_ctr_drbg_context,
    cert: mbedtls_x509_crt,
    pkey: mbedtls_pk_context,
    conf: mbedtls_ssl_config,
    ssl: mbedtls_ssl_context,
}

unsafe impl Send for Instance {}

impl Drop for Instance {
    fn drop(&mut self) {
        // println!(">>> {}::drop()", std::any::type_name::<Self>());
        unsafe {
            mbedtls_ssl_free(&mut self.ssl as _);
            mbedtls_ssl_config_free(&mut self.conf as _);
            mbedtls_pk_free(&mut self.pkey as _);
            mbedtls_x509_crt_free(&mut self.cert as _);
            mbedtls_ctr_drbg_free(&mut self.ctr_drbg as _);
            mbedtls_entropy_free(&mut self.entropy as _);
        }
    }
}

enum Kind {
    Client {
        ca: Option<Vec<Vec<u8>>>,
    },
    Server {
        cert: Vec<u8>,
        key: Vec<u8>,
        alpn: Option<alpn::Alpn>,
    },
}

pub struct TlsConfig {
    kind: Kind,
    /// Cache pool for Mbed-TLS structs, reuse structs after TlsStream dropped.
    ///
    /// # Why
    ///
    /// The Mbed-TLS's thread-safety guarantee is not enabled by default, so we use this cache pool mechanism to provide each TlsStream with sole context structs.
    ///
    /// # Why not `mbedtls_threading_set_alt`
    ///
    /// You may be noticed that you can use `threading_pthread` or `threading_alt` according to the docs ([on Read the Docs](https://mbed-tls.readthedocs.io/en/latest/kb/development/thread-safety-and-multi-threading/) or [on GitHub](https://github.com/Mbed-TLS/mbedtls-docs/blob/5d3c541442be63044b26fba425d216cb37504961/kb/development/thread-safety-and-multi-threading.md)).
    ///
    /// However, it's not perfect:
    ///
    /// 1. Weakness. Some parts of Mbed-TLS still doesn't supports thread-safety.
    /// 2. Low efficiency. Compared to pthread mutex, this cache pool implement brings 9%+ performance improvements.
    /// 3. Hardness. If you want to skip pthread (for better cross-platform compatibility), reverse-binding Rust's Mutex to C for `mbedtls_threading_set_alt` will be painful.
    ///
    /// So, try this one!
    cache: Mutex<Vec<Pin<Box<Instance>>>>,
}

// TODO
// https://mbed-tls.readthedocs.io/en/latest/kb/how-to/how-do-i-tune-elliptic-curves-resource-usage/

fn psa_init() {
    static INITED: OnceLock<()> = OnceLock::new();
    INITED.get_or_init(|| unsafe {
        assert!(psa_crypto_init() == 0);
    });
}

impl TlsConfig {
    /// Create a config for server.
    pub fn new_server(cert: Vec<u8>, key: Vec<u8>, alpn: Option<alpn::Alpn>) -> Arc<Self> {
        psa_init(); // MUST BE CALLED
        Arc::new(Self {
            kind: Kind::Server { cert, key, alpn },
            cache: Mutex::new(Vec::new()),
        })
    }

    /// Create a config for client.
    pub fn new_client(ca: Option<Vec<Vec<u8>>>) -> Arc<Self> {
        psa_init(); // MUST BE CALLED
        Arc::new(Self {
            kind: Kind::Client { ca },
            cache: Mutex::new(Vec::new()),
        })
    }

    /// Give back an instance to cache.
    fn return_instance(&self, instance: Pin<Box<Instance>>) {
        self.cache.lock().unwrap().push(instance);
    }

    /// Get an instance, maybe from cache.
    fn get_instance(&self) -> Pin<Box<Instance>> {
        if let Some(mut v) = {
            // TODO: When to drop?
            let mut guard = self.cache.lock().unwrap();
            let e = guard.pop();
            drop(guard);
            e
        } {
            unsafe { mbedtls_ssl_session_reset(&mut v.ssl as _) };
            v
        } else {
            unsafe {
                let mut uninit = Box::new(MaybeUninit::<Instance>::uninit());
                let uninit_p = uninit.as_mut_ptr();
                macro_rules! p {
                    ($field:ident) => {
                        std::ptr::addr_of_mut!((*uninit_p).$field)
                    };
                }

                // init all
                mbedtls_entropy_init(p!(entropy));
                mbedtls_ctr_drbg_init(p!(ctr_drbg));
                mbedtls_x509_crt_init(p!(cert));
                mbedtls_pk_init(p!(pkey));
                mbedtls_ssl_config_init(p!(conf));
                mbedtls_ssl_init(p!(ssl));

                // drbg seed
                let pers = "tlsimple";
                let code = mbedtls_ctr_drbg_seed(
                    p!(ctr_drbg),
                    Some(mbedtls_entropy_func),
                    p!(entropy) as _,
                    pers.as_ptr(),
                    pers.len(),
                );
                assert_eq!(code, 0);

                // conf rng
                mbedtls_ssl_conf_rng(p!(conf), Some(mbedtls_ctr_drbg_random), p!(ctr_drbg) as _);

                // mbedtls_ssl_conf_early_data(p!(conf), MBEDTLS_SSL_EARLY_DATA_ENABLED);

                // server or client
                match &self.kind {
                    Kind::Server { cert, key, alpn } => {
                        // apply defaults
                        let code = mbedtls_ssl_config_defaults(
                            p!(conf),
                            MBEDTLS_SSL_IS_SERVER,
                            MBEDTLS_SSL_TRANSPORT_STREAM,
                            MBEDTLS_SSL_PRESET_DEFAULT,
                        );
                        assert_eq!(code, 0);

                        // server cert and key
                        let code = mbedtls_x509_crt_parse(p!(cert), cert.as_ptr(), cert.len());
                        assert_eq!(code, 0);
                        let code = mbedtls_pk_parse_key(
                            p!(pkey),
                            key.as_ptr(),
                            key.len(),
                            ptr::null(),
                            0,
                            Some(mbedtls_ctr_drbg_random),
                            p!(ctr_drbg) as _,
                        );
                        assert_eq!(code, 0);
                        let code = mbedtls_ssl_conf_own_cert(p!(conf), p!(cert), p!(pkey));
                        assert_eq!(code, 0);
                        // mbedtls_ssl_conf_ca_chain(p!(conf), (*p!(cert)).next, ptr::null_mut());

                        // alpn
                        if let Some(alpn) = alpn {
                            mbedtls_ssl_conf_alpn_protocols(p!(conf), alpn.0);
                        }

                        // limit ciphersuites
                        // static CIPHERSUITES: [i32; 2] =
                        //     [MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as i32, 0];
                        // only one ciphersuite. must be static here
                        // mbedtls_ssl_conf_ciphersuites(p!(conf), CIPHERSUITES.as_ptr());
                    }
                    Kind::Client { ca } => {
                        // apply defaults
                        let code = mbedtls_ssl_config_defaults(
                            p!(conf),
                            MBEDTLS_SSL_IS_CLIENT,
                            MBEDTLS_SSL_TRANSPORT_STREAM,
                            MBEDTLS_SSL_PRESET_DEFAULT,
                        );
                        assert_eq!(code, 0);

                        // verify ca
                        if let Some(ca) = ca {
                            for ca in ca {
                                // assert_eq!(ca.last(), Some(&0), "ca cert data must ends with zero");
                                let code =
                                    mbedtls_x509_crt_parse_der(p!(cert), ca.as_ptr(), ca.len());
                                assert_eq!(code, 0);
                            }
                            mbedtls_ssl_conf_ca_chain(p!(conf), p!(cert), ptr::null_mut());
                        } else {
                            // no ca specialed, set verify mode to none
                            // in mbedtls docs: server default = NONE, client default = REQUIRED
                            mbedtls_ssl_conf_authmode(p!(conf), MBEDTLS_SSL_VERIFY_NONE);
                        }
                    }
                };

                // setup ssl by conf
                let code = mbedtls_ssl_setup(p!(ssl), p!(conf));
                assert_eq!(code, 0);

                uninit.assume_init_ref(); // for the inner `intrinsics::assert_inhabited`;
                let pinned = Pin::new_unchecked(uninit); // do the same as Box::pin
                std::mem::transmute(pinned) // because MaybeUninit has `#[repr(transparent)]`
            }
        }
    }
}

struct Bio<S> {
    /// Origin stream.
    stream: S,
    /// Async context pointer, but store as usize.
    context: usize,
    /// Last error of origin stream.
    error: io::Result<()>,
}

pub struct TlsStream<S> {
    /// Referance to Config.
    config: Arc<TlsConfig>,
    /// Mbed-TLS structs.
    instance: ManuallyDrop<Pin<Box<Instance>>>,
    /// BIO, an I/O abstraction.
    bio: Pin<Box<Bio<S>>>,
}

impl<S> Drop for TlsStream<S> {
    fn drop(&mut self) {
        // println!(">>> {}::drop()", std::any::type_name::<Self>());
        // safety: instance will be drop in TlsConfig
        let instance = unsafe { ManuallyDrop::take(&mut self.instance) };
        self.config.return_instance(instance);
    }
}

impl<S> TlsStream<S> {
    pub fn close_notify(self) {
        todo!()
    }

    pub fn set_hostname(&mut self, mut hostname: String) {
        unsafe {
            assert!(hostname.len() < MBEDTLS_SSL_MAX_HOST_NAME_LEN as usize - 1);
            if !hostname.ends_with('\0') {
                hostname.push('\0');
            }
            let ssl_p = &mut self.instance.ssl as _;
            let code = mbedtls_ssl_set_hostname(ssl_p, hostname.as_ptr() as _);
            assert_eq!(code, 0);
        }
    }

    pub fn get_ciphersuite(&self) -> &'static str {
        unsafe {
            let p = mbedtls_ssl_get_ciphersuite(&self.instance.ssl as _);
            if p.is_null() {
                return "";
            }
            let mut len = 0;
            while *p.add(len) != '\0' as _ {
                len += 1;
            }
            std::str::from_utf8(slice::from_raw_parts(p as _, len)).unwrap()
        }
    }

    fn create(
        config: Arc<TlsConfig>,
        stream: S,
        f_send: unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int,
        f_recv: unsafe extern "C" fn(*mut c_void, *mut c_uchar, usize) -> c_int,
    ) -> Self {
        let mut ret = Self {
            instance: ManuallyDrop::new(config.get_instance()),
            config,
            bio: Box::pin(Bio {
                stream,
                context: 0,
                error: Ok(()),
            }),
        };
        unsafe {
            // safety: self.bio is Pin<Box<Bio>>, so what we do is the same of Box::pin
            let bio = ret.bio.as_mut().get_unchecked_mut();
            let ssl_p = &mut ret.instance.ssl as _;
            mbedtls_ssl_set_bio(ssl_p, bio as *mut _ as _, Some(f_send), Some(f_recv), None);
        }
        ret
    }

    unsafe fn take_bio_err(&mut self) -> io::Error {
        let bio = self.bio.as_mut().get_unchecked_mut();
        let mut err = Ok(());
        std::mem::swap(&mut bio.error, &mut err); // take out
        debug_assert!(err.is_err());
        err.unwrap_err_unchecked()
    }
}

impl<S: Read + Write> TlsStream<S> {
    unsafe extern "C" fn bio_send(p: *mut c_void, buf: *const u8, len: usize) -> i32 {
        let bio = &mut *(p as *mut Bio<S>);
        match bio.stream.write(slice::from_raw_parts(buf, len)) {
            Ok(n) => n as _,
            Err(e) => {
                bio.error = Err(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    unsafe extern "C" fn bio_recv(p: *mut c_void, buf: *mut u8, len: usize) -> i32 {
        let bio = &mut *(p as *mut Bio<S>);
        match bio.stream.read(slice::from_raw_parts_mut(buf, len)) {
            Ok(n) => n as _,
            Err(e) => {
                bio.error = Err(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    pub fn new_sync(config: Arc<TlsConfig>, stream: S) -> Self {
        Self::create(config, stream, Self::bio_send, Self::bio_recv)
    }
}

impl<S: Read> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let code = mbedtls_ssl_read(&mut self.instance.ssl as _, buf.as_mut_ptr(), buf.len());
            match code {
                0.. => Ok(code as _),
                _ if self.bio.error.is_err() => Err(self.take_bio_err()),
                _ => Err(io::Error::new(io::ErrorKind::Other, err_name(code))),
            }
        }
    }
}

impl<S: Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let code = mbedtls_ssl_write(&mut self.instance.ssl as _, buf.as_ptr(), buf.len());
            match code {
                0.. => Ok(code as _),
                _ if self.bio.error.is_err() => Err(self.take_bio_err()),
                _ => Err(io::Error::new(io::ErrorKind::Other, err_name(code))),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        unsafe {
            let bio = self.bio.as_mut().get_unchecked_mut();
            bio.stream.flush()
        }
    }
}

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "tokio")]
impl<S: AsyncRead + AsyncWrite> TlsStream<S> {
    unsafe extern "C" fn bio_send_async(p: *mut c_void, buf: *const u8, len: usize) -> i32 {
        let bio = &mut *(p as *mut Bio<S>);
        debug_assert_ne!(bio.context, 0);
        let cx = &mut *(bio.context as *mut _);
        let stream = Pin::new_unchecked(&mut bio.stream); // safety: it's sync, called in poll_xxx
        let write_buf = slice::from_raw_parts(buf, len);
        match stream.poll_write(cx, write_buf) {
            Poll::Pending => MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS, // FIXME: needs another custom error code
            Poll::Ready(Ok(n)) => n as _,
            Poll::Ready(Err(e)) => {
                bio.error = Err(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    unsafe extern "C" fn bio_recv_async(p: *mut c_void, buf: *mut u8, len: usize) -> i32 {
        let bio = &mut *(p as *mut Bio<S>);
        debug_assert_ne!(bio.context, 0);
        let cx = &mut *(bio.context as *mut _);
        let stream = Pin::new_unchecked(&mut bio.stream);
        let mut read_buf = ReadBuf::uninit(slice::from_raw_parts_mut(buf as _, len));
        match stream.poll_read(cx, &mut read_buf) {
            Poll::Pending => MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS,
            Poll::Ready(Ok(())) => read_buf.filled().len() as _,
            Poll::Ready(Err(e)) => {
                bio.error = Err(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    pub fn new_async(config: Arc<TlsConfig>, stream: S) -> Self {
        Self::create(config, stream, Self::bio_send_async, Self::bio_recv_async)
    }
}

#[cfg(feature = "tokio")]
impl<S: AsyncRead> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        unsafe {
            let slice = buf.unfilled_mut();
            let ssl_p = &mut self.instance.ssl as *mut _;

            let bio = self.bio.as_mut().get_unchecked_mut();
            bio.context = cx as *mut _ as _; // for the underlying bio_xxx_async
            let code = mbedtls_ssl_read(ssl_p, slice.as_mut_ptr() as _, slice.len());
            bio.context = 0;

            match code {
                0.. => {
                    buf.assume_init(code as _);
                    buf.advance(code as _);
                    Poll::Ready(Ok(()))
                }
                // if WANT_READ is from MbedTLS, call it again, if it's from tokio, return Pending and wait for the next wakeup
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_WANT_WRITE => self.poll_read(cx, buf),
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => self.poll_read(cx, buf), // skip session ticket
                MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS => Poll::Pending, // both WANT_READ and WANT_WRITE are possiable in the handshake stage
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                _ if self.bio.error.is_err() => Poll::Ready(Err(self.take_bio_err())),
                _ => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err_name(code)))),
            }
        }
    }
}

#[cfg(feature = "tokio")]
impl<S: AsyncWrite> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        unsafe {
            let ssl_p = &mut self.instance.ssl as *mut _;

            let bio = self.bio.as_mut().get_unchecked_mut();
            bio.context = cx as *mut _ as _;
            let code = mbedtls_ssl_write(ssl_p, buf.as_ptr(), buf.len());
            bio.context = 0;

            match code {
                0.. => Poll::Ready(Ok(code as usize)),
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_WANT_WRITE => self.poll_write(cx, buf),
                MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS => Poll::Pending,
                _ if self.bio.error.is_err() => Poll::Ready(Err(self.take_bio_err())),
                _ => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err_name(code)))),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        unsafe {
            let bio = self.bio.as_mut().get_unchecked_mut();
            Pin::new_unchecked(&mut bio.stream).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        unsafe {
            let bio = self.bio.as_mut().get_unchecked_mut();
            Pin::new_unchecked(&mut bio.stream).poll_shutdown(cx)
        }
    }
}

#[cfg(feature = "hyper-client")]
use {
    http::uri::Scheme,
    hyper::body::{Body, Incoming},
    hyper::{Request, Response},
    hyper_util::rt::tokio::TokioIo,
};

#[cfg(feature = "hyper-client")]
#[derive(Debug)]
pub enum ClientError {
    Connect(io::Error),
    Hyper(hyper::Error),
}

#[cfg(feature = "hyper-client")]
impl From<hyper::Error> for ClientError {
    fn from(value: hyper::Error) -> Self {
        Self::Hyper(value)
    }
}

#[cfg(feature = "hyper-client")]
impl From<io::Error> for ClientError {
    fn from(value: io::Error) -> Self {
        Self::Connect(value)
    }
}

#[cfg(feature = "hyper-client")]
impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "hyper-client")]
impl std::error::Error for ClientError {}

#[cfg(feature = "hyper-client")]
pub struct Client(Arc<TlsConfig>);

#[cfg(feature = "hyper-client")]
impl Client {
    pub fn default() -> Self {
        // fn cert_from_anchor(anchor: webpki_roots::TrustAnchor) -> Vec<u8> {}
        // for v in webpki_roots::TLS_SERVER_ROOTS { }

        let mut ca = Vec::new();
        for entry in std::fs::read_dir("/etc/ssl/certs").unwrap() {
            let entry = entry.unwrap();
            if !entry.metadata().unwrap().is_file() {
                continue;
            }
            let s = std::fs::read_to_string(entry.path()).unwrap();
            let mut der_base64 = String::new();
            for line in s.split('\n').skip(1) {
                if line.starts_with("-----") {
                    break;
                    // TODO?
                }
                der_base64 += line;
            }
            {
                use base64::{engine::general_purpose, Engine as _};
                let bytes = general_purpose::STANDARD.decode(der_base64).unwrap();
                ca.push(bytes);
            }
        }
        let config = TlsConfig::new_client(Some(ca));
        // let config = TlsConfig::new_client(None);
        Self(config)
    }

    pub async fn fetch<B>(&self, req: Request<B>) -> Result<Response<Incoming>, ClientError>
    where
        B: Body + 'static + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = req.uri();
        let scheme = uri.scheme();
        let host = uri.host().unwrap();
        let mut host_and_port = String::with_capacity(host.len() + 8);
        host_and_port += host;
        host_and_port.push(':');
        let port = uri.port_u16().unwrap_or(match () {
            _ if scheme == Some(&Scheme::HTTP) => 80,
            _ if scheme == Some(&Scheme::HTTPS) => 443,
            _ => panic!("unsupported scheme"),
        });
        {
            use std::fmt::Write as _;
            write!(&mut host_and_port, "{port}").unwrap();
        }
        let tcp_stream = tokio::net::TcpStream::connect(host_and_port).await?;

        if scheme == Some(&Scheme::HTTP) {
            let io = TokioIo::new(tcp_stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?; // only http1 currently
            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    println!("Connection failed: {:?}", err);
                }
            });
            return Ok(sender.send_request(req).await?);
        }

        if uri.scheme() == Some(&Scheme::HTTPS) {
            let mut tls_stream = TlsStream::new_async(self.0.clone(), tcp_stream);
            if let Kind::Client { ca: Some(_) } = self.0.kind {
                tls_stream.set_hostname(host.to_string()); // only host, not port
            }

            let io = TokioIo::new(tls_stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    println!("Connection failed: {:?}", err);
                }
            });
            return Ok(sender.send_request(req).await?);
        }

        unreachable!()
    }
}

#[cfg(feature = "tower-server")]
use {
    hyper_util::rt::TokioExecutor, std::convert::Infallible, std::future::poll_fn,
    tokio::io::AsyncWriteExt, tower_service::Service,
};

#[cfg(feature = "tower-server")]
pub async fn serve<S>(tls_config: Arc<TlsConfig>, tcp_listener: tokio::net::TcpListener, service: S)
where
    S: Service<Request<Incoming>, Response = Response<Incoming>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    loop {
        let (mut tcp_stream, _socket_addr) = match tcp_listener.accept().await {
            Ok(v) => v,
            _ => continue, // ignore error here?
        };
        // dbg!(socket_addr);
        let tls_config = tls_config.clone();
        let svc = service.clone();
        let hyper_service = hyper::service::service_fn(move |req| svc.clone().call(req));

        tokio::spawn(async move {
            // redirect HTTP to HTTPS
            let mut flag = [0]; // expect 0x16, TLS handshake
            let mut buf = tokio::io::ReadBuf::new(&mut flag);
            poll_fn(|cx| tcp_stream.poll_peek(cx, &mut buf)).await.ok();
            if flag[0] != 0x16 {
                const TO_HTTPS_PAGE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type:text/html\r\n\r\n<script>location=location.href.replace(':','s:')</script>\r\n\r\n\0";
                tcp_stream.write_all(TO_HTTPS_PAGE).await.ok();
                tcp_stream.shutdown().await.ok(); // remember to close stream
                return;
            }
            let tls_stream = TlsStream::new_async(tls_config, tcp_stream);
            let io = TokioIo::new(tls_stream);
            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
                .ok();
        });
    }
}
