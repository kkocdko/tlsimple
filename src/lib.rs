use std::error::Error;
use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
mod err;
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

// sure, this's dangerous, please ensure that you wrap this in a Pin
unsafe impl Send for Instance {}
unsafe impl Sync for Instance {}

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
        ca: Option<Vec<u8>>,
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

impl TlsConfig {
    /// Create a config for server.
    pub fn new_server(cert: Vec<u8>, key: Vec<u8>, alpn: Option<alpn::Alpn>) -> Arc<Self> {
        Arc::new(Self {
            kind: Kind::Server { cert, key, alpn },
            cache: Mutex::new(Vec::new()),
        })
    }

    /// Create a config for client.
    pub fn new_client(ca: Option<Vec<u8>>) -> Arc<Self> {
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
                            let code = mbedtls_x509_crt_parse_der(p!(cert), ca.as_ptr(), ca.len());
                            assert_eq!(code, 0);
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
    /// Origin stream
    stream: S,
    /// Async context pointer, but store as usize
    context: usize,
    // error: io::Result<()>, // maybe the last error of origin stream
}

pub struct TlsStream<S> {
    /// Referance to Config
    config: Arc<TlsConfig>,
    /// Mbed-TLS structs
    instance: ManuallyDrop<Pin<Box<Instance>>>,
    /// BIO
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
}

impl<S: Read + Write> TlsStream<S> {
    unsafe extern "C" fn bio_send(p: *mut c_void, buf: *const u8, len: usize) -> i32 {
        let bio = &mut *(p as *mut Bio<S>);
        match bio.stream.write(slice::from_raw_parts(buf, len)) {
            Ok(n) => n as _,
            Err(e) => {
                dbg!(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    unsafe extern "C" fn bio_recv(p: *mut c_void, buf: *mut u8, len: usize) -> i32 {
        let bio = &mut *(p as *mut Bio<S>);
        match bio.stream.read(slice::from_raw_parts_mut(buf, len)) {
            Ok(n) => n as _,
            Err(e) => {
                dbg!(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    pub fn new_sync(config: Arc<TlsConfig>, stream: S) -> Self {
        let mut ret = Self {
            instance: ManuallyDrop::new(config.get_instance()),
            config,
            bio: Box::pin(Bio { stream, context: 0 }),
        };
        unsafe {
            // safety: self.bio is Pin<Box<Bio>>, so what we do is the same of Box::pin
            let bio = ret.bio.as_mut().get_unchecked_mut();
            // set the bio
            mbedtls_ssl_set_bio(
                &mut ret.instance.ssl as _,
                bio as *mut _ as _,
                Some(Self::bio_send),
                Some(Self::bio_recv),
                None,
            );
        }
        ret
    }
}

impl<S: Read> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let ssl_p = &mut self.instance.ssl as *mut _;
            let code = mbedtls_ssl_read(ssl_p, buf.as_mut_ptr(), buf.len());
            match code {
                // FIXME
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                // FIXME: <= 0 or < 0 ?
                _ if code < 0 => {
                    let err_name = err::err_name(code);
                    Err(io::Error::new(io::ErrorKind::Other, err_name))
                }
                _ => Ok(code as _),
            }
        }
    }
}

impl<S: Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let ssl_p = &mut self.instance.ssl as *mut _;
            let code = mbedtls_ssl_write(ssl_p, buf.as_ptr(), buf.len());
            match code {
                _ if code < 0 => {
                    let err_name = err::err_name(code);
                    Err(io::Error::new(io::ErrorKind::Other, err_name))
                }
                _ => Ok(code as _),
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
            Poll::Pending => MBEDTLS_ERR_SSL_WANT_WRITE,
            Poll::Ready(Ok(n)) => n as _,
            Poll::Ready(Err(e)) => {
                dbg!(e);
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
            Poll::Pending => MBEDTLS_ERR_SSL_WANT_READ,
            Poll::Ready(Ok(())) => read_buf.filled().len() as _,
            Poll::Ready(Err(e)) => {
                dbg!(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    pub fn new_async(config: Arc<TlsConfig>, stream: S) -> Self {
        let mut ret = Self {
            instance: ManuallyDrop::new(config.get_instance()),
            config,
            bio: Box::pin(Bio { stream, context: 0 }),
        };
        unsafe {
            let bio = ret.bio.as_mut().get_unchecked_mut();
            mbedtls_ssl_set_bio(
                &mut ret.instance.ssl as _,
                bio as *mut _ as _,
                Some(Self::bio_send_async),
                Some(Self::bio_recv_async),
                None,
            );
        }
        ret
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
                // both WANT_READ and WANT_WRITE are possiable in the handshake stage
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_WANT_WRITE => Poll::Pending,
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                // question: <= 0 or < 0 ?
                _ if code < 0 => {
                    let err_name = err::err_name(code);
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err_name)))
                }
                _ => {
                    buf.assume_init(code as _);
                    buf.advance(code as _);
                    Poll::Ready(Ok(()))
                }
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
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_WANT_WRITE => Poll::Pending,
                // question: <= 0 or < 0 ?
                _ if code < 0 => {
                    let err_name = err::err_name(code);
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err_name)))
                }
                _ => Poll::Ready(Ok(code as usize)),
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
use hyper::{
    client::connect::{Connected, Connection},
    http::uri::{Scheme, Uri},
    service::Service,
};

#[cfg(feature = "hyper-client")]
impl<S: Connection> Connection for TlsStream<S> {
    fn connected(&self) -> Connected {
        self.bio.stream.connected()
    }
}

#[cfg(feature = "hyper-client")]
#[derive(Clone)]
/// Unlike hyper-rustls, this one is always force-https.
pub struct HttpsConnector<T> {
    http: T,
    config: Arc<TlsConfig>,
}

#[cfg(feature = "hyper-client")]
impl<T> HttpsConnector<T> {
    pub fn new(http: T, config: Arc<TlsConfig>) -> Self {
        Self { http, config }
    }
}

#[cfg(feature = "hyper-client")]
impl<S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri>,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Send + 'static,
    S::Response: AsyncRead + AsyncWrite + Connection + Send + Unpin + 'static,
{
    type Response = TlsStream<S::Response>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        assert!(uri.scheme() == Some(&Scheme::HTTPS));
        let hostname = uri.host().unwrap().to_string();
        let connect = self.http.call(uri);
        let config = self.config.clone();
        Box::pin(async move {
            let conn = connect.await?;
            let has_ca = matches!(&config.kind, Kind::Client { ca: Some(_) });
            let mut stream = TlsStream::new_async(config, conn);
            if has_ca {
                stream.set_hostname(hostname);
            }
            Ok(stream)
        })
    }
}
