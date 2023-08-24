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
    use std::ptr;
    pub struct Alpn(pub(crate) *mut *const std::ffi::c_char);
    unsafe impl Send for Alpn {}
    unsafe impl Sync for Alpn {}
    pub const H1: Alpn = Alpn(&[b"http/1.1\0" as _, ptr::null() as *const u8] as *const _ as _);
    pub const H2: Alpn = Alpn(&[b"h2\0" as _, ptr::null() as *const u8] as *const _ as _);
    pub const H1H2: Alpn =
        Alpn(&[b"http/1.1\0" as _, b"h2\0" as _, ptr::null() as *const u8] as *const _ as _);
    pub const H2H1: Alpn =
        Alpn(&[b"h2\0" as _, b"http/1.1\0" as _, ptr::null() as *const u8] as *const _ as _);
}

// Why not mbedtls_threading_set_alt?
// https://mbed-tls.readthedocs.io/en/latest/kb/development/thread-safety-and-multi-threading/
// https://mbed-tls.readthedocs.io/en/latest/kb/how-to/how-do-i-tune-elliptic-curves-resource-usage/?highlight=performance#performance-and-ram-figures

struct Instance {
    entropy: mbedtls_entropy_context,
    ctr_drbg: mbedtls_ctr_drbg_context,
    cert: mbedtls_x509_crt,
    pkey: mbedtls_pk_context,
    conf: mbedtls_ssl_config,
    ssl: mbedtls_ssl_context,
}

unsafe impl Send for Instance {}
unsafe impl Sync for Instance {}

impl Drop for Instance {
    fn drop(&mut self) {
        println!(">>> {}::drop()", std::any::type_name::<Self>());
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
    cache: Mutex<Vec<Pin<Box<Instance>>>>, // 先暴力实现，以后再搞个无锁队列什么的
}

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

    fn return_instance(&self, instance: Pin<Box<Instance>>) {
        self.cache.lock().unwrap().push(instance);
    }

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
                        static CIPHERSUITES: [i32; 2] =
                            [MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as i32, 0];
                        // only one ciphersuite. must be static here, or AddressSanitizer: heap-use-after-free
                        mbedtls_ssl_conf_ciphersuites(p!(conf), CIPHERSUITES.as_ptr());
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

                        // vertify ca
                        if let Some(ca) = ca {
                            let code = mbedtls_x509_crt_parse(p!(cert), ca.as_ptr(), ca.len());
                            assert_eq!(code, 0);
                            mbedtls_ssl_conf_ca_chain(p!(conf), p!(cert), ptr::null_mut());
                            // FIXME
                            // mbedtls_ssl_set_hostname(ssl, hostname);
                        } else {
                            // in mbedtls docs: server default = NONE, client default = REQUIRED
                            mbedtls_ssl_conf_authmode(p!(conf), MBEDTLS_SSL_VERIFY_NONE);
                        }
                    }
                };

                // setup ssl by conf
                let code = mbedtls_ssl_setup(p!(ssl), p!(conf));
                assert_eq!(code, 0);

                uninit.assume_init_ref(); // for the inner `intrinsics::assert_inhabited`;
                let pinned = Pin::new_unchecked(uninit);
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
        // SAFETY: instance will be drop in TlsConfig
        // ManuallyDrop::
        let instance = unsafe { ManuallyDrop::take(&mut self.instance) };
        self.config.return_instance(instance);
    }
}

impl<S: Read + Write + Unpin> TlsStream<S> {
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
            mbedtls_ssl_set_bio(
                &mut ret.instance.ssl as _,
                &mut *ret.bio as *mut _ as _,
                Some(Self::bio_send),
                Some(Self::bio_recv),
                None,
            );
        }
        ret
    }
}

impl<S: Read + Write + Unpin> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let ssl_p = &mut self.instance.ssl as *mut _;
            let code = mbedtls_ssl_read(ssl_p, buf.as_mut_ptr(), buf.len());
            match code {
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                // question: <= 0 or < 0 ?
                _ if code < 0 => {
                    let err_name = err::err_name(code);
                    Err(io::Error::new(io::ErrorKind::Other, err_name))
                }
                _ => Ok(code as _),
            }
        }
    }
}

impl<S: Read + Write + Unpin> Write for TlsStream<S> {
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
        self.bio.stream.flush()
    }
}

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "tokio")]
impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    // # Safety
    //
    // Must be called with `context` set to a valid pointer to a live `Context` object, and the
    // wrapper must be pinned in memory.
    // unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context) {
    //     debug_assert_ne!(self.context, 0);
    //     let stream = Pin::new_unchecked(&mut self.stream);
    //     let context = &mut *(self.context as *mut _);
    //     (stream, context)
    // }

    unsafe extern "C" fn bio_send_async(p: *mut c_void, buf: *const u8, len: usize) -> i32 {
        let bio = &mut *(p as *mut Bio<S>);
        debug_assert_ne!(bio.context, 0);
        let cx = &mut *(bio.context as *mut _);
        let stream = Pin::new(&mut bio.stream);
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
        let stream = Pin::new(&mut bio.stream);
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
            mbedtls_ssl_set_bio(
                &mut ret.instance.ssl as _,
                &mut *ret.bio as *mut _ as _,
                Some(Self::bio_send_async),
                Some(Self::bio_recv_async),
                None,
            );
        }
        ret
    }
}

#[cfg(feature = "tokio")]
impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.bio.context = cx as *mut _ as _;
        let ret = unsafe {
            let slice = buf.unfilled_mut();
            let ssl_p = &mut self.instance.ssl as *mut _;
            let code = mbedtls_ssl_read(ssl_p, slice.as_mut_ptr() as _, slice.len());
            match code {
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
            // todo!()
        };
        self.bio.context = 0;
        ret
    }
}

#[cfg(feature = "tokio")]
impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.bio.context = cx as *mut _ as _;
        let ret = unsafe {
            let ssl_p = &mut self.instance.ssl as *mut _;
            let code = mbedtls_ssl_write(ssl_p, buf.as_ptr(), buf.len());
            match code {
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_WANT_WRITE => Poll::Pending,
                // question: <= 0 or < 0 ?
                _ if code < 0 => {
                    let err_name = err::err_name(code);
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err_name)))
                }
                _ => Poll::Ready(Ok(code as usize)),
            }
        };
        self.bio.context = 0;
        ret
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.bio.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.bio.stream).poll_shutdown(cx)
    }
}

/*
#[cfg(feature = "hyper-client")]
use hyper::{
    client::connect::{Connected, Connection},
    http::uri::{Scheme, Uri},
    service::Service,
};

#[cfg(feature = "hyper-client")]
impl<S: Connection> Connection for TlsStream<S> {
    fn connected(&self) -> Connected {
        self.stream.connected()
    }
}

#[cfg(feature = "hyper-client")]
#[derive(Clone)]
/// Unlike hyper-rustls, this one is always force-https.
pub struct HttpsConnector<T> {
    http: T,
    tls_config: Pin<Arc<TlsConfig>>,
}

#[cfg(feature = "hyper-client")]
impl<T> HttpsConnector<T> {
    pub fn new(http: T, tls_config: Pin<Arc<TlsConfig>>) -> Self {
        Self { http, tls_config }
    }
}

// trait AA=AsyncRead + AsyncWrite + Connection + Send;

#[cfg(feature = "hyper-client")]
impl<S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri>,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Send + 'static,
    S::Response: AsyncRead + AsyncWrite + Connection + Send + Unpin + 'static,
{
    // FIXME
    type Response = TlsStream<S::Response>;
    // type Response = Pin<Box<dyn Connection + Send>>;
    type Error = S::Error;
    // type Error = Box<dyn Error + Sync + Send>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx)
        // self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let is_tls = uri.scheme() == Some(&Scheme::HTTPS);
        let connect = self.http.call(uri);
        let tls_config = self.tls_config.clone();
        todo!()
        // Box::pin(async move {
        //     let conn = connect.await?;
        //     let aa: Pin<Box<dyn Connection + Send>> = TlsStream::new_async(tls_config, conn);
        //     Ok(aa)
        //     // todo!()
        //     // Ok(TlsStream::new_async(tls_config, conn) as _)
        // })
    }
}
*/
