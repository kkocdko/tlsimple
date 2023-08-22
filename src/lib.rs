use std::error::Error;
use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::io::{Read, Write};
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
    pub const H1: *mut *const std::ffi::c_char =
        &[b"http/1.1\0" as _, ptr::null() as *const u8] as *const _ as _;
    pub const H2: *mut *const std::ffi::c_char =
        &[b"h2\0" as _, ptr::null() as *const u8] as *const _ as _;
    pub const H1H2: *mut *const std::ffi::c_char =
        &[b"http/1.1\0" as _, b"h2\0" as _, ptr::null() as *const u8] as *const _ as _;
    pub const H2H1: *mut *const std::ffi::c_char =
        &[b"h2\0" as _, b"http/1.1\0" as _, ptr::null() as *const u8] as *const _ as _;
}

// Why not mbedtls_threading_set_alt?
// https://mbed-tls.readthedocs.io/en/latest/kb/development/thread-safety-and-multi-threading/
// https://mbed-tls.readthedocs.io/en/latest/kb/how-to/how-do-i-tune-elliptic-curves-resource-usage/?highlight=performance#performance-and-ram-figures

// pub struct TlsProfile {
//     entropy: mbedtls_entropy_context,
//     ctr_drbg: mbedtls_ctr_drbg_context,
//     cert: mbedtls_x509_crt,
//     pkey: mbedtls_pk_context,
//     conf: mbedtls_ssl_config,
//     ssl: mbedtls_ssl_context,
// }

// pub struct TlsConfig2 {
//     cache: Mutex<Vec<Pin<Box<TlsProfile>>>>,
// }

pub struct TlsConfig {
    entropy: mbedtls_entropy_context,
    ctr_drbg: mbedtls_ctr_drbg_context,
    cert: mbedtls_x509_crt,
    pkey: mbedtls_pk_context,
    conf: mbedtls_ssl_config,
}

// Is this dangerous?
// I think if we always use TlsConfig::new_xxx which returns Pin<Arc> will be fine.
unsafe impl Sync for TlsConfig {}
unsafe impl Send for TlsConfig {}

impl Drop for TlsConfig {
    fn drop(&mut self) {
        unsafe {
            // println!(">>> TlsConfig::drop()");
            mbedtls_ssl_config_free(&mut self.conf as _);
            mbedtls_pk_free(&mut self.pkey as _);
            mbedtls_x509_crt_free(&mut self.cert as _);
            mbedtls_ctr_drbg_free(&mut self.ctr_drbg as _);
            mbedtls_entropy_free(&mut self.entropy as _);
        }
    }
}

impl TlsConfig {
    /// Prepare and init inner structs.
    unsafe fn prepare_init(place: *mut TlsConfig) {
        macro_rules! p {
            ($field:ident) => {
                std::ptr::addr_of_mut!((*place).$field)
            };
        }

        mbedtls_entropy_init(p!(entropy));
        mbedtls_ctr_drbg_init(p!(ctr_drbg));
        mbedtls_x509_crt_init(p!(cert));
        mbedtls_pk_init(p!(pkey));
        mbedtls_ssl_config_init(p!(conf));

        let pers = "tlsimple";
        let code = mbedtls_ctr_drbg_seed(
            p!(ctr_drbg),
            Some(mbedtls_entropy_func),
            p!(entropy) as _,
            pers.as_ptr(),
            pers.len(),
        );
        assert_eq!(code, 0);

        mbedtls_ssl_conf_rng(p!(conf), Some(mbedtls_ctr_drbg_random), p!(ctr_drbg) as _);
    }

    /// Init a config for server inplace.
    pub unsafe fn init_server(
        place: &mut MaybeUninit<Self>,
        cert: &[u8],
        key: &[u8],
        alpn: Option<*mut *const std::ffi::c_char>,
    ) {
        let p = place.as_mut_ptr();
        Self::prepare_init(p);
        macro_rules! p {
            ($field:ident) => {
                std::ptr::addr_of_mut!((*p).$field)
            };
        }

        let code = mbedtls_ssl_config_defaults(
            p!(conf),
            MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT,
        );
        assert_eq!(code, 0);

        // safety: cert and key will be cloned by mbedtls_xxx_parse function

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

        // mbedtls_ssl_conf_ca_chain(p!(conf), (*p!(cert)).next, ptr::null_mut());

        let code = mbedtls_ssl_conf_own_cert(p!(conf), p!(cert), p!(pkey));
        assert_eq!(code, 0);

        if let Some(alpn) = alpn {
            mbedtls_ssl_conf_alpn_protocols(p!(conf), alpn);
        }

        // static CIPHERSUITES: [i32; 2] =
        //     [MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as i32, 0]; // only one ciphersuite. must be static here, or AddressSanitizer: heap-use-after-free
        // mbedtls_ssl_conf_ciphersuites(p!(conf), CIPHERSUITES.as_ptr());
    }

    /// Init a config for client inplace.
    pub unsafe fn init_client(place: &mut MaybeUninit<Self>, ca: Option<&[u8]>) {
        let p = place.as_mut_ptr();
        Self::prepare_init(p);
        macro_rules! p {
            ($field:ident) => {
                std::ptr::addr_of_mut!((*p).$field)
            };
        }

        let code = mbedtls_ssl_config_defaults(
            p!(conf),
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT,
        );
        assert_eq!(code, 0);

        if let Some(ca) = ca {
            let code = mbedtls_x509_crt_parse(p!(cert), ca.as_ptr(), ca.len());
            assert_eq!(code, 0);

            mbedtls_ssl_conf_ca_chain(p!(conf), p!(cert), ptr::null_mut());
            // mbedtls_ssl_set_hostname(ss;, hostname)
        } else {
            // in mbedtls docs: server default = NONE, client default = REQUIRED
            mbedtls_ssl_conf_authmode(p!(conf), MBEDTLS_SSL_VERIFY_NONE);
        }
    }

    /// Create a config for server.
    pub fn new_server(
        cert: &[u8],
        key: &[u8],
        alpn: Option<*mut *const std::ffi::c_char>,
    ) -> Pin<Arc<Self>> {
        unsafe {
            let mut place = Arc::new(MaybeUninit::uninit());
            Self::init_server(Arc::get_mut(&mut place).unwrap(), cert, key, alpn);
            let place = Pin::new_unchecked(place);
            place.assume_init_ref(); // for the inner `intrinsics::assert_inhabited`;
            std::mem::transmute(place) // because MaybeUninit has `#[repr(transparent)]`
        }
    }

    /// Create a config for client.
    pub fn new_client(ca: Option<&[u8]>) -> Pin<Arc<Self>> {
        unsafe {
            let mut place = Arc::new(MaybeUninit::uninit());
            Self::init_client(Arc::get_mut(&mut place).unwrap(), ca);
            let place = Pin::new_unchecked(place);
            place.assume_init_ref();
            std::mem::transmute(place)
        }
    }
}

pub struct TlsStream<S> {
    tls_config: Pin<Arc<TlsConfig>>,
    stream: S,
    ssl: mbedtls_ssl_context,
    context: usize,
    // error: io::Result<()>,
}

// Is this dangerous?
unsafe impl<S> Sync for TlsStream<S> {}
unsafe impl<S> Send for TlsStream<S> {}

impl<S> Drop for TlsStream<S> {
    fn drop(&mut self) {
        unsafe {
            // println!(">>> TlsStream::drop()");
            mbedtls_ssl_free(&mut self.ssl as _);
        }
    }
}

impl<S> TlsStream<S> {
    /// Inplace constructor.
    pub unsafe fn init_inplace(
        place: &mut MaybeUninit<Self>,
        tls_config: Pin<Arc<TlsConfig>>,
        stream: S,
        bio_send: mbedtls_ssl_send_t,
        bio_recv: mbedtls_ssl_recv_t,
    ) {
        let conf_p = &tls_config.conf as _;
        place.write(Self {
            tls_config,
            stream,
            #[allow(invalid_value)]
            ssl: MaybeUninit::uninit().assume_init(), // is safe, see MaybeUninit's docs
            context: 0,
        });
        let ssl_p = std::ptr::addr_of_mut!((*place.as_mut_ptr()).ssl);
        mbedtls_ssl_init(ssl_p);
        let code = mbedtls_ssl_setup(ssl_p, conf_p);
        assert_eq!(code, 0);
        // let code = mbedtls_ssl_session_reset(ssl_p);
        mbedtls_ssl_set_bio(ssl_p, place.as_mut_ptr() as _, bio_send, bio_recv, None);
    }

    fn accept(&mut self) {
        unsafe {
            // this seems redundant? mbedtls will auto do handshake on first read / write?
            let code = mbedtls_ssl_handshake(&mut self.ssl as *mut _);
            assert_eq!(code, 0);
        }
    }

    pub fn set_hostname(&mut self, mut hostname: String) {
        // to be a zero suffix c string
        if !hostname.ends_with('\0') {
            hostname.push('\0');
        }
        unsafe {
            // safety: this function alloc and clone hostname inside
            let code = mbedtls_ssl_set_hostname(&mut self.ssl as *mut _, hostname.as_ptr() as _);
            assert_eq!(code, 0);
        }
    }

    pub fn close_notify(&mut self) {
        unsafe {
            // will be received on read / write error
            let code = mbedtls_ssl_close_notify(&mut self.ssl as *mut _);
            assert_eq!(code, 0);
        }
    }

    pub fn get_ciphersuite(&self) -> &'static str {
        unsafe {
            let p = mbedtls_ssl_get_ciphersuite(&self.ssl as _);
            if p.is_null() {
                return "";
            }
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            std::str::from_utf8_unchecked(slice::from_raw_parts(p as _, len))
        }
    }
}

impl<S: Read + Write + Unpin> TlsStream<S> {
    unsafe extern "C" fn bio_send(ctx: *mut c_void, buf: *const u8, len: usize) -> i32 {
        let this = &mut *(ctx as *mut Self);
        match this.stream.write(slice::from_raw_parts(buf, len)) {
            Ok(n) => n as _,
            Err(e) => {
                dbg!(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    unsafe extern "C" fn bio_recv(ctx: *mut c_void, buf: *mut u8, len: usize) -> i32 {
        let this = &mut *(ctx as *mut Self);
        match this.stream.read(slice::from_raw_parts_mut(buf, len)) {
            Ok(n) => n as _,
            Err(e) => {
                dbg!(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    pub fn new_sync(tls_config: Pin<Arc<TlsConfig>>, stream: S) -> Pin<Box<Self>> {
        unsafe {
            let mut place = Box::pin(MaybeUninit::<Self>::uninit());
            Self::init_inplace(
                &mut place,
                tls_config,
                stream,
                Some(Self::bio_send),
                Some(Self::bio_recv),
            );
            place.assume_init_ref();
            std::mem::transmute(place)
        }
    }
}

impl<S: Read> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let code = mbedtls_ssl_read(&mut self.ssl as *mut _, buf.as_mut_ptr(), buf.len());
            match code {
                // MBEDTLS_ERR_SSL_WANT_READ => Err(io::Error::from(io::ErrorKind::WouldBlock)),
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

impl<S: Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let code = mbedtls_ssl_write(&mut self.ssl as *mut _, buf.as_ptr(), buf.len());
            match code {
                // MBEDTLS_ERR_SSL_WANT_WRITE => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                _ if code < 0 => {
                    let err_name = err::err_name(code);
                    Err(io::Error::new(io::ErrorKind::Other, err_name))
                }
                _ => Ok(code as _),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "tokio")]
impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context) {
        debug_assert_ne!(self.context, 0);
        let stream = Pin::new_unchecked(&mut self.stream);
        let context = &mut *(self.context as *mut _);
        (stream, context)
    }

    unsafe extern "C" fn bio_send_async(ctx: *mut c_void, buf: *const u8, len: usize) -> i32 {
        let this = &mut *(ctx as *mut Self);
        let (stream, context) = this.parts();
        let write_buf = slice::from_raw_parts(buf, len);
        match stream.poll_write(context, write_buf) {
            Poll::Pending => MBEDTLS_ERR_SSL_WANT_WRITE,
            Poll::Ready(Ok(n)) => n as _,
            Poll::Ready(Err(e)) => {
                dbg!(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    unsafe extern "C" fn bio_recv_async(ctx: *mut c_void, buf: *mut u8, len: usize) -> i32 {
        let this = &mut *(ctx as *mut Self);
        let (stream, context) = this.parts();
        let mut read_buf = ReadBuf::uninit(slice::from_raw_parts_mut(buf as _, len));
        match stream.poll_read(context, &mut read_buf) {
            Poll::Pending => MBEDTLS_ERR_SSL_WANT_READ,
            Poll::Ready(Ok(())) => read_buf.filled().len() as _,
            Poll::Ready(Err(e)) => {
                dbg!(e);
                MBEDTLS_ERR_SSL_INTERNAL_ERROR
            }
        }
    }

    pub fn new_async(tls_config: Pin<Arc<TlsConfig>>, stream: S) -> Pin<Box<Self>> {
        unsafe {
            let mut place = Box::pin(MaybeUninit::<Self>::uninit());
            Self::init_inplace(
                &mut place,
                tls_config,
                stream,
                Some(Self::bio_send_async),
                Some(Self::bio_recv_async),
            );
            place.assume_init_ref();
            std::mem::transmute(place)
        }
    }
}

#[cfg(feature = "tokio")]
impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.context = cx as *mut _ as _;
        let ret = unsafe {
            let slice = buf.unfilled_mut();
            let code = mbedtls_ssl_read(
                &mut self.ssl as *mut _,
                slice.as_mut_ptr() as _,
                slice.len(),
            );
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
        self.context = 0;
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
        self.context = cx as *mut _ as _;
        let ret = unsafe {
            let code = mbedtls_ssl_write(&mut self.ssl as *mut _, buf.as_ptr(), buf.len());
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
        self.context = 0;
        ret
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.stream).poll_flush(cx) }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.stream).poll_shutdown(cx) }
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
