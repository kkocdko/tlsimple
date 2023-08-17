use std::borrow::BorrowMut;
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
use std::task::Context;
use std::task::Poll;

mod ffi;
mod mbedtls_err;
use ffi::*;

pub mod alpn {
    use std::ptr;
    pub const NULL: *mut *const std::ffi::c_char = ptr::null_mut() as _;
    pub const H1: *mut *const std::ffi::c_char =
        &[b"http/1.1\0" as _, ptr::null() as *const u8] as *const _ as _;
    pub const H2: *mut *const std::ffi::c_char =
        &[b"h2\0" as _, ptr::null() as *const u8] as *const _ as _;
    pub const H1H2: *mut *const std::ffi::c_char =
        &[b"http/1.1\0" as _, b"h2\0" as _, ptr::null() as *const u8] as *const _ as _;
    pub const H2H1: *mut *const std::ffi::c_char =
        &[b"h2\0" as _, b"http/1.1\0" as _, ptr::null() as *const u8] as *const _ as _;
}

enum TlsKind<'a> {
    Server {
        cert: &'a [u8],
        key: &'a [u8],
        alpn: *mut *const std::ffi::c_char,
    },
    Client {
        ca: &'a [u8],
        // alpn: *mut *const std::ffi::c_char,
    },
}

pub struct TlsConfig {
    entropy: mbedtls_entropy_context,
    ctr_drbg: mbedtls_ctr_drbg_context,
    cert: mbedtls_x509_crt,
    pkey: mbedtls_pk_context,
    conf: mbedtls_ssl_config,
}

// is this dangerous? I think if we always use TlsConfig::new which returns Pin<Box> will be fine
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
    unsafe fn init_inplace(place: &mut MaybeUninit<Self>, kind: TlsKind) {
        let p = place.as_mut_ptr();
        macro_rules! field {
            ($field:ident) => {
                std::ptr::addr_of_mut!((*p).$field)
            };
        }
        let mut ret;

        let entropy_p = field!(entropy);
        let ctr_drbg_p = field!(ctr_drbg);
        let cert_p = field!(cert);
        let pkey_p = field!(pkey);
        let conf_p = field!(conf);

        mbedtls_entropy_init(entropy_p);

        mbedtls_ctr_drbg_init(ctr_drbg_p);
        let pers = "tlsimple";
        ret = mbedtls_ctr_drbg_seed(
            ctr_drbg_p,
            Some(mbedtls_entropy_func),
            entropy_p as _,
            pers.as_ptr(),
            pers.len(),
        );
        assert_eq!(ret, 0);

        if let TlsKind::Client { ca } = kind {
            mbedtls_x509_crt_init(cert_p);
            ret = mbedtls_x509_crt_parse(cert_p, ca.as_ptr(), ca.len());
            assert_eq!(ret, 0);

            mbedtls_ssl_config_init(conf_p);
            ret = mbedtls_ssl_config_defaults(
                conf_p,
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT,
            );
            assert_eq!(ret, 0);
            mbedtls_ssl_conf_rng(conf_p, Some(mbedtls_ctr_drbg_random), ctr_drbg_p as _);

            mbedtls_ssl_conf_ca_chain(conf_p, cert_p, ptr::null_mut());
            // in mbedtls docs: Default = NONE on server, REQUIRED on client
            mbedtls_ssl_conf_authmode(conf_p, MBEDTLS_SSL_VERIFY_NONE);
            // mbedtls_ssl_conf_authmode(
            //     conf_p,
            //     if vertify {
            //         MBEDTLS_SSL_VERIFY_NONE
            //     } else {
            //         MBEDTLS_SSL_VERIFY_REQUIRED
            //     },
            // );
            // mbedtls_ssl_set_hostname(ss;, hostname)
        }

        if let TlsKind::Server { cert, key, alpn } = kind {
            // safety: cert and key will be cloned by mbedtls_xxx_parse function
            mbedtls_x509_crt_init(cert_p);
            ret = mbedtls_x509_crt_parse(cert_p, cert.as_ptr(), cert.len());
            assert_eq!(ret, 0);

            mbedtls_pk_init(pkey_p);
            ret = mbedtls_pk_parse_key(
                pkey_p,
                key.as_ptr(),
                key.len(),
                ptr::null(),
                0,
                Some(mbedtls_ctr_drbg_random),
                ctr_drbg_p as _,
            );
            assert_eq!(ret, 0);

            mbedtls_ssl_config_init(conf_p);
            ret = mbedtls_ssl_config_defaults(
                conf_p,
                MBEDTLS_SSL_IS_SERVER,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT,
            );
            assert_eq!(ret, 0);
            mbedtls_ssl_conf_rng(conf_p, Some(mbedtls_ctr_drbg_random), ctr_drbg_p as _);
            mbedtls_ssl_conf_ca_chain(conf_p, (*cert_p).next, ptr::null_mut());
            ret = mbedtls_ssl_conf_own_cert(conf_p, cert_p, pkey_p);
            assert_eq!(ret, 0);

            if alpn != alpn::NULL {
                mbedtls_ssl_conf_alpn_protocols(conf_p, alpn);
            }

            // static CIPHERSUITES: [i32; 2] =
            //     [MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as i32, 0]; // only one ciphersuite. must be static here, or AddressSanitizer: heap-use-after-free
            // mbedtls_ssl_conf_ciphersuites(conf_p, CIPHERSUITES.as_ptr());
        }
    }

    unsafe fn build(kind: TlsKind) -> Pin<Arc<Self>> {
        let mut place = Arc::new(MaybeUninit::uninit());
        Self::init_inplace(Arc::get_mut(&mut place).unwrap(), kind);
        let place = Pin::new_unchecked(place);
        place.assume_init_ref(); // for the inner `intrinsics::assert_inhabited`;
        std::mem::transmute(place) // because MaybeUninit has `#[repr(transparent)]`
    }

    pub fn new_server(
        cert: &[u8],
        key: &[u8],
        alpn: *mut *const std::ffi::c_char,
    ) -> Pin<Arc<Self>> {
        unsafe { Self::build(TlsKind::Server { cert, key, alpn }) }
    }

    pub fn new_client(ca: &[u8]) -> Pin<Arc<Self>> {
        unsafe { Self::build(TlsKind::Client { ca }) }
    }
}

pub struct TlsStream<S> {
    tls_config: Pin<Arc<TlsConfig>>,
    stream: S,
    ssl: mbedtls_ssl_context,
    context: usize,
    // error: io::Result<()>,
}

// is this dangerous?
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
        let ret = mbedtls_ssl_setup(ssl_p, conf_p);
        assert_eq!(ret, 0);
        // let ret = mbedtls_ssl_session_reset(ssl_p);
        mbedtls_ssl_set_bio(ssl_p, place.as_mut_ptr() as _, bio_send, bio_recv, None);
    }

    fn accept(&mut self) {
        unsafe {
            let ret = mbedtls_ssl_handshake(&mut self.ssl as *mut _);
            assert_eq!(ret, 0);
        }
    }

    pub fn set_hostname(&mut self, mut hostname: String) {
        if !hostname.ends_with('\0') {
            hostname.push('\0');
        }
        unsafe {
            let ret = mbedtls_ssl_set_hostname(&mut self.ssl as *mut _, hostname.as_ptr() as _);
            assert_eq!(ret, 0);
        }
    }

    pub fn close_notify(&mut self) {
        unsafe {
            let ret = mbedtls_ssl_close_notify(&mut self.ssl as *mut _);
            assert_eq!(ret, 0);
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

    pub fn get_ref_stream(&self) -> &S {
        &self.stream
    }
}

impl<S: Read + Write + Unpin> TlsStream<S> {
    pub fn new_sync(tls_config: Pin<Arc<TlsConfig>>, stream: S) -> Pin<Box<Self>> {
        unsafe extern "C" fn bio_send<S: Read + Write>(
            ctx: *mut c_void,
            buf: *const u8,
            len: usize,
        ) -> i32 {
            let this = &mut *(ctx as *mut TlsStream<S>);
            match this.stream.write(slice::from_raw_parts(buf, len)) {
                Ok(n) => n as _,
                // Err(e) if e.kind() == io::ErrorKind::WouldBlock => MBEDTLS_ERR_SSL_WANT_WRITE,
                Err(e) => {
                    dbg!(e);
                    MBEDTLS_ERR_SSL_INTERNAL_ERROR
                }
            }
        }

        unsafe extern "C" fn bio_recv<S: Read + Write>(
            ctx: *mut c_void,
            buf: *mut u8,
            len: usize,
        ) -> i32 {
            let this = &mut *(ctx as *mut TlsStream<S>);
            match this.stream.read(slice::from_raw_parts_mut(buf, len)) {
                Ok(n) => n as _,
                // Err(e) if e.kind() == io::ErrorKind::WouldBlock => MBEDTLS_ERR_SSL_WANT_READ,
                Err(e) => {
                    dbg!(e);
                    MBEDTLS_ERR_SSL_INTERNAL_ERROR
                }
            }
        }

        unsafe {
            let mut place = Box::pin(MaybeUninit::<Self>::uninit());
            Self::init_inplace(
                &mut place,
                tls_config,
                stream,
                Some(bio_send::<S>),
                Some(bio_recv::<S>),
            );
            place.assume_init_ref();
            std::mem::transmute(place)
        }
    }
}

impl<S: Read> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let ret = mbedtls_ssl_read(&mut self.ssl as *mut _, buf.as_mut_ptr(), buf.len());
            match ret {
                // MBEDTLS_ERR_SSL_WANT_READ => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                // question: <= 0 or < 0 ?
                _ if ret < 0 => Err(io::Error::new(
                    io::ErrorKind::Other,
                    mbedtls_err::err_name(ret),
                )),
                _ => Ok(ret as _),
            }
        }
    }
}

impl<S: Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let ret = mbedtls_ssl_write(&mut self.ssl as *mut _, buf.as_ptr(), buf.len());
            match ret {
                // MBEDTLS_ERR_SSL_WANT_WRITE => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                _ if ret < 0 => Err(io::Error::new(
                    io::ErrorKind::Other,
                    mbedtls_err::err_name(ret),
                )),
                _ => Ok(ret as _),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        let stream = Pin::new_unchecked(&mut self.stream);
        let context = &mut *(self.context as *mut _);
        (stream, context)
    }

    pub fn new_async(tls_config: Pin<Arc<TlsConfig>>, stream: S) -> Pin<Box<Self>> {
        unsafe extern "C" fn bio_send<S: AsyncRead + AsyncWrite + Unpin>(
            ctx: *mut c_void,
            buf: *const u8,
            len: usize,
        ) -> i32 {
            let this = &mut *(ctx as *mut TlsStream<S>);
            let (stream, context) = this.parts();
            match stream.poll_write(context, slice::from_raw_parts(buf, len)) {
                Poll::Pending => MBEDTLS_ERR_SSL_WANT_WRITE,
                Poll::Ready(Err(e)) => {
                    dbg!(e);
                    MBEDTLS_ERR_SSL_INTERNAL_ERROR
                }
                Poll::Ready(Ok(n)) => n as _,
            }
        }

        unsafe extern "C" fn bio_recv<S: AsyncRead + AsyncWrite + Unpin>(
            ctx: *mut c_void,
            buf: *mut u8,
            len: usize,
        ) -> i32 {
            let this = &mut *(ctx as *mut TlsStream<S>);
            let (stream, context) = this.parts();
            let mut read_buf = ReadBuf::uninit(slice::from_raw_parts_mut(buf as _, len));
            match stream.poll_read(context, &mut read_buf) {
                Poll::Pending => MBEDTLS_ERR_SSL_WANT_READ,
                Poll::Ready(Err(e)) => {
                    dbg!(e);
                    MBEDTLS_ERR_SSL_INTERNAL_ERROR
                }
                Poll::Ready(Ok(())) => read_buf.filled().len() as _,
            }
        }

        unsafe {
            let mut place = Box::pin(MaybeUninit::<Self>::uninit());
            Self::init_inplace(
                &mut place,
                tls_config,
                stream,
                Some(bio_send::<S>),
                Some(bio_recv::<S>),
            );
            place.assume_init_ref();
            std::mem::transmute(place)
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.context = cx as *mut _ as _;
        let ret = unsafe {
            let slice = buf.unfilled_mut();
            // let slice = {
            //     let buf = buf.unfilled_mut();
            //     slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len())
            // };
            let ret = mbedtls_ssl_read(
                &mut self.ssl as *mut _,
                slice.as_mut_ptr() as _,
                slice.len(),
            );
            match ret {
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_WANT_WRITE => Poll::Pending,
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                // question: <= 0 or < 0 ?
                _ if ret < 0 => {
                    dbg!(mbedtls_err::err_name(ret));
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, format!("{ret}"))))
                }
                _ => {
                    buf.assume_init(ret as _);
                    buf.advance(ret as _);
                    Poll::Ready(Ok(()))
                }
            }
            // todo!()
        };
        self.context = 0;
        ret
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.context = cx as *mut _ as _;
        let ret = unsafe {
            let ret = mbedtls_ssl_write(&mut self.ssl as *mut _, buf.as_ptr(), buf.len());
            match ret {
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_WANT_WRITE => Poll::Pending,
                // question: <= 0 or < 0 ?
                _ if ret < 0 => {
                    dbg!(mbedtls_err::err_name(ret));
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, format!("{ret}"))))
                }
                _ => Poll::Ready(Ok(ret as usize)),
            }
        };
        self.context = 0;
        ret
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unsafe { Pin::new_unchecked(&mut self.stream).poll_flush(cx) }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unsafe { Pin::new_unchecked(&mut self.stream).poll_shutdown(cx) }
    }
}

use hyper::client::connect::Connection;
use hyper::http::uri::Scheme;
use hyper::service::Service;
use hyper::Uri;

/// A stream which may be wrapped with TLS.
pub enum MaybeTlsStream<T> {
    /// Raw stream.
    Raw(T),
    /// TLS-wrapped stream.
    Tls(Pin<Box<TlsStream<T>>>),
}

impl<T: AsyncRead + Unpin> AsyncRead for MaybeTlsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_write(ctx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(ctx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_flush(ctx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_shutdown(ctx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(ctx),
        }
    }
}

impl<T: Connection> Connection for MaybeTlsStream<T> {
    fn connected(&self) -> hyper::client::connect::Connected {
        match self {
            MaybeTlsStream::Raw(s) => s.connected(),
            MaybeTlsStream::Tls(s) => s.get_ref_stream().connected(),
        }
    }
}

#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls_config: Pin<Arc<TlsConfig>>,
}

impl<T> HttpsConnector<T> {
    pub fn new(http: T, tls_config: Pin<Arc<TlsConfig>>) -> Self {
        Self { http, tls_config }
    }
}

impl<S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Send + 'static,
    S::Response: AsyncRead + AsyncWrite + Connection + Send + Unpin,
{
    type Response = MaybeTlsStream<S::Response>;
    type Error = Box<dyn Error + Sync + Send>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let is_tls = uri.scheme() == Some(&Scheme::HTTPS);
        let connect = self.http.call(uri);
        if is_tls {
            let tls_config = self.tls_config.clone();
            return Box::pin(async move {
                let conn = connect.await.map_err(Into::into)?;
                Ok(MaybeTlsStream::Tls(TlsStream::new_async(tls_config, conn)))
            });
        } else {
            return Box::pin(async move {
                let conn = connect.await.map_err(Into::into)?;
                Ok(MaybeTlsStream::Raw(conn))
            });
        }
    }
}
