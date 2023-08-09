use std::ffi::c_void;
use std::io;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ptr;
use std::slice;
use std::task::Context;
use std::task::Poll;

mod ffi;
use ffi::*;

pub struct TlsConfig {
    entropy: mbedtls_entropy_context,
    ctr_drbg: mbedtls_ctr_drbg_context,
    srvcert: mbedtls_x509_crt,
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
            mbedtls_x509_crt_free(&mut self.srvcert as _);
            mbedtls_ctr_drbg_free(&mut self.ctr_drbg as _);
            mbedtls_entropy_free(&mut self.entropy as _);
        }
    }
}

impl TlsConfig {
    pub unsafe fn init_inplace(place: &mut MaybeUninit<Self>, cert_der: &[u8], key_der: &[u8]) {
        let p = place.as_mut_ptr();
        macro_rules! field {
            ($field:ident) => {
                std::ptr::addr_of_mut!((*p).$field)
            };
        }
        let mut ret;

        let entropy_p = field!(entropy);
        let ctr_drbg_p = field!(ctr_drbg);
        let srvcert_p = field!(srvcert);
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

        // safety: cert and key will be cloned by mbedtls_xxx_parse function

        mbedtls_x509_crt_init(srvcert_p);
        ret = mbedtls_x509_crt_parse(srvcert_p, cert_der.as_ptr(), cert_der.len());
        assert_eq!(ret, 0);

        mbedtls_pk_init(pkey_p);
        ret = mbedtls_pk_parse_key(
            pkey_p,
            key_der.as_ptr(),
            key_der.len(),
            ptr::null(),
            0,
            Some(mbedtls_ctr_drbg_random),
            ctr_drbg_p as _,
        );
        assert_eq!(ret, 0);

        mbedtls_ssl_config_init(conf_p);
        ret = mbedtls_ssl_config_defaults(
            conf_p,
            MBEDTLS_SSL_IS_SERVER as _,
            MBEDTLS_SSL_TRANSPORT_STREAM as _,
            MBEDTLS_SSL_PRESET_DEFAULT as _,
        );
        assert_eq!(ret, 0);
        mbedtls_ssl_conf_rng(conf_p, Some(mbedtls_ctr_drbg_random), ctr_drbg_p as _);
        mbedtls_ssl_conf_ca_chain(conf_p, (*srvcert_p).next, ptr::null_mut());
        ret = mbedtls_ssl_conf_own_cert(conf_p, srvcert_p, pkey_p);
        assert_eq!(ret, 0);

        // static CIPHERSUITES: [i32; 2] = [MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as i32, 0]; // only one ciphersuite. must be static here, or AddressSanitizer: heap-use-after-free
        // mbedtls_ssl_conf_ciphersuites(conf_p, CIPHERSUITES.as_ptr());
    }

    pub fn new(cert_der: &[u8], key_der: &[u8]) -> Pin<Box<Self>> {
        unsafe {
            let mut place = Box::pin(MaybeUninit::uninit());
            Self::init_inplace(&mut place, cert_der, key_der);
            place.assume_init_ref(); // for the inner `intrinsics::assert_inhabited`;
            std::mem::transmute(place) // because MaybeUninit has `#[repr(transparent)]`
        }
    }
}

pub struct TlsStream<'a, S> {
    tls_config: &'a TlsConfig,
    stream: &'a mut S,
    ssl: mbedtls_ssl_context,
    context: usize,
    // error: io::Result<()>,
}

// is this dangerous?
unsafe impl<'a, S> Sync for TlsStream<'a, S> {}
unsafe impl<'a, S> Send for TlsStream<'a, S> {}

impl<'a, S> Drop for TlsStream<'a, S> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_ssl_free(&mut self.ssl as _);
        }
    }
}

impl<'a, S> TlsStream<'a, S> {
    pub unsafe fn init_inplace(
        place: &mut MaybeUninit<Self>,
        tls_config: &'a TlsConfig,
        stream: &'a mut S,
        bio_send: mbedtls_ssl_send_t,
        bio_recv: mbedtls_ssl_recv_t,
    ) {
        place.write(Self {
            tls_config,
            stream,
            #[allow(invalid_value)]
            ssl: MaybeUninit::uninit().assume_init(), // is safe, see MaybeUninit's docs
            context: 0,
        });
        let ssl_p = std::ptr::addr_of_mut!((*place.as_mut_ptr()).ssl);
        mbedtls_ssl_init(ssl_p);
        let ret = mbedtls_ssl_setup(ssl_p, &tls_config.conf as _);
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
}

impl<'a, S: Read + Write> TlsStream<'a, S> {
    pub fn new_sync(tls_config: &'a TlsConfig, stream: &'a mut S) -> Pin<Box<Self>> {
        unsafe extern "C" fn bio_send<S: Read + Write>(
            ctx: *mut c_void,
            buf: *const u8,
            len: usize,
        ) -> i32 {
            let this = &mut *(ctx as *mut TlsStream<'_, S>);
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
            let this = &mut *(ctx as *mut TlsStream<'_, S>);
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

impl<'a, S: Read> Read for TlsStream<'a, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let ret = mbedtls_ssl_read(&mut self.ssl as *mut _, buf.as_mut_ptr(), buf.len());
            match ret {
                // MBEDTLS_ERR_SSL_WANT_READ => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                // question: <= 0 or < 0 ?
                _ if ret < 0 => Err(io::Error::new(io::ErrorKind::Other, format!("{ret}"))),
                _ => Ok(ret as _),
            }
        }
    }
}

impl<'a, S: Write> Write for TlsStream<'a, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let ret = mbedtls_ssl_write(&mut self.ssl as *mut _, buf.as_ptr(), buf.len());
            match ret {
                // MBEDTLS_ERR_SSL_WANT_WRITE => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                _ if ret < 0 => Err(io::Error::new(io::ErrorKind::Other, format!("{ret}"))),
                _ => Ok(ret as _),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

impl<'a, S: AsyncRead + AsyncWrite> TlsStream<'a, S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        let stream = Pin::new_unchecked(&mut *self.stream);
        let context = &mut *(self.context as *mut _);
        (stream, context)
    }

    pub fn new_async(tls_config: &'a TlsConfig, stream: &'a mut S) -> Pin<Box<Self>> {
        unsafe extern "C" fn bio_send<S: AsyncRead + AsyncWrite>(
            ctx: *mut c_void,
            buf: *const u8,
            len: usize,
        ) -> i32 {
            let this = &mut *(ctx as *mut TlsStream<'_, S>);
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

        unsafe extern "C" fn bio_recv<S: AsyncRead + AsyncWrite>(
            ctx: *mut c_void,
            buf: *mut u8,
            len: usize,
        ) -> i32 {
            let this = &mut *(ctx as *mut TlsStream<'_, S>);
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

impl<'a, S: AsyncRead> AsyncRead for TlsStream<'a, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.context = cx as *mut _ as _;
        let ret = unsafe {
            let slice = buf.unfilled_mut();
            let ret = mbedtls_ssl_read(
                &mut self.ssl as *mut _,
                slice.as_mut_ptr() as _,
                slice.len(),
            );
            match ret {
                MBEDTLS_ERR_SSL_WANT_READ => Poll::Pending,
                // MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Err(io::Error::new(io::ErrorKind::Other,"MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")),
                // question: <= 0 or < 0 ?
                _ if ret < 0 => {
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

impl<'a, S: AsyncWrite> AsyncWrite for TlsStream<'a, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.context = cx as *mut _ as _;
        let ret = unsafe {
            let ret = mbedtls_ssl_write(&mut self.ssl as *mut _, buf.as_ptr(), buf.len());
            match ret {
                MBEDTLS_ERR_SSL_WANT_WRITE => Poll::Pending,
                // question: <= 0 or < 0 ?
                _ if ret < 0 => {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, format!("{ret}"))))
                }
                _ => Poll::Ready(Ok(ret as usize)),
            }
        };
        self.context = 0;
        ret
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unsafe { Pin::new_unchecked(&mut *self.stream).poll_flush(cx) }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unsafe { Pin::new_unchecked(&mut *self.stream).poll_shutdown(cx) }
    }
}
