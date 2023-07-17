pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

mod ssl_h;

unsafe fn acc() {
    // ssl_h::SSL_accept(ssl);
    // ssl_h::ERR
    // ssl_h_openssl::A
    // ssl_ffi::ASN
    // ssl_ffi::ASN1_BIT_STRING;
}
