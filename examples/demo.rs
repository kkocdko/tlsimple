use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;
use tower_service::Service;

pub const CERT_DER: &[u8] = b"\x30\x82\x04\x1b\x30\x82\x02\x83\xa0\x03\x02\x01\x02\x02\x10\x61\x1c\x33\xf0\xb4\x04\x7b\x07\x5a\xdf\x65\x7e\xce\xa1\x3a\xa3\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30\x59\x31\x1e\x30\x1c\x06\x03\x55\x04\x0a\x13\x15\x6d\x6b\x63\x65\x72\x74\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x20\x43\x41\x31\x17\x30\x15\x06\x03\x55\x04\x0b\x0c\x0e\x6b\x6b\x6f\x63\x64\x6b\x6f\x40\x66\x65\x64\x6f\x72\x61\x31\x1e\x30\x1c\x06\x03\x55\x04\x03\x0c\x15\x6d\x6b\x63\x65\x72\x74\x20\x6b\x6b\x6f\x63\x64\x6b\x6f\x40\x66\x65\x64\x6f\x72\x61\x30\x1e\x17\x0d\x32\x32\x30\x37\x32\x31\x32\x33\x33\x32\x35\x37\x5a\x17\x0d\x32\x34\x31\x30\x32\x31\x32\x33\x33\x32\x35\x37\x5a\x30\x42\x31\x27\x30\x25\x06\x03\x55\x04\x0a\x13\x1e\x6d\x6b\x63\x65\x72\x74\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x31\x17\x30\x15\x06\x03\x55\x04\x0b\x0c\x0e\x6b\x6b\x6f\x63\x64\x6b\x6f\x40\x66\x65\x64\x6f\x72\x61\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xa4\xea\x4b\x8d\x23\xa4\x32\x35\xb9\x0f\x7c\xcd\xa5\x49\x4c\x1e\x71\xd8\x5a\x38\x02\x65\x01\x33\xea\xbc\xbe\xf3\xa5\x93\x3d\xea\x9a\x03\x17\x6f\x1a\xc9\x1c\x96\x14\x1d\x89\xf3\xb5\x48\x67\x61\xf2\x33\xe6\x06\xbd\x99\x60\xa9\x7a\x4a\x1c\x60\x5f\xda\x68\xd6\x20\x63\xc7\xb2\xd3\xff\x30\xe2\x37\xb6\xc4\x7f\x9e\xb0\x84\x46\x8d\xc9\x94\xdd\x41\x17\x90\x9d\x0b\xaf\x7a\x1d\x65\x71\x30\x78\x9f\xd8\x32\x0b\xfb\x08\xbd\xce\xd3\x22\xcf\x50\x13\x13\x71\x5d\xd9\xf5\xa7\xa5\xf4\xbb\x47\x70\x9b\x84\x81\x89\xee\x62\x69\x99\xf2\x16\x54\x29\xae\xd8\x93\xfe\x99\x28\xfe\xa0\x8b\x1f\x7d\x9b\xc7\x92\xb8\x63\x64\xf1\xd8\xc8\x06\x9b\x9d\xe1\xef\xdb\x0c\xd6\xd3\x1a\xc6\x86\xdb\x82\xc0\x5a\xb9\x42\x19\x98\x97\x11\xe3\xa1\x59\xb7\xe2\xa8\x95\x39\x1d\x00\x5b\xe4\x6a\x3e\x88\x47\x7c\x9c\x90\x40\xb4\x9d\xbc\xae\x18\xd1\x0b\xfa\x68\x0a\xd1\xf4\x28\xe6\x5c\xb5\x81\x98\x17\x07\x36\x22\x52\x0e\xba\x51\x96\x87\x4c\xf6\xf8\x5c\x17\x72\x76\x3c\xde\xa3\xfe\x81\xf8\x23\x58\xe6\x99\x03\xd0\xb4\xac\x61\x1c\xf5\xd7\xc9\x92\x54\x2f\x75\xbb\x0f\x91\x89\x02\x03\x01\x00\x01\xa3\x76\x30\x74\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\x28\x40\x87\xe2\x4d\x97\x48\x35\x2b\x14\x18\x30\xd4\x68\xae\xe8\xab\xdb\x48\xf1\x30\x2c\x06\x03\x55\x1d\x11\x04\x25\x30\x23\x82\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x87\x04\x7f\x00\x00\x01\x87\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x81\x00\x0d\xd3\xfc\x01\xe6\xbc\x24\x1e\x33\x0f\xfb\xd7\x0f\x33\xad\xfb\x5b\xf8\x34\x92\x7c\xda\x9b\xf5\xfd\xba\x6c\xda\x3f\x10\x3a\x4f\x13\x7e\x18\x07\xe1\xf2\xf1\x15\x94\x69\x0e\x56\x81\xb4\xc3\x20\xc4\xf8\x45\x3c\x65\x25\x1d\x06\x34\x77\xbe\x07\xe9\xf0\x78\x9c\xe6\x90\x1d\x51\xab\xd4\x23\x89\x7a\xed\x05\xd0\xf7\x96\x6f\x3a\xcd\xab\xaa\xae\x74\x82\xdc\x39\x3b\x39\x15\x2a\x50\x09\x70\x77\xb6\xc1\x78\xbc\xc4\x0d\xc6\xee\x18\xdc\xbd\x7b\x02\xbb\xb8\x78\x55\x17\x2f\x13\x9e\xf9\x15\xfe\x40\x06\x9e\x0c\x1f\x8f\xda\x84\xcc\x43\x26\xa1\xd7\x16\x10\xc5\x79\x76\xf4\xb2\xed\xc7\x8f\x30\x9e\xbd\x42\x18\xfd\x46\xe3\xb2\x14\x78\x10\x81\x4d\xed\x26\x5f\x94\x5d\x96\xf2\x2a\xc2\x39\x29\xad\xda\x61\x40\x83\xd6\x77\x52\xc9\xfe\x5f\x44\x53\x18\x9f\x48\x43\x9f\x59\x7e\xe5\x51\x1b\xe5\x7c\x0c\xba\xdf\x87\xfe\x56\xf1\x1b\x96\x30\xdd\xf5\x4f\x59\x35\xf1\xa4\xa2\xe0\xda\x95\xd9\xd7\x95\x40\x0e\x4f\xd8\x8a\x9c\xf1\x7e\x27\xfb\xbd\x98\x46\x86\xf8\xf1\xd0\x3a\x64\x06\x1c\x04\xe5\x1e\xa4\x75\xee\xf1\x90\xe8\x70\x45\xa8\x75\xde\x82\xc6\x73\xea\x67\xe4\xc3\xd2\x34\x97\x0b\xd4\x9e\x1b\x65\x45\xf4\xe9\x74\x53\xbd\x0b\x10\xb7\x24\x04\x50\xeb\xb4\x77\xbb\xf9\x8d\xa5\x88\x20\xfc\x8c\xf5\xb3\xcc\x42\x98\xa6\x17\xc8\xd8\x40\x44\xd2\xd4\xc2\x2f\xed\x64\x3a\x2b\xd1\xfc\x74\x78\x75\x32\x84\xb1\x0d\x3c\xd9\x3a\x3f\xd3\xf3\xce\x85\xae\x72\x12\x4b\xda\x1a\x95\xfa\x84\xc2\xf1\x30\x41\xbd\x90\xe1\x7e\x51\xe6\xe8\xf8\xed\x04\xf7\x70\x75\x55\x34\x17\x68\x4f\xb5\x51\x62\x40\xef\x22\xe0\x72\x06\xc9\xe1\x41\x02\x56\x6b\x4f\x6c\x1b\xd2\x79\x4e\x88\x4c\x2b\x80\x42\xac";
pub const KEY_DER: &[u8] = b"\x30\x82\x04\xbf\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x82\x04\xa9\x30\x82\x04\xa5\x02\x01\x00\x02\x82\x01\x01\x00\xa4\xea\x4b\x8d\x23\xa4\x32\x35\xb9\x0f\x7c\xcd\xa5\x49\x4c\x1e\x71\xd8\x5a\x38\x02\x65\x01\x33\xea\xbc\xbe\xf3\xa5\x93\x3d\xea\x9a\x03\x17\x6f\x1a\xc9\x1c\x96\x14\x1d\x89\xf3\xb5\x48\x67\x61\xf2\x33\xe6\x06\xbd\x99\x60\xa9\x7a\x4a\x1c\x60\x5f\xda\x68\xd6\x20\x63\xc7\xb2\xd3\xff\x30\xe2\x37\xb6\xc4\x7f\x9e\xb0\x84\x46\x8d\xc9\x94\xdd\x41\x17\x90\x9d\x0b\xaf\x7a\x1d\x65\x71\x30\x78\x9f\xd8\x32\x0b\xfb\x08\xbd\xce\xd3\x22\xcf\x50\x13\x13\x71\x5d\xd9\xf5\xa7\xa5\xf4\xbb\x47\x70\x9b\x84\x81\x89\xee\x62\x69\x99\xf2\x16\x54\x29\xae\xd8\x93\xfe\x99\x28\xfe\xa0\x8b\x1f\x7d\x9b\xc7\x92\xb8\x63\x64\xf1\xd8\xc8\x06\x9b\x9d\xe1\xef\xdb\x0c\xd6\xd3\x1a\xc6\x86\xdb\x82\xc0\x5a\xb9\x42\x19\x98\x97\x11\xe3\xa1\x59\xb7\xe2\xa8\x95\x39\x1d\x00\x5b\xe4\x6a\x3e\x88\x47\x7c\x9c\x90\x40\xb4\x9d\xbc\xae\x18\xd1\x0b\xfa\x68\x0a\xd1\xf4\x28\xe6\x5c\xb5\x81\x98\x17\x07\x36\x22\x52\x0e\xba\x51\x96\x87\x4c\xf6\xf8\x5c\x17\x72\x76\x3c\xde\xa3\xfe\x81\xf8\x23\x58\xe6\x99\x03\xd0\xb4\xac\x61\x1c\xf5\xd7\xc9\x92\x54\x2f\x75\xbb\x0f\x91\x89\x02\x03\x01\x00\x01\x02\x82\x01\x01\x00\xa1\x79\xaf\xe4\x50\xa3\xb3\x6e\x1a\xf7\xe9\x31\xca\xc7\x8c\x3a\xbb\x2a\x26\x9c\x74\xeb\xc5\x53\xba\x62\x79\x6e\x44\x0f\x7a\x2e\xbe\x02\x8c\xed\x83\x02\xac\x74\xde\xd9\x55\x7c\x45\x62\xd1\xa7\x7b\xea\x09\x2f\x4c\x72\x63\xcd\x4e\x2a\x46\xc2\xae\xd8\x42\x92\x77\x40\x7c\x06\xc3\xc1\x39\x72\x27\x2f\x54\x13\xc9\xa3\xf8\xc0\xc4\x90\x3e\xac\xad\xd1\x8f\x0d\xd6\xa5\x49\x22\x83\x73\x63\x0c\x99\x26\xad\x4a\x41\xd0\xfb\x59\x0a\x2f\x29\x62\xb4\x6a\xf3\x33\xfb\xf8\xa6\xe0\xbe\x52\xa9\xce\xbe\xd7\xed\xa6\xca\xbd\x9d\xbb\x45\xdc\xea\x54\x3c\xfc\xac\x68\x78\x0d\x44\xdc\x5c\x49\x8a\xee\x84\xc4\xec\x1c\xef\xba\xdc\x11\x11\xf3\x2f\x1f\x46\xd4\x71\x6f\xa5\x23\x2c\xc0\x25\x25\xee\x1a\x94\x9d\xb4\x6b\xe2\xed\xec\x39\x13\xd1\xa2\x49\xa1\x67\xa1\xf8\xab\xc8\x3d\xdd\x16\x3f\x2a\x26\xb2\x7a\xf4\xf9\x9d\x29\x3f\xfc\xa6\x08\x7c\xce\x74\x52\x04\xf0\x0d\x60\x37\xd1\x00\xb8\x18\x22\xab\xfe\xd5\x1c\xc3\x66\x53\x83\x5a\x82\x40\x4d\x61\x92\x05\x8f\x55\x3d\xb2\x7d\x4d\x10\xd0\x62\xc1\xa3\x5f\x06\x5d\x4b\xf5\x0f\xa6\xa1\x99\x44\xb9\x27\x0c\x49\x02\x81\x81\x00\xd9\xb1\xab\x30\x7b\xf2\xf6\x79\xe5\x70\xf5\x40\xea\xae\xaf\x1b\xe3\x61\x84\x80\x80\x3a\xf1\x6a\xcb\x67\x85\x65\xc8\x4a\x04\x4e\x8d\x97\x66\x4f\x51\x0a\x7a\x49\x3e\x33\x39\x6c\x09\x8c\x47\xa6\x2a\xf9\xe7\xbf\x2a\x7d\xa0\x33\x2a\xb6\x0b\xf3\x40\x1d\xa4\xce\xbe\xa7\x1e\x7d\x1a\xf2\x90\xc4\xa3\xe0\xe9\x05\xdc\xe6\x80\x1e\xde\x46\x68\x70\xd9\x27\xfb\x22\x4a\x2a\xfa\xcd\x86\xc7\x7d\xed\x75\xa0\x95\x46\x32\xa4\xd7\x5c\xfd\x8e\x3d\x0a\x35\xda\x1d\x0d\x09\xc2\x9a\xd2\xa2\x1f\x0e\x87\x27\x0e\x39\xb8\x45\x8e\xf7\xc7\x02\x81\x81\x00\xc1\xef\x21\xa8\x00\x50\xce\x14\xaf\x8c\x09\xaf\xaa\x5f\xe9\x1f\xe6\x48\xed\x99\xff\xea\x3f\x89\xca\xf6\xf1\x19\x89\x65\x53\x09\xbd\xc8\x4e\x21\xb8\x21\xd9\xaa\x8b\x12\x07\xf9\x54\xdb\x70\xd1\xe0\x4a\xa9\x79\x9c\x73\x85\x6a\xdc\xbe\xe9\xef\x0f\xf9\xc6\xed\xea\x3b\x5d\xec\x27\x94\xe0\xa5\x41\xad\x57\x10\xd3\x40\xd4\x91\x11\xb6\xb4\x0a\x7d\xed\xf0\xa2\x74\x71\x7a\xad\x24\x71\x22\x52\x3a\xbb\xb8\x7e\x7c\x74\x06\x06\xfa\x84\x5d\x1e\xad\x0c\xbb\xd8\x11\x0d\x5e\x91\xad\x95\x3b\x1a\x45\x5a\x5e\xbf\x73\xb7\x4c\x2f\x02\x81\x80\x5b\xe5\x0d\x1f\xc5\x62\xf5\xba\xd5\x29\x0e\xce\x9d\x82\xa9\xf6\xba\xd0\x82\x8f\x80\x11\xe1\xb1\x34\x35\xf9\xf0\xd2\x50\xb4\x6a\xb8\x88\x8d\xae\xb3\xc6\x19\x82\xeb\x97\xd2\x08\x92\x2b\x3e\x5f\x9d\xca\xaa\x92\x5f\x0c\x72\xe0\xc6\x89\xdc\x97\x8d\x9c\x35\xe2\xf4\x46\x35\xaf\x97\xfd\x87\x31\x0b\x00\xb9\x3d\x39\x57\xb0\x03\xd7\xce\x9e\xed\xec\x2d\x5d\x6c\xc7\x24\x47\x85\x14\xfd\x07\x62\x83\x02\x0b\xa1\x7b\x65\x6c\x68\x1b\xbc\xbc\x75\x9f\xef\xf7\xcd\x76\x2e\x49\x0e\xdb\x53\x02\xdd\xf8\x95\x9f\xb5\xf2\xde\xfc\x27\x02\x81\x81\x00\xbd\xca\x92\x0c\x81\x2a\x93\x53\xe9\x2c\xca\x39\xf1\x29\xe5\xd3\x03\x22\x71\xed\x19\x67\x9d\x00\xf3\xf1\xd1\xa8\x25\x2f\x55\x21\x9e\x6a\x8e\x14\x2f\xc8\x68\xe5\x9f\x2e\x69\x41\x58\x0b\x5d\x90\xf7\xc8\xf9\xac\x7b\x31\x0e\xeb\xb2\xd6\xdf\xc7\xc6\xc1\xb2\x2e\x19\xe2\x39\x9b\xa8\x6c\xe9\xa0\xb0\xf2\xbb\xd7\x4a\x77\x12\xd0\x5a\x1e\x8c\x7a\x0c\x1d\xb5\x36\xb7\x70\x6b\x17\x51\x27\xaa\xe8\x00\x74\xc0\x2c\x81\x0d\x66\xec\xa3\x74\xb0\x51\x1a\x17\xf1\x29\x96\x1e\x98\x63\x47\x16\x59\x7d\xef\x4b\x6e\x98\x3c\xdd\xb0\x9f\x02\x81\x81\x00\xd5\xf2\x6a\x02\x98\xc3\x98\x62\xb3\x0d\xd6\xc2\x28\x9e\xa3\x2b\xff\x1f\x62\x55\x77\x0c\x10\x4b\x08\x7a\xd6\xe7\x75\xe1\xa3\x0d\x67\xb5\x8b\x36\x97\x1a\x46\x12\xae\xa6\xdb\xdd\xfb\xf6\xde\x20\x4f\xea\x85\x9c\xf8\x2b\x9f\xbe\x2c\xbd\xee\x6d\x81\xcd\xf9\x2d\xce\x68\x55\x3f\x71\x56\x02\x0a\x94\xa1\xaf\xf2\x51\x33\xf4\x3d\x4f\x09\x27\x9e\xac\x7b\x28\xad\x7f\x9d\x25\xba\xd0\xbf\xba\x83\x4a\xcc\x9f\x80\xda\x7e\x6a\xd6\x38\x3f\xac\xb8\xd9\xbd\x48\x9a\x2e\x17\x2c\xfd\x92\x5e\xc8\xcf\x77\x20\x62\xe5\x5f\xe9\x2c\xae";

const SERVER_ADDR: &str = "127.0.0.1:11111";

use hyper::server::conn::Http;
use tlsimple::{TlsConfig, TlsStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/*

async fn run_server_async() {
    let tls_config = TlsConfig::new_server(CERT_DER, KEY_DER, None);
    let listener = tokio::net::TcpListener::bind(SERVER_ADDR).await.unwrap();
    loop {
        let (mut stream, socket_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                dbg!(e);
                continue;
            }
        };
        dbg!(socket_addr);
        let tls_config = tls_config.clone();
        tokio::spawn(async move {
            // let mut stream_wrapper = StreamWrapper { stream, context: 0 };
            let mut tls_stream = TlsStream::new_async(tls_config, &mut stream);

            let mut buf = [0; 256];

            let len = tls_stream.read(&mut buf).await.unwrap();
            println!("----- read\n{}-----", String::from_utf8_lossy(&buf[..len]));

            let mut write_buf = String::new();
            write_buf += "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello world! ciphersuite = ";
            write_buf += tls_stream.get_ciphersuite();
            write_buf += "\n";
            tls_stream.write(write_buf.as_bytes()).await.unwrap();

            // tls_stream.close_notify();
            // drop(tls_stream);
            // stream.shutdown().await.unwrap();
        });
    }
}

mod async_client {
    use hyper::body::HttpBody;
    use hyper::client::HttpConnector;
    use hyper::Response;
    use hyper::{Body, Client, Request};
    use once_cell::sync::Lazy;
    use tlsimple::HttpsConnector;

    static CLIENT: Lazy<Client<HttpsConnector<HttpConnector>>> = Lazy::new(|| {
        let mut http_conn = HttpConnector::new();
        http_conn.enforce_http(false); // allow HTTPS
        use tlsimple::TlsConfig;
        let tls_config = TlsConfig::new_client(None);
        let connector = HttpsConnector::new(http_conn, tls_config);
        Client::builder().build(connector)
    });

    /// Same as JavaScript's `encodeURI`.
    pub fn encode_uri(i: &str) -> String {
        const fn gen_table() -> [bool; TABLE_LEN] {
            let mut table = [false; TABLE_LEN];
            let valid_chars =
            b"!#$&'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_abcdefghijklmnopqrstuvwxyz~";
            let mut i = 0;
            while i < valid_chars.len() {
                table[valid_chars[i] as usize] = true;
                i += 1;
            }
            table
        }

        const TABLE_LEN: usize = u8::MAX as usize + 1; // == 256
        const IS_VALID: [bool; TABLE_LEN] = gen_table();

        fn to_hex(d: u8) -> u8 {
            match d {
                0..=9 => d + b'0',
                10..=255 => d - 10 + b'a', // regardless of upper or lower case
            }
        }

        let mut o = Vec::with_capacity(i.len());
        for b in i.as_bytes() {
            if IS_VALID[*b as usize] {
                o.push(*b);
            } else {
                o.push(b'%');
                o.push(to_hex(b >> 4));
                o.push(to_hex(b & 15));
            }
        }
        unsafe { String::from_utf8_unchecked(o) }
    }

    pub trait ToRequest {
        fn into_request(self) -> Request<Body>;
    }
    impl ToRequest for Request<Body> {
        fn into_request(self) -> Request<Body> {
            self
        }
    }
    impl ToRequest for &str {
        fn into_request(self) -> Request<Body> {
            let ret = Request::get(encode_uri(self)).body(Body::empty()).unwrap();
            ret.into_request()
        }
    }
    impl ToRequest for &String {
        fn into_request(self) -> Request<Body> {
            self.as_str().into_request()
        }
    }

    /// Read `hyper::Body` into `Vec<u8>`, returns emply if reached the limit size (2 MiB).
    ///
    /// Simpler than `hyper::body::to_bytes`.
    pub async fn read_body(mut body: Body) -> Vec<u8> {
        // TODO: reimplement?
        let mut v = Vec::new();
        while let Some(Ok(bytes)) = body.data().await {
            v.append(&mut bytes.into());
            // 2 MiB
            if v.len() > 2048 * 1024 {
                v.clear();
                break;
            }
        }
        v
    }

    /// Send a `Request` and return the response. Allow both HTTPS and HTTP.
    ///
    /// This function is used to replace `reqwest` crate to reduce binary size.
    /// But unlike `reqwest`, this function dose not follow redirect.
    pub async fn fetch(request: impl ToRequest) -> Result<Response<Body>, hyper::Error> {
        CLIENT.request(request.into_request()).await
    }

    /// Fetch a URI, returns as `Vec<u8>`.
    pub async fn fetch_data(request: impl ToRequest) -> Result<Vec<u8>, hyper::Error> {
        // let request = request.into_request();
        // let a = format!("{}", request.uri());
        // log!("begin:  {a}");
        let response = fetch(request).await?;
        let body = read_body(response.into_body()).await;
        // log!("finish: {a}");
        Ok(body)
    }
}

async fn run_client_async() {
    use async_client::fetch_data;
    let a = fetch_data("https://127.0.0.1:9304").await.unwrap();
    let d = String::from_utf8_lossy(&a).into_owned();
    println!("d = {d}");
}

fn run_server() {
    use tlsimple::{alpn, TlsConfig, TlsStream};

    let tls_config = TlsConfig::new_server(CERT_DER, KEY_DER, Some(alpn::H1));
    let listener = TcpListener::bind(SERVER_ADDR).unwrap();
    loop {
        let (mut stream, socket_addr) = match listener.accept() {
            Ok(v) => v,
            Err(e) => {
                dbg!(e);
                continue;
            }
        };
        dbg!(socket_addr);
        let tls_config = tls_config.clone();
        thread::spawn(move || {
            let mut tls_stream = TlsStream::new_sync(tls_config, &mut stream);

            let mut buf = [0; 256];

            // loop{

            let len = tls_stream.read(&mut buf).unwrap();
            println!("----- read\n{}-----", String::from_utf8_lossy(&buf[..len]));

            let mut write_buf = String::new();
            write_buf += "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello world! ciphersuite = ";
            write_buf += tls_stream.get_ciphersuite();
            write_buf += "\n";
            tls_stream.write(write_buf.as_bytes()).unwrap();
            // }

            tls_stream.close_notify();
            drop(tls_stream);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });
    }
}

fn run_client() {
    use tlsimple::{TlsConfig, TlsStream};

    let tls_config = TlsConfig::new_client(None);
    let mut stream = std::net::TcpStream::connect("127.0.0.1:9304").unwrap();
    let mut tls_stream = TlsStream::new_sync(tls_config, &mut stream);

    let write_buf = b"GET / HTTP/1.1\r\n\r\n";
    tls_stream.write(write_buf).unwrap();

    let mut buf = [0; 4096];
    let len = tls_stream.read(&mut buf).unwrap();
    println!("----- read\n{}-----", String::from_utf8_lossy(&buf[..len]));

    // let mut write_buf = String::new();
    // write_buf += "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello world! ciphersuite = ";
    // write_buf += tls_stream.get_ciphersuite();
    // write_buf += "\n";
    // tls_stream.write(write_buf.as_bytes()).unwrap();
    // // }

    // tls_stream.close_notify();
    // drop(tls_stream);
    // stream.shutdown(std::net::Shutdown::Both).unwrap();
}

*/

// https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_timeout
const TIMEOUT: Duration = Duration::from_secs(75);
const TO_HTTPS_PAGE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type:text/html\r\n\r\n<script>location=location.href.replace(':','s:')</script>\r\n\r\n\0";
const DEMO_PAGE: &str = "<!DOCTYPE html>\n\n<head>\n  <meta charset=\"utf8\" />\n  <meta name=\"viewport\" content=\"width=device-width\" />\n</head>\n\n<style>\n  body {\n    display: grid;\n    margin: 15px;\n    gap: 15px;\n  }\n  body > * {\n    min-height: 20px;\n    border: 1px solid #777;\n    padding: 10px;\n  }\n  input[type=\"checkbox\"] {\n    height: 16px;\n    width: 16px;\n    box-shadow: inset 0 0 0 1px #aaa, inset 0 0 0 9px #fff, inset 0 0 0 9px #888;\n  }\n  input[type=\"checkbox\"]:checked {\n    box-shadow: inset 0 0 0 1px #aaa, inset 0 0 0 3px #fff, inset 0 0 0 9px #888;\n  }\n  * {\n    color: #000;\n    background: #fff;\n    transition: 0.2s;\n  }\n</style>\n\n<body>\n  <input id=\"$order\" placeholder=\"Order\" type=\"number\" />\n  <form id=\"$i\"></form>\n  <form id=\"$o\"></form>\n</body>\n\n<script>\n  $order.onchange = $order.oninput = () => {\n    const n = Number($order.value);\n    if (n > 32) throw alert(\"Matrix order should not greater than 32\");\n    let innerHTML = \"\";\n    for (let i = 0; i < n; i++) {\n      for (let j = 0; j < n; j++) innerHTML += \"<input type='checkbox' />\";\n      innerHTML += \"<br />\";\n    }\n    $i.innerHTML = $o.innerHTML = innerHTML;\n  };\n  $i.onchange = () => {\n    const n = Number($order.value);\n    let m = [...$i.querySelectorAll(\"input\")].map((v) => v.checked);\n    for (let k = 0; k < n; k++)\n      for (let i = 0; i < n; i++)\n        for (let j = 0; j < n; j++) m[i * n + j] |= m[i * n + k] & m[k * n + j];\n    const hasse = false;\n    if (hasse)\n      for (let k = 0; k < n; k++)\n        for (let i = 0; i < n; i++)\n          for (let j = 0; j < n; j++)\n            if (i === j || m[i * n + k] & m[k * n + j]) m[i * n + j] = false; // spin or transfer\n    $o.querySelectorAll(\"input\").forEach((el, i) => (el.checked = m[i]));\n  };\n</script>\n";
const DEMO_PAGE_SMALL: &str = "<!DOCTYPE html><head></head><body>Hi</body>";

async fn serve_tlsimple(addr: &SocketAddr, svc: axum::Router) {
    // pub async fn serve_tlsimple(addr: &SocketAddr, svc: axum::Router) {
    let tls_config =
        TlsConfig::new_server(CERT_DER.into(), KEY_DER.into(), Some(tlsimple::alpn::H1));
    static PROTOCOL: OnceLock<Http> = OnceLock::new();
    let protocol_get = || {
        PROTOCOL.get_or_init(|| {
            let mut protocol = Http::new();
            protocol.http1_keep_alive(false);
            protocol
        })
    };
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    loop {
        let (mut stream, _socket_addr) = match listener.accept().await {
            Ok(v) => v,
            _ => continue, // ignore error here?
        };
        // dbg!(socket_addr);
        let svc = svc.clone();
        let tls_config = tls_config.clone();
        // tokio::spawn(tokio::time::timeout(TIMEOUT, async move {
        tokio::spawn(async move {
            // redirect HTTP to HTTPS
            let mut flag = [0]; // expect 0x16, TLS handshake
            let mut buf = tokio::io::ReadBuf::new(&mut flag);
            poll_fn(|cx| stream.poll_peek(cx, &mut buf)).await.ok();
            if flag[0] != 0x16 {
                stream.write_all(TO_HTTPS_PAGE).await.ok();
                stream.shutdown().await.ok(); // remember to close stream
                return;
            }
            let tls_stream = TlsStream::new_async(tls_config, &mut stream);
            protocol_get()
                .serve_connection(tls_stream, svc)
                // .with_upgrades() // allow WebSocket
                .await
                .ok();
        });
    }
}

async fn serve_rustls(addr: &SocketAddr, svc: axum::Router) {
    use tokio_rustls::rustls::cipher_suite::*;
    use tokio_rustls::rustls::version::TLS12;
    use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
    use tokio_rustls::TlsAcceptor;
    let mut tls_cfg = ServerConfig::builder()
        .with_cipher_suites(&[TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(CERT_DER.into())],
            PrivateKey(KEY_DER.into()),
        )
        .unwrap();
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    static PROTOCOL: OnceLock<Http> = OnceLock::new();
    let protocol_get = || {
        PROTOCOL.get_or_init(|| {
            let mut protocol = Http::new();
            protocol.http1_keep_alive(false);
            protocol
        })
    };
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_cfg)));
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            _ => continue, // ignore error here?
        };
        let svc = svc.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            // redirect HTTP to HTTPS
            let mut flag = [0]; // expect 0x16, TLS handshake
            let mut buf = tokio::io::ReadBuf::new(&mut flag);
            poll_fn(|cx| stream.poll_peek(cx, &mut buf)).await.ok();
            if flag[0] != 0x16 {
                stream.write_all(TO_HTTPS_PAGE).await.ok();
                stream.shutdown().await.ok(); // remember to close stream
                return;
            }
            if let Ok(tls_stream) = tls_acceptor.accept(stream).await {
                protocol_get()
                    .serve_connection(tls_stream, svc)
                    // .with_upgrades() // allow WebSocket
                    .await
                    .ok();
            }
        });
    }
}

async fn serve_raw(addr: &SocketAddr, svc: axum::Router) {
    static PROTOCOL: OnceLock<Http> = OnceLock::new();
    let protocol_get = || {
        PROTOCOL.get_or_init(|| {
            let mut protocol = Http::new();
            protocol.http1_keep_alive(false);
            protocol
        })
    };
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            _ => continue, // ignore error here?
        };
        let svc = svc.clone();
        tokio::spawn(async move {
            protocol_get()
                .serve_connection(stream, svc)
                // .with_upgrades() // allow WebSocket
                .await
                .ok();
        });
    }
}

async fn run_server_axum() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 9304));
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(|| async { ([("Connection", "close")], DEMO_PAGE_SMALL) }),
        )
        .with_state(());
    // serve_raw(&addr, app).await;
    serve_tlsimple(&addr, app).await;
    // serve_rustls(&addr, app).await;
}

fn main() {
    // return run_client();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_server_axum());
}

// https://github.com/Mbed-TLS/mbedtls/issues/7722
// https://github.com/sfackler/rust-openssl/blob/9784356/openssl/src/ssl/mod.rs#L3708
