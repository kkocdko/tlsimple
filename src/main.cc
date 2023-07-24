// https://github.com/openssl/openssl/blob/master/demos/sslecho/main.c
// https://github.com/openssl/openssl/blob/master/INSTALL.md
// https://github.com/sfackler/rust-openssl/tree/master/openssl-sys/build

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

// #define OPENSSL_ALL
// #include <wolfssl/openssl/ssl.h>

static const int server_port = 11111;
// clang-format off
const unsigned char CERT_ASN1[] = "\x30\x82\x04\x1b\x30\x82\x02\x83\xa0\x03\x02\x01\x02\x02\x10\x61\x1c\x33\xf0\xb4\x04\x7b\x07\x5a\xdf\x65\x7e\xce\xa1\x3a\xa3\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30\x59\x31\x1e\x30\x1c\x06\x03\x55\x04\x0a\x13\x15\x6d\x6b\x63\x65\x72\x74\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x20\x43\x41\x31\x17\x30\x15\x06\x03\x55\x04\x0b\x0c\x0e\x6b\x6b\x6f\x63\x64\x6b\x6f\x40\x66\x65\x64\x6f\x72\x61\x31\x1e\x30\x1c\x06\x03\x55\x04\x03\x0c\x15\x6d\x6b\x63\x65\x72\x74\x20\x6b\x6b\x6f\x63\x64\x6b\x6f\x40\x66\x65\x64\x6f\x72\x61\x30\x1e\x17\x0d\x32\x32\x30\x37\x32\x31\x32\x33\x33\x32\x35\x37\x5a\x17\x0d\x32\x34\x31\x30\x32\x31\x32\x33\x33\x32\x35\x37\x5a\x30\x42\x31\x27\x30\x25\x06\x03\x55\x04\x0a\x13\x1e\x6d\x6b\x63\x65\x72\x74\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x31\x17\x30\x15\x06\x03\x55\x04\x0b\x0c\x0e\x6b\x6b\x6f\x63\x64\x6b\x6f\x40\x66\x65\x64\x6f\x72\x61\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xa4\xea\x4b\x8d\x23\xa4\x32\x35\xb9\x0f\x7c\xcd\xa5\x49\x4c\x1e\x71\xd8\x5a\x38\x02\x65\x01\x33\xea\xbc\xbe\xf3\xa5\x93\x3d\xea\x9a\x03\x17\x6f\x1a\xc9\x1c\x96\x14\x1d\x89\xf3\xb5\x48\x67\x61\xf2\x33\xe6\x06\xbd\x99\x60\xa9\x7a\x4a\x1c\x60\x5f\xda\x68\xd6\x20\x63\xc7\xb2\xd3\xff\x30\xe2\x37\xb6\xc4\x7f\x9e\xb0\x84\x46\x8d\xc9\x94\xdd\x41\x17\x90\x9d\x0b\xaf\x7a\x1d\x65\x71\x30\x78\x9f\xd8\x32\x0b\xfb\x08\xbd\xce\xd3\x22\xcf\x50\x13\x13\x71\x5d\xd9\xf5\xa7\xa5\xf4\xbb\x47\x70\x9b\x84\x81\x89\xee\x62\x69\x99\xf2\x16\x54\x29\xae\xd8\x93\xfe\x99\x28\xfe\xa0\x8b\x1f\x7d\x9b\xc7\x92\xb8\x63\x64\xf1\xd8\xc8\x06\x9b\x9d\xe1\xef\xdb\x0c\xd6\xd3\x1a\xc6\x86\xdb\x82\xc0\x5a\xb9\x42\x19\x98\x97\x11\xe3\xa1\x59\xb7\xe2\xa8\x95\x39\x1d\x00\x5b\xe4\x6a\x3e\x88\x47\x7c\x9c\x90\x40\xb4\x9d\xbc\xae\x18\xd1\x0b\xfa\x68\x0a\xd1\xf4\x28\xe6\x5c\xb5\x81\x98\x17\x07\x36\x22\x52\x0e\xba\x51\x96\x87\x4c\xf6\xf8\x5c\x17\x72\x76\x3c\xde\xa3\xfe\x81\xf8\x23\x58\xe6\x99\x03\xd0\xb4\xac\x61\x1c\xf5\xd7\xc9\x92\x54\x2f\x75\xbb\x0f\x91\x89\x02\x03\x01\x00\x01\xa3\x76\x30\x74\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\x28\x40\x87\xe2\x4d\x97\x48\x35\x2b\x14\x18\x30\xd4\x68\xae\xe8\xab\xdb\x48\xf1\x30\x2c\x06\x03\x55\x1d\x11\x04\x25\x30\x23\x82\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x87\x04\x7f\x00\x00\x01\x87\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x81\x00\x0d\xd3\xfc\x01\xe6\xbc\x24\x1e\x33\x0f\xfb\xd7\x0f\x33\xad\xfb\x5b\xf8\x34\x92\x7c\xda\x9b\xf5\xfd\xba\x6c\xda\x3f\x10\x3a\x4f\x13\x7e\x18\x07\xe1\xf2\xf1\x15\x94\x69\x0e\x56\x81\xb4\xc3\x20\xc4\xf8\x45\x3c\x65\x25\x1d\x06\x34\x77\xbe\x07\xe9\xf0\x78\x9c\xe6\x90\x1d\x51\xab\xd4\x23\x89\x7a\xed\x05\xd0\xf7\x96\x6f\x3a\xcd\xab\xaa\xae\x74\x82\xdc\x39\x3b\x39\x15\x2a\x50\x09\x70\x77\xb6\xc1\x78\xbc\xc4\x0d\xc6\xee\x18\xdc\xbd\x7b\x02\xbb\xb8\x78\x55\x17\x2f\x13\x9e\xf9\x15\xfe\x40\x06\x9e\x0c\x1f\x8f\xda\x84\xcc\x43\x26\xa1\xd7\x16\x10\xc5\x79\x76\xf4\xb2\xed\xc7\x8f\x30\x9e\xbd\x42\x18\xfd\x46\xe3\xb2\x14\x78\x10\x81\x4d\xed\x26\x5f\x94\x5d\x96\xf2\x2a\xc2\x39\x29\xad\xda\x61\x40\x83\xd6\x77\x52\xc9\xfe\x5f\x44\x53\x18\x9f\x48\x43\x9f\x59\x7e\xe5\x51\x1b\xe5\x7c\x0c\xba\xdf\x87\xfe\x56\xf1\x1b\x96\x30\xdd\xf5\x4f\x59\x35\xf1\xa4\xa2\xe0\xda\x95\xd9\xd7\x95\x40\x0e\x4f\xd8\x8a\x9c\xf1\x7e\x27\xfb\xbd\x98\x46\x86\xf8\xf1\xd0\x3a\x64\x06\x1c\x04\xe5\x1e\xa4\x75\xee\xf1\x90\xe8\x70\x45\xa8\x75\xde\x82\xc6\x73\xea\x67\xe4\xc3\xd2\x34\x97\x0b\xd4\x9e\x1b\x65\x45\xf4\xe9\x74\x53\xbd\x0b\x10\xb7\x24\x04\x50\xeb\xb4\x77\xbb\xf9\x8d\xa5\x88\x20\xfc\x8c\xf5\xb3\xcc\x42\x98\xa6\x17\xc8\xd8\x40\x44\xd2\xd4\xc2\x2f\xed\x64\x3a\x2b\xd1\xfc\x74\x78\x75\x32\x84\xb1\x0d\x3c\xd9\x3a\x3f\xd3\xf3\xce\x85\xae\x72\x12\x4b\xda\x1a\x95\xfa\x84\xc2\xf1\x30\x41\xbd\x90\xe1\x7e\x51\xe6\xe8\xf8\xed\x04\xf7\x70\x75\x55\x34\x17\x68\x4f\xb5\x51\x62\x40\xef\x22\xe0\x72\x06\xc9\xe1\x41\x02\x56\x6b\x4f\x6c\x1b\xd2\x79\x4e\x88\x4c\x2b\x80\x42\xac";
const unsigned char KEY_ASN1[] = "\x30\x82\x04\xbf\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x82\x04\xa9\x30\x82\x04\xa5\x02\x01\x00\x02\x82\x01\x01\x00\xa4\xea\x4b\x8d\x23\xa4\x32\x35\xb9\x0f\x7c\xcd\xa5\x49\x4c\x1e\x71\xd8\x5a\x38\x02\x65\x01\x33\xea\xbc\xbe\xf3\xa5\x93\x3d\xea\x9a\x03\x17\x6f\x1a\xc9\x1c\x96\x14\x1d\x89\xf3\xb5\x48\x67\x61\xf2\x33\xe6\x06\xbd\x99\x60\xa9\x7a\x4a\x1c\x60\x5f\xda\x68\xd6\x20\x63\xc7\xb2\xd3\xff\x30\xe2\x37\xb6\xc4\x7f\x9e\xb0\x84\x46\x8d\xc9\x94\xdd\x41\x17\x90\x9d\x0b\xaf\x7a\x1d\x65\x71\x30\x78\x9f\xd8\x32\x0b\xfb\x08\xbd\xce\xd3\x22\xcf\x50\x13\x13\x71\x5d\xd9\xf5\xa7\xa5\xf4\xbb\x47\x70\x9b\x84\x81\x89\xee\x62\x69\x99\xf2\x16\x54\x29\xae\xd8\x93\xfe\x99\x28\xfe\xa0\x8b\x1f\x7d\x9b\xc7\x92\xb8\x63\x64\xf1\xd8\xc8\x06\x9b\x9d\xe1\xef\xdb\x0c\xd6\xd3\x1a\xc6\x86\xdb\x82\xc0\x5a\xb9\x42\x19\x98\x97\x11\xe3\xa1\x59\xb7\xe2\xa8\x95\x39\x1d\x00\x5b\xe4\x6a\x3e\x88\x47\x7c\x9c\x90\x40\xb4\x9d\xbc\xae\x18\xd1\x0b\xfa\x68\x0a\xd1\xf4\x28\xe6\x5c\xb5\x81\x98\x17\x07\x36\x22\x52\x0e\xba\x51\x96\x87\x4c\xf6\xf8\x5c\x17\x72\x76\x3c\xde\xa3\xfe\x81\xf8\x23\x58\xe6\x99\x03\xd0\xb4\xac\x61\x1c\xf5\xd7\xc9\x92\x54\x2f\x75\xbb\x0f\x91\x89\x02\x03\x01\x00\x01\x02\x82\x01\x01\x00\xa1\x79\xaf\xe4\x50\xa3\xb3\x6e\x1a\xf7\xe9\x31\xca\xc7\x8c\x3a\xbb\x2a\x26\x9c\x74\xeb\xc5\x53\xba\x62\x79\x6e\x44\x0f\x7a\x2e\xbe\x02\x8c\xed\x83\x02\xac\x74\xde\xd9\x55\x7c\x45\x62\xd1\xa7\x7b\xea\x09\x2f\x4c\x72\x63\xcd\x4e\x2a\x46\xc2\xae\xd8\x42\x92\x77\x40\x7c\x06\xc3\xc1\x39\x72\x27\x2f\x54\x13\xc9\xa3\xf8\xc0\xc4\x90\x3e\xac\xad\xd1\x8f\x0d\xd6\xa5\x49\x22\x83\x73\x63\x0c\x99\x26\xad\x4a\x41\xd0\xfb\x59\x0a\x2f\x29\x62\xb4\x6a\xf3\x33\xfb\xf8\xa6\xe0\xbe\x52\xa9\xce\xbe\xd7\xed\xa6\xca\xbd\x9d\xbb\x45\xdc\xea\x54\x3c\xfc\xac\x68\x78\x0d\x44\xdc\x5c\x49\x8a\xee\x84\xc4\xec\x1c\xef\xba\xdc\x11\x11\xf3\x2f\x1f\x46\xd4\x71\x6f\xa5\x23\x2c\xc0\x25\x25\xee\x1a\x94\x9d\xb4\x6b\xe2\xed\xec\x39\x13\xd1\xa2\x49\xa1\x67\xa1\xf8\xab\xc8\x3d\xdd\x16\x3f\x2a\x26\xb2\x7a\xf4\xf9\x9d\x29\x3f\xfc\xa6\x08\x7c\xce\x74\x52\x04\xf0\x0d\x60\x37\xd1\x00\xb8\x18\x22\xab\xfe\xd5\x1c\xc3\x66\x53\x83\x5a\x82\x40\x4d\x61\x92\x05\x8f\x55\x3d\xb2\x7d\x4d\x10\xd0\x62\xc1\xa3\x5f\x06\x5d\x4b\xf5\x0f\xa6\xa1\x99\x44\xb9\x27\x0c\x49\x02\x81\x81\x00\xd9\xb1\xab\x30\x7b\xf2\xf6\x79\xe5\x70\xf5\x40\xea\xae\xaf\x1b\xe3\x61\x84\x80\x80\x3a\xf1\x6a\xcb\x67\x85\x65\xc8\x4a\x04\x4e\x8d\x97\x66\x4f\x51\x0a\x7a\x49\x3e\x33\x39\x6c\x09\x8c\x47\xa6\x2a\xf9\xe7\xbf\x2a\x7d\xa0\x33\x2a\xb6\x0b\xf3\x40\x1d\xa4\xce\xbe\xa7\x1e\x7d\x1a\xf2\x90\xc4\xa3\xe0\xe9\x05\xdc\xe6\x80\x1e\xde\x46\x68\x70\xd9\x27\xfb\x22\x4a\x2a\xfa\xcd\x86\xc7\x7d\xed\x75\xa0\x95\x46\x32\xa4\xd7\x5c\xfd\x8e\x3d\x0a\x35\xda\x1d\x0d\x09\xc2\x9a\xd2\xa2\x1f\x0e\x87\x27\x0e\x39\xb8\x45\x8e\xf7\xc7\x02\x81\x81\x00\xc1\xef\x21\xa8\x00\x50\xce\x14\xaf\x8c\x09\xaf\xaa\x5f\xe9\x1f\xe6\x48\xed\x99\xff\xea\x3f\x89\xca\xf6\xf1\x19\x89\x65\x53\x09\xbd\xc8\x4e\x21\xb8\x21\xd9\xaa\x8b\x12\x07\xf9\x54\xdb\x70\xd1\xe0\x4a\xa9\x79\x9c\x73\x85\x6a\xdc\xbe\xe9\xef\x0f\xf9\xc6\xed\xea\x3b\x5d\xec\x27\x94\xe0\xa5\x41\xad\x57\x10\xd3\x40\xd4\x91\x11\xb6\xb4\x0a\x7d\xed\xf0\xa2\x74\x71\x7a\xad\x24\x71\x22\x52\x3a\xbb\xb8\x7e\x7c\x74\x06\x06\xfa\x84\x5d\x1e\xad\x0c\xbb\xd8\x11\x0d\x5e\x91\xad\x95\x3b\x1a\x45\x5a\x5e\xbf\x73\xb7\x4c\x2f\x02\x81\x80\x5b\xe5\x0d\x1f\xc5\x62\xf5\xba\xd5\x29\x0e\xce\x9d\x82\xa9\xf6\xba\xd0\x82\x8f\x80\x11\xe1\xb1\x34\x35\xf9\xf0\xd2\x50\xb4\x6a\xb8\x88\x8d\xae\xb3\xc6\x19\x82\xeb\x97\xd2\x08\x92\x2b\x3e\x5f\x9d\xca\xaa\x92\x5f\x0c\x72\xe0\xc6\x89\xdc\x97\x8d\x9c\x35\xe2\xf4\x46\x35\xaf\x97\xfd\x87\x31\x0b\x00\xb9\x3d\x39\x57\xb0\x03\xd7\xce\x9e\xed\xec\x2d\x5d\x6c\xc7\x24\x47\x85\x14\xfd\x07\x62\x83\x02\x0b\xa1\x7b\x65\x6c\x68\x1b\xbc\xbc\x75\x9f\xef\xf7\xcd\x76\x2e\x49\x0e\xdb\x53\x02\xdd\xf8\x95\x9f\xb5\xf2\xde\xfc\x27\x02\x81\x81\x00\xbd\xca\x92\x0c\x81\x2a\x93\x53\xe9\x2c\xca\x39\xf1\x29\xe5\xd3\x03\x22\x71\xed\x19\x67\x9d\x00\xf3\xf1\xd1\xa8\x25\x2f\x55\x21\x9e\x6a\x8e\x14\x2f\xc8\x68\xe5\x9f\x2e\x69\x41\x58\x0b\x5d\x90\xf7\xc8\xf9\xac\x7b\x31\x0e\xeb\xb2\xd6\xdf\xc7\xc6\xc1\xb2\x2e\x19\xe2\x39\x9b\xa8\x6c\xe9\xa0\xb0\xf2\xbb\xd7\x4a\x77\x12\xd0\x5a\x1e\x8c\x7a\x0c\x1d\xb5\x36\xb7\x70\x6b\x17\x51\x27\xaa\xe8\x00\x74\xc0\x2c\x81\x0d\x66\xec\xa3\x74\xb0\x51\x1a\x17\xf1\x29\x96\x1e\x98\x63\x47\x16\x59\x7d\xef\x4b\x6e\x98\x3c\xdd\xb0\x9f\x02\x81\x81\x00\xd5\xf2\x6a\x02\x98\xc3\x98\x62\xb3\x0d\xd6\xc2\x28\x9e\xa3\x2b\xff\x1f\x62\x55\x77\x0c\x10\x4b\x08\x7a\xd6\xe7\x75\xe1\xa3\x0d\x67\xb5\x8b\x36\x97\x1a\x46\x12\xae\xa6\xdb\xdd\xfb\xf6\xde\x20\x4f\xea\x85\x9c\xf8\x2b\x9f\xbe\x2c\xbd\xee\x6d\x81\xcd\xf9\x2d\xce\x68\x55\x3f\x71\x56\x02\x0a\x94\xa1\xaf\xf2\x51\x33\xf4\x3d\x4f\x09\x27\x9e\xac\x7b\x28\xad\x7f\x9d\x25\xba\xd0\xbf\xba\x83\x4a\xcc\x9f\x80\xda\x7e\x6a\xd6\x38\x3f\xac\xb8\xd9\xbd\x48\x9a\x2e\x17\x2c\xfd\x92\x5e\xc8\xcf\x77\x20\x62\xe5\x5f\xe9\x2c\xae";
// clang-format on

// clang-format off
#ifndef __FILE_NAME__
#define __FILE_NAME__ (strrchr(__FILE__,'/')?strrchr(__FILE__,'/')+1:__FILE__)
#endif
#define BUILD_INFO "0.1.1"
#define log(lv,msg...){printf("\e[1m\e[3%dm[%s:%04d]\e[0m ",lv,__FILE_NAME__,__LINE__);printf(msg);printf("\n");};
#define h(v,op,msg...)if(!(v)){log(1,msg);op;};
// clang-format on

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool server_running = true;

int create_socket(bool isServer) {
  int s;
  int optval = 1;
  struct sockaddr_in addr;

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("Unable to create socket");
    exit(1);
  }

  if (isServer) {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
      perror("setsockopt(SO_REUSEADDR) failed");
      exit(1);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      perror("Unable to bind");
      exit(1);
    }

    if (listen(s, 1) < 0) {
      perror("Unable to listen");
      exit(1);
    }
  }
  // ERRO
  return s;
}

void configure_client_context(SSL_CTX *ctx) {
  /*
   * Configure the client to abort the handshake if certificate verification
   * fails
   */
  // https://blog.csdn.net/u013919153/article/details/78616737
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  /*
   * In a real application you would probably just use the default system
   * certificate trust store and call: SSL_CTX_set_default_verify_paths(ctx); In
   * this demo though we are using a self-signed certificate, so the client must
   * trust it directly.
   */
  // if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
  //   ERR_print_errors_fp(stderr);
  //   exit(1);
  // }
}

void usage() {
  printf("Usage: sslecho s\n");
  printf("       --or--\n");
  printf("       sslecho c ip\n");
  printf("       c=client, s=server, ip=dotted ip of server\n");
  exit(1);
}

int main(int argc, char **argv) {
  bool isServer;
  int result;

  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;

  int server_skt = -1;
  int client_skt = -1;

  /* used by getline relying on realloc, can't be statically allocated */
  char *txbuf = NULL;
  size_t txcap = 0;
  int txlen;

  char rxbuf[128];
  size_t rxcap = sizeof(rxbuf);
  int rxlen;

  char *rem_server_ip = NULL;

  struct sockaddr_in addr;
  unsigned int addr_len = sizeof(addr);

  /* ignore SIGPIPE so that server can continue running when client pipe closes
   * abruptly */
  signal(SIGPIPE, SIG_IGN);

  /* Splash */
  printf("\nsslecho : Simple Echo Client/Server : %s : %s\n\n", __DATE__, __TIME__);

  /* Need to know if client or server */
  if (argc < 2) {
    usage();
    /* NOTREACHED */
  }
  isServer = (argv[1][0] == 's') ? true : false;
  /* If client get remote server address (could be 127.0.0.1) */
  if (!isServer) {
    if (argc != 3) {
      usage();
      /* NOTREACHED */
    }
    rem_server_ip = argv[2];
  }

  /* Create context used by both client and server */
  {
    const SSL_METHOD *method;

    if (isServer)
      method = TLS_server_method();
    else
      method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
      perror("Unable to create SSL context");
      exit(1);
    }
  }

  /* If server */
  if (isServer) {

    printf("We are the server on port: %d\n\n", server_port);

    /* Configure server context with appropriate key files */
    h(SSL_CTX_use_certificate_ASN1(ctx, sizeof(CERT_ASN1), CERT_ASN1) > 0, (ERR_print_errors_fp(stderr), exit(1)), "_");
    h(SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_NONE, ctx, (unsigned char *)KEY_ASN1, sizeof(KEY_ASN1)) > 0, exit(1), "_");

    /* Create server socket; will bind with server port and listen */
    server_skt = create_socket(true);

    /*
     * Loop to accept clients.
     * Need to implement timeouts on TCP & SSL connect/read functions
     * before we can catch a CTRL-C and kill the server.
     */
    while (server_running) {
      /* Wait for TCP connection from client */
      client_skt = accept(server_skt, (struct sockaddr *)&addr, &addr_len);
      if (client_skt < 0) {
        perror("Unable to accept");
        exit(1);
      }

      printf("Client TCP connection accepted\n");

      /* Create server SSL structure using newly accepted client socket */
      ssl = SSL_new(ctx);
      // BIO_METHOD
      SSL_set_fd(ssl, client_skt);

      /* Wait for SSL connection from the client */
      if (SSL_accept(ssl) <= 0) {
        log(2, "SSL_accept failed");
        server_running = false;
      } else {

        printf("Client SSL connection accepted\n\n");

        /* Echo loop */
        while (true) {
          /* Get message from client; will fail if client closes connection */
          if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
            if (rxlen == 0) {
              printf("Client closed connection\n");
            } else {
              printf("SSL_read returned %d\n", rxlen);
            }
            break;
          }
          /* Insure null terminated input */
          rxbuf[rxlen] = 0;
          /* Look for kill switch */
          if (strcmp(rxbuf, "kill\n") == 0) {
            /* Terminate...with extreme prejudice */
            printf("Server received 'kill' command\n");
            server_running = false;
            break;
          }
          /* Show received message */
          printf("Received: %s", rxbuf);
          /* Echo it back */
          if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
            log(2, "SSL_write failed");
          }
        }
      }
      if (server_running) {
        /* Cleanup for next client */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_skt);
      }
    }
    printf("Server exiting...\n");
  }
  /* Else client */
  else {

    printf("We are the client\n\n");

    /* Configure client context so we verify the server correctly */
    configure_client_context(ctx);

    /* Create "bare" socket */
    client_skt = create_socket(false);
    /* Set up connect address */
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
    addr.sin_port = htons(server_port);
    /* Do TCP connect with server */
    if (connect(client_skt, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      perror("Unable to TCP connect to server");
      goto exit;
    } else {
      printf("TCP connection to server successful\n");
    }

    /* Create client SSL structure using dedicated client socket */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_skt);
    /* Set hostname for SNI */
    SSL_set_tlsext_host_name(ssl, rem_server_ip);
    /* Configure server hostname check */
    SSL_set1_host(ssl, rem_server_ip);

    /* Now do SSL connect with server */
    if (SSL_connect(ssl) == 1) {

      printf("SSL connection to server successful\n\n");

      /* Loop to send input from keyboard */
      while (true) {
        /* Get a line of input */
        txlen = getline(&txbuf, &txcap, stdin);
        /* Exit loop on error */
        if (txlen < 0 || txbuf == NULL) {
          break;
        }
        /* Exit loop if just a carriage return */
        if (txbuf[0] == '\n') {
          break;
        }
        /* Send it to the server */
        if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
          printf("Server closed connection\n");
          break;
        }

        /* Wait for the echo */
        rxlen = SSL_read(ssl, rxbuf, rxcap);
        if (rxlen <= 0) {
          printf("Server closed connection\n");
          break;
        } else {
          /* Show it */
          rxbuf[rxlen] = 0;
          printf("Received: %s", rxbuf);
        }
      }
      printf("Client exiting...\n");
    } else {
      log(2, "SSL connection to server failed");
    }
  }
exit:
  /* Close up */
  if (ssl != NULL) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  SSL_CTX_free(ctx);

  if (client_skt != -1)
    close(client_skt);
  if (server_skt != -1)
    close(server_skt);

  if (txbuf != NULL && txcap > 0)
    free(txbuf);

  printf("sslecho exiting\n");

  return 0;
}
