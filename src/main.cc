/* server-tls.c */

/* the usual suspects */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* socket includes */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

const int DEFAULT_PORT = 11111;
const char *CERT_FILE =
    "/home/kkocdko/misc/code/misc/cert_localhost/localhost+2.pem";
const char *KEY_FILE =
    "/home/kkocdko/misc/code/misc/cert_localhost/localhost+2-key.pem";

int main() {
  int sockfd = SOCKET_INVALID;
  int connd = SOCKET_INVALID;
  struct sockaddr_in servAddr;
  struct sockaddr_in clientAddr;
  socklen_t size = sizeof(clientAddr);
  char buff[256];
  size_t len;
  int shutdown = 0;
  int ret;
  const char *reply = "I hear ya fa shizzle!\n";

  /* declare wolfSSL objects */
  WOLFSSL_CTX *ctx = NULL;
  WOLFSSL *ssl = NULL;

  /* Initialize wolfSSL */
  wolfSSL_Init();

  /* Create a socket that uses an internet IPv4 address,
   * Sets the socket to be stream based (TCP),
   * 0 means choose the default protocol. */
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "ERROR: failed to create the socket\n");
    ret = -1;
    goto exit;
  }

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
    ret = -1;
    goto exit;
  }

  /* Load server certificates into WOLFSSL_CTX */
  if ((ret = wolfSSL_CTX_use_certificate_file(
           ctx, CERT_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
            CERT_FILE);
    goto exit;
  }

  /* Load server key into WOLFSSL_CTX */
  if ((ret = wolfSSL_CTX_use_PrivateKey_file(
           ctx, KEY_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
            KEY_FILE);
    goto exit;
  }

  /* Initialize the server address struct with zeros */
  memset(&servAddr, 0, sizeof(servAddr));

  /* Fill in the server address */
  servAddr.sin_family = AF_INET;           /* using IPv4      */
  servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
  servAddr.sin_addr.s_addr = INADDR_ANY;   /* from anywhere   */

  /* Bind the server socket to our port */
  if (bind(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1) {
    fprintf(stderr, "ERROR: failed to bind\n");
    ret = -1;
    goto exit;
  }

  /* Listen for a new connection, allow 5 pending connections */
  if (listen(sockfd, 5) == -1) {
    fprintf(stderr, "ERROR: failed to listen\n");
    ret = -1;
    goto exit;
  }

  /* Continue to accept clients until shutdown is issued */
  while (!shutdown) {
    printf("Waiting for a connection...\n");

    /* Accept client connections */
    if ((connd = accept(sockfd, (struct sockaddr *)&clientAddr, &size)) == -1) {
      fprintf(stderr, "ERROR: failed to accept the connection\n\n");
      ret = -1;
      goto exit;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
      fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
      ret = -1;
      goto exit;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, connd);

    /* Establish TLS connection */
    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
      fprintf(stderr, "wolfSSL_accept error = %d\n",
              wolfSSL_get_error(ssl, ret));
      goto exit;
    }

    printf("Client connected successfully\n");

    /* Read the client data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1) {
      fprintf(stderr, "ERROR: failed to read\n");
      goto exit;
    }

    /* Print to stdout any data the client sends */
    printf("Client: %s\n", buff);

    /* Check for server shutdown command */
    if (strncmp(buff, "shutdown", 8) == 0) {
      printf("Shutdown command issued!\n");
      shutdown = 1;
    }

    /* Write our reply into buff */
    memset(buff, 0, sizeof(buff));
    memcpy(buff, reply, strlen(reply));
    len = strnlen(buff, sizeof(buff));

    /* Reply back to the client */
    if ((ret = wolfSSL_write(ssl, buff, len)) != (int)len) {
      fprintf(stderr, "ERROR: failed to write\n");
      goto exit;
    }

    /* Notify the client that the connection is ending */
    wolfSSL_shutdown(ssl);
    printf("Shutdown complete\n");

    /* Cleanup after this connection */
    wolfSSL_free(ssl); /* Free the wolfSSL object              */
    ssl = NULL;
    close(connd); /* Close the connection to the client   */
  }

  ret = 0;

exit:
  /* Cleanup and return */
  if (ssl)
    wolfSSL_free(ssl); /* Free the wolfSSL object              */
  if (connd != SOCKET_INVALID)
    close(connd); /* Close the connection to the client   */
  if (sockfd != SOCKET_INVALID)
    close(sockfd); /* Close the socket listening for clients   */
  if (ctx)
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  wolfSSL_Cleanup();       /* Cleanup the wolfSSL environment          */

  return ret; /* Return reporting a success               */
}
