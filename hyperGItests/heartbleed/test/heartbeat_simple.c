/* test/heartbeat_test.c */
/*
 * Code Adapted from heartbeats unit test in openssl-1.0.1h
 * More information for Heartbleed bug:
 *      http://mike-bland.com/2014/04/12/heartbleed.html
 * 
 * Unit test for TLS heartbeats Information Leakage
 * Acts as a regression test against the Heartbleed bug (CVE-2014-0160).
 *
 * Author:  Ibrahim Mesecan (imesecan@gmail.com),
 * Date:    2020-03-05
 * License: Creative Commons Attribution 4.0 International (CC By 4.0)
 *          http://creativecommons.org/licenses/by/4.0/deed.en_US
 *
 * OUTPUT
 * ------
 * The program returns zero on success. It will print a message with a count
 * of the number of failed tests and return nonzero if any tests fail.
 *
 * It will print the contents of the request and response buffers for each
 * failing test. In a "fixed" version, all the tests should pass and there
 * should be no output.
 *
 * The contents of the returned buffer in the failing test will depend on the
 * contents of memory on your machine.
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "../ssl/ssl_locl.h"
#include "leakage.h"

#if !defined(OPENSSL_NO_HEARTBEATS) && !defined(OPENSSL_SYS_WINDOWS)

/* As per https://tools.ietf.org/html/rfc6520#section-4 */
#define MIN_PADDING_SIZE	16
int verbose 	=  false; //	false; // Detailed verbose

/* Maximum number of payload characters to print as test output */
#define MAX_PRINTABLE_CHARACTERS	250

typedef struct heartbeat_test_fixture
{
	SSL_CTX *ctx;
	SSL *s;
	const char* test_case_name;
	const char* expRet_payload;
	ucp* payload_received;
	ucp* payload;
	int (*process_heartbeat)(SSL* s);
	int sent_payload_len;
	int expRet_value;
	int return_payload_offset;
	int expPyl_len;
	int payload_received_len;
} HEARTBEAT_TEST_FIXTURE;


static HEARTBEAT_TEST_FIXTURE set_up(const char* const test_case_name,
	const SSL_METHOD* meth)
{
	HEARTBEAT_TEST_FIXTURE fixture;
	int setup_ok = 1;
	memset(&fixture, 0, sizeof(fixture));
	fixture.test_case_name = test_case_name;

	fixture.ctx = SSL_CTX_new(meth);
	if (!fixture.ctx)
	{
		fprintf(stderr, "Failed to allocate SSL_CTX for test: %s\n",
			test_case_name);
		setup_ok = 0;
		goto fail;
	}

	fixture.s = SSL_new(fixture.ctx);
	if (!fixture.s)
	{
		fprintf(stderr, "Failed to allocate SSL for test: %s\n", test_case_name);
		setup_ok = 0;
		goto fail;
	}

	if (!ssl_init_wbio_buffer(fixture.s, 1))
	{
		fprintf(stderr, "Failed to set up wbio buffer for test: %s\n",
			test_case_name);
		setup_ok = 0;
		goto fail;
	}

	if (!ssl3_setup_buffers(fixture.s))
	{
		fprintf(stderr, "Failed to setup buffers for test: %s\n",
			test_case_name);
		setup_ok = 0;
		goto fail;
	}

	/* Clear the memory for the return buffer, since this isn't automatically
	 * zeroed in opt mode and will cause spurious test failures that will change
	 * with each execution.
	 */
	memset(fixture.s->s3->wbuf.buf, 0, fixture.s->s3->wbuf.len);

	fail:
	if (!setup_ok)
	{
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return fixture;
}

static HEARTBEAT_TEST_FIXTURE set_up_dtls(const char* const test_case_name)
{
	HEARTBEAT_TEST_FIXTURE fixture = set_up(test_case_name,
		DTLSv1_server_method());
	fixture.process_heartbeat = dtls1_process_heartbeat;

	/* As per dtls1_get_record(), skipping the following from the beginning of
	 * the returned heartbeat message:
	 * type-1 byte; version-2 bytes; sequence number-8 bytes; length-2 bytes
	 *
	 * And then skipping the 1-byte type encoded by process_heartbeat for
	 * a total of 14 bytes, at which point we can grab the length and the
	 * payload we seek.	 */
	fixture.return_payload_offset = 14;
	return fixture;
}

/* Needed by ssl3_write_bytes() */
static int dummy_handshake(SSL* s)
{	
	return true; 
}

static void tear_down(HEARTBEAT_TEST_FIXTURE fixture)
{
	ERR_print_errors_fp(stderr);
	SSL_free(fixture.s);
	if(fixture.ctx != NULL)
		SSL_CTX_free(fixture.ctx);
}

unsigned char * prepare4Response()
{
    unsigned int padding = MIN_PADDING_SIZE;

	unsigned char *buffer = OPENSSL_malloc(3 + padding + 2);
	unsigned char *bp = buffer;
		
	*bp++ = TLS1_HB_RESPONSE;	
	s2n(padding+2, bp);
	*bp++ = 0;
	*bp++ = 0;

	RAND_pseudo_bytes(bp, padding);
	
	return buffer;
}

static int execute_heartbeat(HEARTBEAT_TEST_FIXTURE *fixture, int j, int prob)
{
	int result = SUCCESS;
	SSL* s = fixture->s;
	int return_value;
	unsigned const char *p;
	int actual_len = 0; // length of payload received

	// Prepare data to send
	ucp *payload = fixture->payload;
	s->s3->rrec.data = payload;
	s->s3->rrec.length = strlen((const char*)payload);
	*payload++ = TLS1_HB_REQUEST;
	int sent_payload_len = fixture->sent_payload_len;
	if (j == 2 || j == 3)
	{
    	payload = prepare4Response();
    	fixture->payload = payload;
    	s->s3->rrec.data = payload;
    	s->s3->rrec.length = MIN_PADDING_SIZE + 2;
    	fixture->sent_payload_len = MIN_PADDING_SIZE + 2;
    	sent_payload_len = fixture->sent_payload_len;
	}else 
	{
    	int rnum = rand() % 100;
    	if ((prob == 0 && j > 1) || (rnum<prob))	
    		if (sent_payload_len < MAX_PRINTABLE_CHARACTERS)
    			sent_payload_len = MAX_PRINTABLE_CHARACTERS;
    	
    	s2n(sent_payload_len, payload);
	}
	
	//****** Actual call for the function ********
	return_value = fixture->process_heartbeat(s);
	//********************************************

	// get received data
	p = &(s->s3->wbuf.buf[fixture->return_payload_offset + s->s3->wbuf.offset]);
	n2s(p, actual_len);
	fixture->payload_received = calloc(actual_len, sizeof(ucp));	
	ucpcpy(fixture->payload_received, p, actual_len);
	fixture->payload_received_len = actual_len;	

	if (return_value != fixture->expRet_value || actual_len != fixture->expPyl_len)
	{
		if(verbose == true) 
		{
			if (return_value != fixture->expRet_value )		
				printf("%s has failed:\n  expected return value %d,\n  received %d\n",
					 fixture->test_case_name, fixture->expRet_value, return_value);
			else printf("%s has failed:\n  expected payload len: %d\n  received: %d\n",
					 fixture->test_case_name, fixture->expPyl_len, actual_len);
		}
		result = FAILURE;
	} else if (j==2 || j==3) { return SUCCESS; }
	else 
	{
		int cnt = 0;
		if( fixture->expRet_payload == NULL) cnt++;
		if( fixture->payload_received == NULL) cnt++;
		if( cnt == 1)
		{
			if(verbose == true)		
				printf("%s has failed:\n  expected payload: \"%s\"\n  received: \"%s\"\n",
					 fixture->test_case_name, fixture->expRet_payload,
					 fixture->payload_received);
			result = FAILURE;
		}
		else if (ucpcmp(fixture->payload_received, (ucp *)fixture->expRet_payload, actual_len ) != 0)
		{
			if(verbose == true)		
				printf("%s has failed:\n  expected payload: \"%s\"\n  received: \"%s\"\n",
					 fixture->test_case_name, fixture->expRet_payload,
					 fixture->payload_received);
			result = FAILURE;
		}
		if(verbose == true)		
			printf("%s has not failed:\n  expected payload len: %d\n  received: %d\n",
				 fixture->test_case_name, fixture->expPyl_len, actual_len);
			
	}// end of else 

	return result;
}

static int honest_payload_size(unsigned char payload_buf[])
{
	/* Omit three-byte pad at the beginning for type and payload length */
	return strlen((const char*)&payload_buf[3]) - MIN_PADDING_SIZE;
}

#undef EXECUTE_HEARTBEAT_TEST
#undef SETUP_HEARTBEAT_TEST_FIXTURE
#define SETUP_HEARTBEAT_TEST_FIXTURE(type)\
	HEARTBEAT_TEST_FIXTURE fixture = set_up_##type(__func__)


// payload is the input string
// exp is the expected output,
// rec is the received output
// rlen is the length of received string
static int test_tls1(const ucp *payload, ucp **rec, int j, int *rlen, int prob)
{
	int result = SUCCESS;
	
	/***************** Prepare Fixture **************************/
	SETUP_HEARTBEAT_TEST_FIXTURE(dtls);
	
	// since payload is modified during the process
	ucp *payload_buf = ucpdup(payload, strlen((char *)payload));	
	const int payload_buf_len = honest_payload_size(payload_buf);

	fixture.payload = &payload_buf[0];
	fixture.sent_payload_len = payload_buf_len;
	fixture.expRet_value = 0;
	fixture.expPyl_len = payload_buf_len;

	fixture.expRet_payload = "";
	if (payload_buf_len > 0) 
		fixture.expRet_payload = ucpdup(exp, payload_buf_len);

	/***************** Actual Process ***************************/            
	result = execute_heartbeat(&fixture, j, prob);
	
	/**************** Prepare output string **********************/
	*rlen = 0;
	if(fixture.payload_received_len > 0) {
		if(verbose == true)		
			printf("Fixture Payload len: %d\n", fixture.payload_received_len);
		*rec = (ucp *) ucpdup(fixture.payload_received, fixture.payload_received_len);
		*rlen = fixture.payload_received_len;
	}

	tear_down(fixture);
	return result;
}

int main(int argc, char *argv[])
{
	SSL_library_init();
	SSL_load_error_strings();

	char buf[1024];
	int len = read(STDIN_FILENO, buf, 1024);

	ucp *sent = genInputStr(buf, len);
	ucp *received = NULL; // the text received back from the call
	int rlen = 0; // length of received text
	int prob = 0;
	test_tls1(sent, &received, 0, &rlen, prob);

	return EXIT_SUCCESS;
}

#else /* OPENSSL_NO_HEARTBEATS*/

int main(int argc, char *argv[])
	{
		return EXIT_SUCCESS;
	}
#endif /* OPENSSL_NO_HEARTBEATS */

