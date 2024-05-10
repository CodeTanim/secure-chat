#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen ee*/
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "util.h"
#include <openssl/evp.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

// TODO: implement the 3dh way, how to do longterm keys and epheremal keys?

// not available by default on all systems
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

static unsigned char globalSharedSecret[256];

static GtkTextBuffer *tbuf; /* transcript buffer */
static GtkTextBuffer *mbuf; /* message buffer */
static GtkTextView *tview;	/* view for transcript */
static GtkTextMark *mark;	/* used for  scrolling to end of transcript, etc */

static pthread_t trecv; /* wait for incoming messagess and post to queue */
void *recvMsg(void *);	/* for trecv */

#define max(a, b) \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stfwefwefwuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void loadLongTermKey(const char *fname, dhKey *K)
{
	FILE *file = fopen(fname, "r");

	if (file == NULL)
	{
		fprintf(stderr, "key file not found, so creating %s\n", fname);
		initKey(K);
		dhGenk(K);
		writeDH(fname, K);
	}

	else
	{
		printf(" Public key file found, reading...\n");

		if (readDH(fname, K) < 0)
		{
			printf("error reading key file.");
		}
	}
}

// Function to encrypt and send a test message without a nonce
void encryptAndSendTestMessage(int sockfd, unsigned char *sharedSecret, size_t klen)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[16] = {0}; // Initialize IV to zeros

	// Set up encryption using the shared secret
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sharedSecret, iv);

	// Define a basic test message
	const char *testMsg = "auth-test";
	unsigned char ciphertext[128];
	int len, ciphertext_len;

	// Encrypt the message
	EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)testMsg, strlen(testMsg));
	ciphertext_len = len;
	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;

	printf("ciphertext: %s\n", ciphertext);
	// Send the encrypted test message to the other party
	send(sockfd, ciphertext, ciphertext_len, 0);

	EVP_CIPHER_CTX_free(ctx);
}

// Function to receive and verify the encrypted test message without a nonce
void receiveAndVerifyTestResponse(int sockfd, unsigned char *sharedSecret, size_t klen)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[16] = {0}; // Initialize IV to zeros

	// Set up decryption using the shared secret
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sharedSecret, iv);

	unsigned char ciphertext[128];
	int nbytes = recv(sockfd, ciphertext, sizeof(ciphertext), 0);

	// Check if the message was successfully received
	if (nbytes <= 0)
	{
		fprintf(stderr, "Failed to receive encrypted test message\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	unsigned char plaintext[128] = {0}; // Ensure buffer is zeroed
	int len, plaintext_len;

	// Decrypt the received test message
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, nbytes) != 1)
	{
		fprintf(stderr, "DecryptUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	plaintext_len = len;
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
	{
		fprintf(stderr, "DecryptFinal failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	plaintext_len += len;
	plaintext[plaintext_len] = '\0'; // Null-terminate the string

	// Verify the decrypted message content
	if (strcmp((char *)plaintext, "auth-test") == 0)
	{
		printf("Explicit authentication successful\n");
		printf("decrypted text: %s\n", plaintext);
	}
	else
	{
		fprintf(stderr, "Explicit authentication failed: Invalid message content\n");
	}

	EVP_CIPHER_CTX_free(ctx);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n", port);
	listen(listensock, 1);
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);

	// New additions:
	// Generate server's ephemeral DH key
	dhKey serverKey;
	initKey(&serverKey);
	dhGenk(&serverKey);

	// Generate server's long-term DH key
	dhKey serverLongTermKey;
	// initKey(&serverLongTermKey);

	// load the long term key
	loadLongTermKey("longTermServer", &serverLongTermKey);

	// gmp_printf("longtermserver pubkey: %Zd\n", serverLongTermKey.PK);
	// gmp_printf("longtermserver privkey: %Zd\n", serverLongTermKey.SK);

	// Serialize and send server's epheremal public key
	if (serialize_mpz(sockfd, serverKey.PK) == 0)
	{
		perror("Failed to send server's epheremal public key");
		shredKey(&serverKey);
		return -1;
	}

	// Prepare to receive client's epheremal public key
	mpz_t clientPubKey;
	mpz_init(clientPubKey);
	if (deserialize_mpz(clientPubKey, sockfd) != 0)
	{
		perror("Failed to receive client's public key");
		shredKey(&serverKey);
		mpz_clear(clientPubKey);
		return -1;
	}

	// debugging:
	// gmp_printf("Server Public Key: %Zd\n", serverKey.PK);
	// gmp_printf("Server Secret Key: %Zd\n", serverKey.SK);

	const size_t klen = 256;
	unsigned char sharedSecret[klen]; // Adjust size based on security needs

	// after recieving clients public epheremal key and reading clients long term pub key from .pub file, compute
	// the shared secret

	dhKey longTermClientpub;
	readDH("longtermClient.pub", &longTermClientpub);

	// gmp_printf("long term client pub key recieved: %Zd\n", longTermClientpub.PK);
	if (dh3Final(serverLongTermKey.SK, serverLongTermKey.PK, serverKey.SK, serverKey.PK, longTermClientpub.PK, clientPubKey, sharedSecret, klen) != 0)
	{
		perror("Failed to compute shared secret");
	}

	// Clean up
	mpz_clear(clientPubKey);
	shredKey(&serverKey);
	shredKey(&longTermClientpub);

	// Encrypt and send the test message from server to client
	// // testing global secret:
	// memcpy(globalSharedSecret, sharedSecret, klen);

	encryptAndSendTestMessage(sockfd, sharedSecret, klen);

	// Receive and verify the test response from the client
	receiveAndVerifyTestResponse(sockfd, sharedSecret, klen);

	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, shouldd be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char *hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL)
	{
		fprintf(stderr, "ERROR, no such host\n");
		exit(0);
	}
	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */

	// Generate client's ephemeral DH key
	dhKey clientKey;
	initKey(&clientKey);
	dhGenk(&clientKey);

	// Print client's public and secret key
	// gmp_printf("Client Public Key: %Zd\n", clientKey.PK);
	// gmp_printf("Client Secret Key: %Zd\n", clientKey.SK);

	// read/generate client's longterm keys
	dhKey clientLongTermKey;
	loadLongTermKey("longTermClient", &clientLongTermKey);

	// gmp_printf("client longterm pubkey: %Zd\n", clientLongTermKey.PK);
	// gmp_printf("client longterm privkey: %Zd\n", clientLongTermKey.SK);

	// Send client's public key
	if (serialize_mpz(sockfd, clientKey.PK) == 0)
	{
		perror("Failed to send client's public key");
		shredKey(&clientKey);
		return -1;
	}

	// Receive server's public key
	mpz_t serverPubKey;
	mpz_init(serverPubKey);
	if (deserialize_mpz(serverPubKey, sockfd) != 0)
	{
		perror("Failed to receive server's public key");
		shredKey(&clientKey);
		return -1;
	}

	// gmp_printf("Received Server Public Key: %Zd\n", serverPubKey);

	size_t klen = 256;
	// Compute the shared secret
	unsigned char sharedSecret[klen]; // Adjust size based on security needs

	dhKey longTermServerpub;
	readDH("longtermServer.pub", &longTermServerpub);

	// gmp_printf("long term server pub key recieved: %Zd\n", longTermServerpub.PK);

	if (dh3Final(clientLongTermKey.SK, clientLongTermKey.PK, clientKey.SK, clientKey.PK, longTermServerpub.PK, serverPubKey, sharedSecret, klen) != 0)
	{
		perror("Failed to compute shared secret");
	}

	mpz_clear(serverPubKey);
	shredKey(&clientKey);
	shredKey(&longTermServerpub);

	// Receive and verify the test message from the server
	receiveAndVerifyTestResponse(sockfd, sharedSecret, klen);

	// Encrypt and send the test response from client to server
	encryptAndSendTestMessage(sockfd, sharedSecret, klen);

	fprintf(stderr, "Secure connection established.\n");
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd, 2);
	unsigned char dummy[64];
	ssize_t r;
	do
	{
		r = recv(sockfd, dummy, 64, 0);
	} while (r != 0 && r != -1);

	memset(globalSharedSecret, 0, sizeof(globalSharedSecret)); // clear global secret
	close(sockfd);
	return 0;
}

/* end network stuff. */

static const char *usage =
	"Usage: %s [OPTIONS]...\n"
	"Secure chat (CCNY computer security project).\n\n"
	"   -c, --connect HOST  Attempt a connection to HOST.\n"
	"   -l, --listen        Listen for new connections.\n"
	"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
	"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char *message, char **tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf, &t0);
	size_t len = g_utf8_strlen(message, -1);
	if (ensurenewline && message[len - 1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf, &t0, message, len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf, &t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0, len);
	if (tagnames)
	{
		char **tag = tagnames;
		while (*tag)
		{
			gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
			tag++;
		}
	}
	if (!ensurenewline)
		return;
	gtk_text_buffer_add_mark(tbuf, mark, &t1);
	gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
	gtk_text_buffer_delete_mark(tbuf, mark);
}

static void sendMessage(GtkWidget *w /* <-- msg entry widget */, gpointer /* data */)
{
	char *tags[2] = {"self", NULL};
	tsappend("me: ", tags, 0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;	/* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	char *message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);
	size_t len = g_utf8_strlen(message, -1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes;
	if ((nbytes = send(sockfd, message, len, 0)) == -1)
		error("send failed");

	tsappend(message, NULL, 1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf, &mstart, &mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char *tags[2] = {"friend", NULL};
	char *friendname = "mr. friend: ";
	tsappend(friendname, tags, 0);
	char *message = (char *)msg;
	tsappend(message, NULL, 1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0)
	{
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}

	// define long options
	static struct option long_opts[] = {
		{"connect", required_argument, 0, 'c'},
		{"listen", no_argument, 0, 'l'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX + 1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1)
	{
		switch (c)
		{
		case 'c':
			if (strnlen(optarg, HOST_NAME_MAX))
				strncpy(hostname, optarg, HOST_NAME_MAX);
			break;
		case 'l':
			isclient = 0;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			printf(usage, argv[0]);
			return 0;
		case '?':
			printf(usage, argv[0]);
			return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient)
	{
		initClientNet(hostname, port);
	}
	else
	{
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder *builder;
	GObject *window;
	GObject *button;
	GObject *transcript;
	GObject *message;
	GError *error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder, "layout.ui", &error) == 0)
	{
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark = gtk_text_mark_new(NULL, TRUE);
	window = gtk_builder_get_object(builder, "window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider *css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css, "colors.css", NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
											  GTK_STYLE_PROVIDER(css),
											  GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "font", "italic", NULL);
	gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "font", "bold", NULL);
	gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "font", "bold", NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv, 0, recvMsg, 0))
	{
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void *recvMsg(void *)
{
	size_t maxlen = 512;
	char msg[maxlen + 2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1)
	{
		if ((nbytes = recv(sockfd, msg, maxlen, 0)) == -1)
			error("recv failed");
		if (nbytes == 0)
		{
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		char *m = malloc(maxlen + 2);
		memcpy(m, msg, nbytes);
		if (m[nbytes - 1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
	}
	return 0;
}
