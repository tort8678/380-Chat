#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
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
#include <gmp.h>


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */
size_t gmp_export_to_buf(unsigned char *buf, mpz_t num);


#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
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
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	// if connection is successful, begin the handshake
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	else {
		fprintf(stderr, "connected to %s:%i\n",hostname,port);
	}
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
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
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes;
	if ((nbytes = send(sockfd,message,len,0)) == -1)
		error("send failed");

	tsappend(message,NULL,1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int send_mpz_t(int sockfd, mpz_t number) {
    size_t pk_len = (mpz_sizeinbase(number, 2) + 7) / 8;
	unsigned char *pk_buf = malloc(pk_len);
	mpz_export(pk_buf, &pk_len, 1, 1, 1, 0, number);

	uint16_t len_net = htons(pk_len);
	if (write(sockfd, &len_net, 2) != 2 || write(sockfd, pk_buf, pk_len) != pk_len) {
		perror("send pk");
		free(pk_buf);
		return -1;
	}
	free(pk_buf);
	return 0;
}

int recv_mpz_t(int sockfd, mpz_t number) {
    uint16_t peer_len_net;
	if (read(sockfd, &peer_len_net, 2) != 2) {
		perror("read peer key len");
		return -1;
	}

	size_t peer_len = ntohs(peer_len_net);
	unsigned char *peer_buf = malloc(peer_len);
	if (read(sockfd, peer_buf, peer_len) != peer_len) {
		perror("read peer key");
		free(peer_buf);
		return -1;
	}

	mpz_import(number, peer_len, 1, 1, 1, 0, peer_buf);
	free(peer_buf);
	return 0;
}

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", buf[i]);
    printf("\n");
}

void printString(unsigned char str[],int len) {
	for (int i = 0; i < len; ++i)
		printf("%c", str[i]);
}

void getTranscriptHash(unsigned char *out, mpz_t A, mpz_t B, mpz_t X, mpz_t Y) {
    // Calculate expected byte lengths from each number.
    size_t lenA = (mpz_sizeinbase(A, 2) + 7) / 8;
    size_t lenB = (mpz_sizeinbase(B, 2) + 7) / 8;
    size_t lenX = (mpz_sizeinbase(X, 2) + 7) / 8;
    size_t lenY = (mpz_sizeinbase(Y, 2) + 7) / 8;
    size_t total_len = lenA + lenB + lenX + lenY;
    printf("lenA: %zu, lenB: %zu, lenX: %zu, lenY: %zu\n", lenA, lenB, lenX, lenY);
    printf("Total concatenated length: %zu\n", total_len);

    // Allocate a buffer large enough for all exported bytes.
    unsigned char *buf = malloc(total_len);
    if (!buf) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    size_t offset = 0;
    size_t countA, countB, countX, countY;

    // Export A into the buffer
    mpz_export(buf + offset, &countA, 1, 1, 1, 0, A);
    printf("Exported A: %zu bytes\n", countA);
    offset += countA;

    // Export B into the buffer
    mpz_export(buf + offset, &countB, 1, 1, 1, 0, B);
    printf("Exported B: %zu bytes\n", countB);
    offset += countB;

    // Export X into the buffer
    mpz_export(buf + offset, &countX, 1, 1, 1, 0, X);
    printf("Exported X: %zu bytes\n", countX);
    offset += countX;

    // Export Y into the buffer
    mpz_export(buf + offset, &countY, 1, 1, 1, 0, Y);
    printf("Exported Y: %zu bytes\n", countY);
    offset += countY;

    printf("Final offset after export: %zu\n", offset);
    if (offset > total_len) {
        fprintf(stderr, "Error: Offset exceeds allocated buffer size!\n");
        free(buf);
        exit(EXIT_FAILURE);
    }

    // Now compute the SHA256 hash over the concatenated buffer.
    SHA256(buf, offset, out);

    free(buf);
}

size_t gmp_export_to_buf(unsigned char *buf, mpz_t num) {
	size_t pk_len = (mpz_sizeinbase(num, 2) + 7) / 8;
    return (size_t)mpz_export(buf, &pk_len, 1, 1, 1, 0, num);
}

int performMutualAuthentication(int sockfd, unsigned char *kA, size_t klen, 
    unsigned char *transcript_hash, unsigned char *kB_mac) {
    // Alice's MAC from shared key
    unsigned char alice_mac[SHA256_DIGEST_LENGTH];
    if (HMAC(EVP_sha256(), kA, klen, transcript_hash, SHA256_DIGEST_LENGTH, alice_mac, NULL) == NULL) {
        perror("HMAC failed");
        return -1;
    }
    
    // Send Alice's MAC to Bob
    if (send(sockfd, alice_mac, SHA256_DIGEST_LENGTH, 0) == -1) {
        perror("send failed");
        return -1;
    }

    // Receive Bob's MAC
    if (recv(sockfd, kB_mac, SHA256_DIGEST_LENGTH, 0) == -1) {
        perror("recv failed");
        return -1;
    }

    // Verify received MAC
    unsigned char expected_mac[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), kA, klen, transcript_hash, SHA256_DIGEST_LENGTH, expected_mac, NULL);

    if (memcmp(expected_mac, kB_mac, SHA256_DIGEST_LENGTH) == 0) {
        printf("Mutual authentication succeeded!\n");
        return 0;  // Success
    } else {
        printf("Mutual authentication failed!\n");
        return -1;  // Failure
    }
}

int doHandshake(int sockfd, unsigned char *keybuf, size_t buflen) {
    /* Alice's long-term key: */
    NEWZ(a); /* secret key (a random exponent) */
    NEWZ(A); /* public key: A = g^a mod p */
    dhGen(a, A);
    
    /* Alice's ephemeral key: */
    NEWZ(x);
    NEWZ(X);
    dhGen(x, X);

    mpz_t B, Y; /* Bob's long-term public key and ephemeral key */
    mpz_init(B);
    mpz_init(Y);
    
    ssize_t nbytes;
    send_mpz_t(sockfd, A);
    send_mpz_t(sockfd, X);
    recv_mpz_t(sockfd, B);
    recv_mpz_t(sockfd, Y);

    // gmp_printf("user %d public key:%Zd\n", isclient, B);
    // gmp_printf("user %d ephemeral key:%Zd\n", isclient, Y);

    const size_t klen = 128;
    /* Alice's key derivation: */
    unsigned char kA[klen];
    unsigned char kB[klen];
    dh3Final(a, A, x, X, B, Y, kA, klen);

    // Send Alice's shared key kA to Bob
    if ((nbytes = send(sockfd, kA, klen, 0)) == -1)
        error("send failed");

    // Receive Bob's shared key kB
    if (recv(sockfd, kB, klen, 0) == -1) {
        printf("user %d, receiving kB\n", isclient);
        error("recv failed");
    }

    // Key verification: Ensure that both Alice and Bob share the same key
    if (memcmp(kA, kB, klen) == 0) {
        printf("Alice and Bob have the same key :D\n");
        memcpy(keybuf, kA, klen);
    } else {
        printf("Key mismatch! Authentication failed.\n");
        return -1;
    }

    // Now perform mutual authentication at the end:
	unsigned char transcript_hash[SHA256_DIGEST_LENGTH];
	if (isclient) {
		// For the client, her long-term key A and ephemeral X correspond
		// to the server's keys on the other side.
		// So we swap them: Use B and Y in the first positions.
		getTranscriptHash(transcript_hash, B, A, Y, X);
	} else {
		// For the server, the keys are already in the proper order.
		getTranscriptHash(transcript_hash, A, B, X, Y);
	}
    unsigned char kB_mac[SHA256_DIGEST_LENGTH]; // For receiving Bob's MAC

    // Perform mutual authentication with kA, transcript_hash, and kB_mac
    performMutualAuthentication(sockfd, kA, klen, transcript_hash, kB_mac);
	return 0;
}




int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}
	/* Handshake using dh */
	unsigned char sharedKey[128];
	if (doHandshake(sockfd, sharedKey, sizeof(sharedKey)) != 0) {
		fprintf(stderr, "Handshake failed\n");
		exit(1);
	}
	
	printf("Shared key (first 8 bytes): ");
	for (int i = 0; i < 8; i++) printf("%02x", sharedKey[i]);
	printf("\n");

	printf("Handshake successful. Shared secret established.\n");


	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		char* m = malloc(maxlen+2);
		memcpy(m,msg,nbytes);
		if (m[nbytes-1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
	}
	return 0;
}
