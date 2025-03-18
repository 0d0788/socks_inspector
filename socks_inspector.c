/*
 * SOCKS Protocol Version 5 : implementation based on RFC 1928
 * SSL/TLS MITM decryption : based on openssl library from the OpenSSL project
 * Copyright (C) 2025 www.github.com/0d0788. All rights reserved.
 * This program is licensed under the GPLv2+. See LICENSE for more information.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>

#define BUFFERSIZE 65536	// size of the used buffers in bytes (max IPv4 package size)
							// 65536 bytes is 64 Kibibyte, which is the max. IPv4 package size

int open_socket(bool listening_socket, uint32_t addr, uint16_t port) {
	// opens a socket and either binds a name or connects it based on the (bool) listen argument
	int socketfd; // the socket fd returned by the function
	struct sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = addr;
	serveraddr.sin_port = port;
	if((socketfd = socket(AF_INET,SOCK_STREAM | SOCK_NONBLOCK,0)) < 0) {
		char msg[] = "error creating socket : quitting\n";
		write(1, msg, sizeof(msg));
		exit(-1);
	}
	if(listening_socket == true) {
		bind(socketfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
		if(listen(socketfd, 1024) < 0) { // make the socket passive (queue for incoming connections)
			exit(-1); // unknown listen() error
		}
		// use poll() with the returned socketfd to determine if traffic is coming in
	} else {
		connect(socketfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
		// use poll() with the returned socketfd to detemine if the connecting attempt was successfull
	}
	return socketfd;
}

short timeout(int socketfd, short events, int timeout) { // poll() helper to reduce code size
	struct pollfd pollfd;
	pollfd.fd = socketfd;
	pollfd.events = events;
	int poll_return = poll(&pollfd, 1, timeout);
	if(poll_return > 0) {
		return pollfd.revents;
	}
	if(poll_return == 0) {
		return 0; // timeout
	}
	if(poll_return < 0) {
		exit(-1); // unknown poll() error
	}
}

int check_argv(int argc, char *argv[], char *search_word) { // dynamically check arguments regardless of their order
	if(argc > 1) { // only if at least one argument is given
		for(int count = 0; count < argc; count++) {
			if(strcmp(argv[count], search_word) == 0) {
				return count; // return the position of the found argument
			}
		}
	}
	return -1; // searched argument not found :(
}

void hexdump(unsigned char *buffer, size_t bufferlen) {
	int count;
	int bufferlen_count;
	for(bufferlen_count = 0; bufferlen_count < bufferlen; bufferlen_count = bufferlen_count+16) {
		printf("%08X | ", bufferlen_count);
		for(count = 0; count < 16 && (count+bufferlen_count) < bufferlen; count++) {
			printf("%02X ", buffer[bufferlen_count+count]);
		}
		while(count < 16) {
			printf("%02X ", 0x00);
			count++;
		}
		printf("| ");
		for(count = 0; count < 16 && (count+bufferlen_count) < bufferlen; count++) {
			if(isprint(buffer[bufferlen_count+count]) != 0) { // check if the char is printable
				printf("%c", buffer[bufferlen_count+count]);
			} else {
				printf(".");
			}
		}
		while(count < 16) {
			printf(".");
			count++;
		}
		printf("\n");
	}
	printf("\n");
}

size_t editbuffer_new(unsigned char *buffer, size_t bufferlen, char *randvalue) { // new edit function (using external text editor)
	char selection;
	while(1) {
		printf("edit this package or skip? (y/n): "); scanf("%c", &selection);
		getchar(); // consume newline to clear STDIN
		if(selection == 'y' || selection == 'Y') { // selection is yes
			char *editor = getenv("EDITOR"); // get the text editor set in EDITOR env variable
			char path[strlen("/dev/shm/") + strlen(randvalue) + strlen(".tmp") + 1];
			strcpy(path, "/dev/shm/");
			strcat(path, randvalue);
			strcat(path, ".tmp");
			FILE *tmp = fopen(path, "w"); // open (create) the tmp file
			for(int bufferlen_count = 0; bufferlen_count < bufferlen; bufferlen_count = bufferlen_count+16) {
				for(int count = 0; count < 16 && (count+bufferlen_count) < bufferlen; count++) {
					fprintf(tmp, "%02X", buffer[bufferlen_count+count]);
					if(count < 15 && (count+bufferlen_count) < bufferlen) {
						fprintf(tmp, " ");
					}
				}
				fprintf(tmp, "\n");
			}
			fflush(tmp);
			char cmd[strlen(editor) + strlen(path) + 2];
			memset(cmd, 0, sizeof(cmd));
			strcpy(cmd, editor);
			strcat(cmd, " ");
			strcat(cmd, path);
			system(cmd);
			struct stat st;
			fstat(fileno(tmp), &st);
			unsigned char tmpbuffer[st.st_size], *tmpbuffer_pos = tmpbuffer;
			memset(tmpbuffer, 0, sizeof(tmpbuffer));
			size_t tmplen = fread(tmpbuffer, 1, st.st_size, tmp);
			fclose(tmp);
			memset(buffer, 0, BUFFERSIZE);
			int x = 0;
			int y = 0;
			while(y < tmplen && x < BUFFERSIZE) {
				while(*tmpbuffer_pos == '\n' || *tmpbuffer_pos == ' ') {
					tmpbuffer_pos++; // move past space or newline (dont copy them)
					y++;
				}
				// copy the hex value into binary
				if(sscanf(tmpbuffer_pos, "%02X", (buffer+x)) == 1) {
					tmpbuffer_pos += 2; // move past the copied two digit hex value
					y += 2;
					x++; // move to next index in dst buffer
				} else {
					tmpbuffer_pos++; // Skip invalid chars
					y++;
				}
			}
			return (x+1); // return the new len of the buffer (+1 because len starting from index 1 (size in bytes) and not 0)
		}
		else if(selection == 'n' || selection == 'N') { // selection is no
			return 0;
		}
	}
}

void editbuffer(unsigned char *buffer, size_t bufferlen) { // not memory safe the buffers can simply overflow (deprecated, replaced by editbuffer_new)
	char selection;
	while(1) {
		printf("change a single byte, byterange or skip (b/r/s): "); scanf("%c", &selection);
		getchar(); // consume newline to clear STDIN
		if(selection == 'b' || selection == 'B') { // selection is to change a single byte
			unsigned char newbyte = 0;
			int bytepos = 0;
			printf("enter byte (0-%u) you wanna change: ", (bufferlen-1)); scanf("%u", &bytepos);
			getchar(); // consume newline to clear STDIN
			if(bytepos >= bufferlen) {
				printf("input > bufferlen\n");
				continue;
			} else {
				printf("(%u) enter new value in 2 digit hex format: ", bytepos); scanf("%02X", &newbyte);
				getchar(); // consume newline to clear STDIN
				printf("swapping values...");
				buffer[bytepos] = newbyte;
				printf("done!\n");
				while(1) {
					printf("change another byte or byterange? (y/n): "); scanf("%c", &selection);
					getchar(); // consume newline to clear STDIN
					if(selection == 'y' || selection == 'Y') {
						break;
					}
					else if(selection == 'n' || selection == 'N') {
						return;
					}
				}
			}
		}
		else if(selection == 'r' || selection == 'R') { // selection is to change a range of bytes
			int frombyte;
			int tobyte;
			int count;
			unsigned char newbytes[bufferlen];
			memset(newbytes, 0, sizeof(newbytes));
			printf("enter byterange (max. %u) you wanna change\n", (bufferlen-1));
			printf("from: "); scanf("%u", &frombyte);
			getchar(); // consume newline to clear STDIN
			printf("to: "); scanf("%u", &tobyte);
			getchar(); // consume newline to clear STDIN
			if(frombyte >= bufferlen || tobyte >= bufferlen) {
				printf("input > bufferlen");
				continue;
			}
			else if(tobyte <= frombyte) {
				printf("to <= from");
				continue;
			} else {
				printf("(%u-%u) enter new values in 2 digit hex format and without spaces:\n", frombyte, tobyte);
				for(count = 0; count <= (tobyte-frombyte); count++) {
					scanf("%02X", &newbytes[count]);
					getchar(); // consume newline to clear STDIN
				}
				printf("swapping values...");
				for(count = 0; count <= (tobyte-frombyte); count++) {
					buffer[frombyte+count] = newbytes[count];
				}
				printf("done!\n");
				while(1) {
					printf("change another byte or byterange? (y/n): "); scanf("%c", &selection);
					getchar(); // consume newline to clear STDIN
					if(selection == 'y' || selection == 'Y') {
						break;
					}
					else if(selection == 'n' || selection == 'N') {
						return;
					}
				}
			}
		}
		else if(selection == 's' || selection == 'S') {
			return;
		}
	}
}

void logpkg(char *filename, char *logpath, char *package, size_t package_len) { // logging helper to reduce code size
	// log the package content in form of a .bin binary file to the path in the argument
	// if the content is somehow encrypted you need to decrypt it yourself
	// path is argv[argv_pos+1]
	// construct full path with filename
	char full_path[strlen(logpath)+strlen(filename)+1]; // +1 for null terminator byte
	strcpy(full_path, logpath);
	if(logpath[strlen(logpath)-1] != '/') { // if last char of path is not / then append
		strcat(full_path, "/");
	}
	strcat(full_path, filename);
	FILE *logfile = fopen(full_path, "w"); // open (create) the logfile
	fwrite(package, 1, package_len, logfile); // write package to logfile
	if(fclose(logfile) != 0) { // close the log file (every connection got its own)
		exit(-1); // unknown fclose() error
	}
}

void get_local_ip_and_port(int sockfd, uint8_t ip_buffer[4], uint16_t port) {
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(local_addr);
	if(getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len) == -1) {
		exit(-1); // unknown getsockname() error
	}
	memcpy(ip_buffer, &local_addr.sin_addr.s_addr, 4);
	port = local_addr.sin_port;
}

void close_connection(int sockfd) { // helper to reduce code size
	if(shutdown(sockfd, SHUT_RDWR) < 0) {
		if(errno != ENOTCONN && errno != EPIPE && errno != ECONNRESET) {
			exit(-1); // unknown shutdown() error
		}
	}
	if(close(sockfd) < 0) {
		exit(-1); // unknown close() error
	}
}

typedef struct {
	EVP_PKEY *new_ppkey;
	X509 *new_cert;
} tls_cert_and_pkey;

int gen_tls_cert_and_pkey(tls_cert_and_pkey *new, unsigned char *CN, unsigned char *SAN) {
	FILE *root_cert_file = fopen("rootCA.crt", "r");
	if(root_cert_file == NULL) {
		printf("failed to open root cert file!\n");
		exit(1);
	}
	X509 *root_ca_cert = X509_new();
	if(PEM_read_X509(root_cert_file, &root_ca_cert, NULL, NULL) == NULL) {
		printf("failed to read root cert!\n");
		exit(-1);
	}
	FILE *root_privkey_file = fopen("rootCA.key", "r");
	if(root_privkey_file == NULL) {
		printf("failed to open root privkey file!\n");
		exit(1);
	}
	EVP_PKEY *root_ca_privkey = EVP_PKEY_new();
	if(PEM_read_PrivateKey(root_privkey_file, &root_ca_privkey, NULL, NULL) == NULL) {
		printf("failed to read root privkey!\n");
		exit(-1);
	}
	EVP_PKEY *root_ca_pubkey = X509_get_pubkey(root_ca_cert);
	if(root_ca_pubkey == NULL) {
		printf("failed to read root pubkey!\n");
		exit(-1);
	}
	if(fclose(root_privkey_file) != 0) {
		exit(-1);
	}
	if(fclose(root_cert_file) != 0) {
		exit(-1);
	}
	EVP_PKEY *new_ppkey = EVP_RSA_gen(2048);
	X509 *new_cert = X509_new();
	X509_NAME *new_crt_name = X509_NAME_new();
	X509_EXTENSION *extension_san = NULL;
	X509_set_version(new_cert, X509_VERSION_3);
	ASN1_INTEGER_set(X509_get_serialNumber(new_cert), 1);
	X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(new_cert), 31536000L);
	if(X509_NAME_add_entry_by_txt(new_crt_name, "CN", MBSTRING_ASC, CN, -1, -1, 0) != 1) {
		printf("failed to add COMMON NAME to subject name field!\n");
		exit(-1);
	}
	if(X509_set_subject_name(new_cert, new_crt_name) != 1) {
		printf("failed to set subject name field in cert!\n");
		exit(-1);
	}
	if(X509_set_issuer_name(new_cert, X509_get_subject_name(root_ca_cert)) != 1) {
		printf("failed to set issuer name field in cert!\n");
		exit(-1);
	}
	if((extension_san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, SAN)) == NULL) {
		printf("failed to create SAN!\n");
		exit(-1);
	}
	if(X509_add_ext(new_cert, extension_san, -1) != 1) {
		printf("failed to add SAN to cert!\n");
		exit(-1);
	}
	if(X509_set_pubkey(new_cert, new_ppkey) != 1) {
		printf("failed to add pubkey to cert!\n");
		exit(-1);
	}
	EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", "provider=default");
	if(X509_sign(new_cert, root_ca_privkey, md) == 0) {
		printf("failed to sign cert!\n");
		exit(-1);
	}
	EVP_MD_free(md);
	X509_EXTENSION_free(extension_san);
	X509_NAME_free(new_crt_name);
	EVP_PKEY_free(root_ca_privkey);
	X509_free(root_ca_cert);
	if(X509_verify(new_cert, root_ca_pubkey) == 1) {
		new->new_ppkey = new_ppkey;
		new->new_cert = new_cert;
		EVP_PKEY_free(root_ca_pubkey);
		return 0;
	} else {
		EVP_PKEY_free(root_ca_pubkey);
		return -1;
	}
}

typedef struct {
	struct timeval start_time;
	bool forwarding_enabled;
	bool hexdump_enabled;
	bool editing_enabled;
	bool logging_enabled;
	char *logpath;
	bool tls_decrypt_enabled;
	unsigned char *CN;
	unsigned char *SAN;
	int clientfd;
	struct sockaddr_in clientaddr;
	bool forward_to_proxy;
	uint32_t proxy_addr;
	uint16_t proxy_port;
} socks_handler_args;

void *handle_socks_request(void *args) {
	socks_handler_args *func_args = (socks_handler_args*) args;
	struct timeval start_time = func_args->start_time;
	struct timeval current_time;
	bool forwarding_enabled = func_args->forwarding_enabled;
	bool hexdump_enabled = func_args->hexdump_enabled;
	bool editing_enabled = func_args->editing_enabled;
	bool logging_enabled = func_args->logging_enabled;
	char *logpath = func_args->logpath;
	bool tls_decrypt_enabled = func_args->tls_decrypt_enabled;
	unsigned char *CN = func_args->CN;
	unsigned char *SAN = func_args->SAN;
	int clientfd = func_args->clientfd; // accepted incoming connection from listenfd
	int destfd; // destination where packages are forwarded to (if enabled)
	struct sockaddr_in clientaddr = func_args->clientaddr;
	char client_ip[INET_ADDRSTRLEN+1]; // ip address of the client +1 for null terminator
	memset(client_ip, 0, sizeof(client_ip)); // zero the buffer
	char dest_ip[INET_ADDRSTRLEN+1]; // ip address of the dest as string +1 for null terminator
	memset(dest_ip, 0, sizeof(dest_ip)); // zero the buffer
	uint32_t dest_addr = 0; // dest ipv4 in network byte order used by connect()
	uint16_t dest_port = 0; // dest port in network byte order used by connect()
	bool forward_to_proxy = func_args->forward_to_proxy;
	uint32_t proxy_addr = func_args->proxy_addr;
	uint16_t proxy_port = func_args->proxy_port;
	short timeout_return; // the value returned by timeout()
	SSL_CTX *tls_client_ctx; // TLS client context
	SSL_CTX *tls_dest_ctx; // TLS dest context
	SSL *tls_client; // TLS client object
	SSL *tls_dest; // TLS dest object
	int ssl_rtrn; // the value returned by the openssl SSL_* functions
	bool is_tls; // used to identify if a connected client is really using TLS
	unsigned char package[BUFFERSIZE]; // 64KiB buffer used for receiving packages into that buffer
	memset(package, 0, BUFFERSIZE); // zero the package buffer

	// SOCKS5 data formats to parse packages
	typedef struct {
		uint8_t version;
		uint8_t nmethods;
		uint8_t methods[]; // the size is the value of nmethods
	} SOCKS5_greeting;
	typedef struct {
		uint8_t version;
		uint8_t method;
	} SOCKS5_method_selection;
	SOCKS5_method_selection method_selection;
	memset(&method_selection, 0, sizeof(SOCKS5_method_selection));
	typedef struct {
		uint8_t version;
		uint8_t command;
		uint8_t reserved;
		uint8_t address_type;
		uint8_t dst_address[4]; // 4 octets for IPv4 address
		uint8_t dst_port[2]; // 2 octets for port number
	} SOCKS5_request_details_ip;
	SOCKS5_request_details_ip request_details_ip;
	memset(&request_details_ip, 0, sizeof(SOCKS5_request_details_ip));
	typedef struct {
		uint8_t version;
		uint8_t command;
		uint8_t reserved;
		uint8_t address_type;
		uint8_t domain_lenght;
		unsigned char domain_and_port[];
	} SOCKS5_request_details_domain;
	typedef struct {
		uint8_t version;
		uint8_t reply_code;
		uint8_t reserved;
		uint8_t address_type;
		uint8_t bnd_address[4]; // 4 octets for IPv4 address
		uint16_t bnd_port;
	} SOCKS5_request_reply;
	SOCKS5_request_reply request_reply;
	memset(&request_reply, 0, sizeof(SOCKS5_request_reply));

	uint8_t local_ip[4]; // the local address used to fill request reply bnd_address field
	uint16_t local_port; // the local port used to fill request reply bnd_port field
	ssize_t readbytes; // used to safe return value of read()

	uint32_t rand_value = arc4random();
	int length = snprintf(NULL, 0, "%u", rand_value);
	char random_string[length+1]; // random value used in logfilename to guarantee unique file names and in the STDOUT messages for this connection
	sprintf(random_string, "%u", rand_value);

	int logcount_requests = 0; // log counter used for unique filenames
	int logcount_replys = 0; // log counter used for unique filenames

	get_local_ip_and_port(clientfd, local_ip, local_port); // get the local ip and port for the SOCKS5_request_reply.bnd_addr and SOCKS5_request_reply.bnd_port
	char client_port[6]; // outbound port of the connected client used in log filenames
	sprintf(client_port, "%u", ntohs(clientaddr.sin_port));
	inet_ntop(AF_INET, &clientaddr.sin_addr, client_ip, sizeof(client_ip)); // convert client ip to string
	gettimeofday(&current_time, NULL); printf("[%.6f][%s] (ACK) CONNECTION REQUEST ACCEPTED from %s:%u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, client_ip, ntohs(clientaddr.sin_port));
	timeout_return = timeout(clientfd, POLLIN, 5000); // wait 5 seconds for the SOCKS5 greeting from client
	if(timeout_return & POLLIN) { // there is a package from a connected client
		gettimeofday(&current_time, NULL); printf("[%.6f][%s] starting SOCKS5 handshake for %s:%u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, client_ip, ntohs(clientaddr.sin_port));
		if(read(clientfd, package, BUFFERSIZE) < 0) {
			exit(-1); // unknown read() error
		}
		SOCKS5_greeting *package_greeting = malloc(sizeof(SOCKS5_greeting) + sizeof(uint8_t) * (*(package+1)));
		if(package_greeting == NULL) {
			exit(-1); // unknown malloc() error
		}
		memset(package_greeting, 0, (sizeof(SOCKS5_greeting)+sizeof(uint8_t)*(*(package+1))));
		package_greeting->version = *package;
		package_greeting->nmethods = *(package+1);
		for(int count = 0; count < package_greeting->nmethods; count++) {
			package_greeting->methods[count] = *(package+(2+count));
		}
		if(package_greeting->version == 0x05) { // check SOCKS version used by client
			int is_supported = 0;
			int count = 0;
			while(is_supported != 1 && count < package_greeting->nmethods) { // check if the NO AUTH method is supported by the client
				if(package_greeting->methods[count] == 0x00) {
					is_supported = 1;
				} else {
					count++;
				}
			}
			free(package_greeting);
			if(is_supported == 1) { // NO AUTH is supported (the only AUTH method supported by this proxy)
				method_selection.version = 0x05;
				method_selection.method = 0x00; // select NO AUTH method
				if(send(clientfd, &method_selection, sizeof(method_selection), MSG_NOSIGNAL) < 0) { // send method selection to client
					if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
						gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
						if(close(clientfd) < 0) {
							exit(-1);
						}
						return NULL;
					} else {
						exit(-1); // unknown write() error
					}
				}
				timeout_return = timeout(clientfd, POLLIN, 5000); // wait max 5 seconds for an answer from the client (the request details)
				if(timeout_return & POLLIN) { // request details came in from client
					memset(package, 0, BUFFERSIZE);
					if((readbytes = read(clientfd, package, BUFFERSIZE)) < 0) { // read the request details into buffer
						exit(-1); // unknown read() error
					}
					if(*(package+1) == 0x01) { // check if the command in the request details is CONNECT
						if(*(package+3) == 0x01) { // check if the address type in the request details is IPv4
							request_details_ip.version = *package;
							request_details_ip.command = *(package+1);
							request_details_ip.reserved = 0x00;
							request_details_ip.address_type = *(package+3);
							request_details_ip.dst_address[0] = *(package+4);
							request_details_ip.dst_address[1] = *(package+5);
							request_details_ip.dst_address[2] = *(package+6);
							request_details_ip.dst_address[3] = *(package+7);
							memcpy(&dest_addr, request_details_ip.dst_address, 4);
							//request_details.dst_port = (package[8] << 8) | package[9]; // copy port
							request_details_ip.dst_port[0] = *(package+8);
							request_details_ip.dst_port[1] = *(package+9);
							memcpy(&dest_port, request_details_ip.dst_port, 2);
							request_reply.version = 0x05;
							request_reply.reply_code = 0x00; // connection succeeded
							request_reply.reserved = 0x00;
							request_reply.address_type = 0x01;
							request_reply.bnd_address[0] = local_ip[0];
							request_reply.bnd_address[1] = local_ip[1];
							request_reply.bnd_address[2] = local_ip[2];
							request_reply.bnd_address[3] = local_ip[3];
							request_reply.bnd_port = local_port;
							if(send(clientfd, &request_reply, sizeof(request_reply), MSG_NOSIGNAL) < 0) { // send reply (0x00 for connection succeded)
								if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									if(close(clientfd) < 0) {
										exit(-1);
									}
									return NULL;
								} else {
									exit(-1); // unknown write() error
								}
							}
							timeout_return = timeout(clientfd, POLLIN, 5000); // wait 5 seconds for an answer (the actual package to echo and/or decrypt and/or forward)
							if(timeout_return & POLLIN) { // the request came in
								memset(package, 0, BUFFERSIZE); // zero out buffer to avoid garbage data
								if(tls_decrypt_enabled == true) { // check if decryption is enabled
									if(recv(clientfd, package, 3, MSG_PEEK) < 0) { // peek at the first 3 bytes to check if its indeed a TLS client hello
										exit(-1); // unknown recv() error (too lazy to write further errno handling lol)
									}
									if(package[0] == 0x16 && (((package[1] << 8) | package[2]) == 0x0303 || ((package[1] << 8) | package[2]) == 0x0301)) { // is a TLS client hello
										is_tls = true;
										// TLS man-in-the-middle decryption
										tls_client_ctx = SSL_CTX_new(TLS_server_method());
										uint64_t opts = SSL_OP_IGNORE_UNEXPECTED_EOF | SSL_OP_NO_RENEGOTIATION;
										SSL_CTX_set_options(tls_client_ctx, opts);
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] GENERATING TLS CERT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										tls_cert_and_pkey cert_and_pkey;
										if(gen_tls_cert_and_pkey(&cert_and_pkey, CN, SAN) < 0) {
											printf("failed! signature could not be verified, possible rootCA.key/rootCA.crt mismatch???\n");
											SSL_CTX_free(tls_client_ctx);
											close_connection(clientfd);
											exit(-1);
										} else {
											printf("done!\n");
										}
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] LOADING TLS CERT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										if(SSL_CTX_use_certificate(tls_client_ctx, cert_and_pkey.new_cert) <= 0) { // load TLS server cert
											printf("failed!\n");
											SSL_CTX_free(tls_client_ctx);
											close_connection(clientfd);
											exit(-1);
										} else {
											printf("done!\n");
										}
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] LOADING TLS PRIVATE KEY... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										if(SSL_CTX_use_PrivateKey(tls_client_ctx, cert_and_pkey.new_ppkey) <= 0) { // load TLS server private key
											printf("failed! possible key/cert mismatch???\n");
											SSL_CTX_free(tls_client_ctx);
											close_connection(clientfd);
											exit(-1);
										} else {
											printf("done!\n");
										}
										SSL_CTX_set_verify(tls_client_ctx, SSL_VERIFY_NONE, NULL);
										tls_client = SSL_new(tls_client_ctx);
										SSL_set_fd(tls_client, clientfd);
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] ATTEMPTING TLS HANDSHAKE WITH CLIENT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										while((ssl_rtrn = SSL_accept(tls_client)) != 1) { // Attempt an TLS handshake with the client
											switch(SSL_get_error(tls_client, ssl_rtrn)) {
												case SSL_ERROR_WANT_READ: // handshake not complete yet
													usleep(1000);
													continue;
												case SSL_ERROR_WANT_WRITE: // handshake not complete yet
													usleep(1000);
													continue;
												default:
													printf("failed!\n");
													SSL_free(tls_client);
													SSL_CTX_free(tls_client_ctx);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
											}
										}
										// TLS handshake complete
										printf("done!\n");
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] waiting for the actual request to decrypt...", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										timeout_return = timeout(clientfd, POLLIN, 5000);
										if(timeout_return & POLLIN) {
											memset(package, 0, BUFFERSIZE); // zero out buffer to avoid garbage data
											while((ssl_rtrn = SSL_read_ex(tls_client, package, BUFFERSIZE, &readbytes)) != 1) {
												switch(SSL_get_error(tls_client, ssl_rtrn)) {
													case SSL_ERROR_WANT_READ:
														usleep(1000);
														continue;
													case SSL_ERROR_WANT_WRITE:
														usleep(1000);
														continue;
													case SSL_ERROR_ZERO_RETURN:
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
														if(close(clientfd) < 0) {
															exit(-1);
														}
														return NULL;
													default:
														printf("error!\n");
														exit(-1); // unknown SSL_read() error
												}
											}
											printf("done!\n");
										}
										else if(timeout_return == 0) {
											gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] no request to decrypt : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											SSL_free(tls_client);
											SSL_CTX_free(tls_client_ctx);
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											close_connection(clientfd);
											return NULL;
										}
										else if(timeout_return < 0) {
											exit(-1); // unknown poll() error
										}
									} else { // is not a TLS client hello, just read()
										is_tls = false;
										memset(package, 0, BUFFERSIZE); // zero out buffer to avoid garbage data
										if((readbytes = read(clientfd, package, BUFFERSIZE)) < 0) {
											exit(-1); // unknown read() error (too lazy to write further errno handling lol)
										}
									}
								} else { // no TLS decryption enabled just read()
									if((readbytes = read(clientfd, package, BUFFERSIZE)) < 0) {
										exit(-1); // unknown read() error (too lazy to write further errno handling lol)
									}
								}
								if(hexdump_enabled == true) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									hexdump(package, readbytes); // hexdump the read data
								}
								if(editing_enabled == true) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] entering hexedit mode...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									//editbuffer(package, readbytes);
									int newlen = editbuffer_new(package, readbytes, random_string);
									if (newlen > 0 && newlen != readbytes) { readbytes = newlen; } // update package len
									if(hexdump_enabled == true) {
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] EDITED REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										hexdump(package, readbytes);
									}
								}
								if(logging_enabled == true) {
									// log the package content in form of a .bin binary file to the path in the argument
									// if the content is somehow encrypted you need to decrypt it yourself
									// path is argv[argv_pos+1]
									char logname[] = "-request-";
									char ending[] = ".bin";
									char logcount[10]; // size is 10 because of max int value (10 digits)
									sprintf(logcount, "%u", logcount_requests);
									// construct file name
									char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(logcount)+strlen(ending)+4]; // +4 because of the _ and - added below, and the null byte for strings
									memset(filename, 0, sizeof(filename));
									strcpy(filename, client_ip);
									for(int count = 0; count < sizeof(filename); count++) { // replace dots with _ in the filename (because ipv4 of client is used as filename)
										if(filename[count] == '.') {
											filename[count] = '_';
										}
									}
									strcat(filename, "_");
									strcat(filename, client_port);
									strcat(filename, logname);
									strcat(filename, random_string);
									strcat(filename, "-");
									strcat(filename, logcount);
									strcat(filename, ending);
									logpkg(filename, logpath, package, readbytes);
									logcount_requests++;
								}
								if(forwarding_enabled == true) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] forwarding to :: %u.%u.%u.%u:%u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, request_details_ip.dst_address[0], request_details_ip.dst_address[1], request_details_ip.dst_address[2], request_details_ip.dst_address[3], ntohs(dest_port));
									if(forward_to_proxy == true) {
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] CONNECTING TO SOCKS5 PROXY... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										destfd = open_socket((bool) false, proxy_addr, proxy_port); // create destination socket and connect it to the proxy
									} else {
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] CONNECTING TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										destfd = open_socket((bool) false, dest_addr, dest_port); // create destination socket and connect it to destination
									}
									timeout_return = timeout(destfd, POLLOUT, 5000);
									if(timeout_return & POLLOUT) { // wait for the destfd socket to become writeable (connected)
										printf("done!\n");
										if(forward_to_proxy == true) {
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] ATTEMPTING SOCKS5 HANDSHAKE WITH PROXY... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											SOCKS5_greeting *proxy_greeting = malloc(sizeof(SOCKS5_greeting) + sizeof(uint8_t));
											if(proxy_greeting == NULL) {
												exit(-1); // unknown malloc() error
											}
											proxy_greeting->version = 0x05;
											proxy_greeting->nmethods = 1;
											proxy_greeting->methods[0] = 0x00;
											if(send(destfd, proxy_greeting, (sizeof(SOCKS5_greeting) + sizeof(uint8_t)), MSG_NOSIGNAL) < 0) { // send socks5 client hello to proxy
												if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													free(proxy_greeting);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													if(close(destfd) < 0) {
														exit(-1);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												} else {
													printf("error!\n");
													exit(-1); // unknown send() error
												}
											}
											free(proxy_greeting);
											timeout_return = timeout(destfd, POLLIN, 5000); // wait for socks5 method selection from the proxy
											if(timeout_return & POLLIN) { // answer came in
												unsigned char handshake_buffer[1024];
												memset(handshake_buffer, 0, sizeof(handshake_buffer));
												int read_rtrn = read(destfd, handshake_buffer, sizeof(handshake_buffer)); // try to read() a answer from proxy
												if(read_rtrn == 0) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													if(close(destfd) < 0) {
														exit(-1); // unknown close() error
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												else if(read_rtrn < 0) {
													exit(-1); // unknown read() error
												}
												if(*handshake_buffer != 0x05) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : wrong version\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												else if(*(handshake_buffer+1) != 0x00) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : NO AUTH method not supported\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												if(send(destfd, &request_details_ip, sizeof(request_details_ip), MSG_NOSIGNAL) < 0) { // send socks5 request details to proxy
													if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														if(tls_decrypt_enabled == true && is_tls == true) {
															SSL_free(tls_client);
															SSL_CTX_free(tls_client_ctx);
														}
														if(close(destfd) < 0) {
															exit(-1);
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													} else {
														printf("error!\n");
														exit(-1); // unknown send() error
													}
												}
												timeout_return = timeout(destfd, POLLIN, 5000); // wait for socks5 request reply from the proxy
												if(timeout_return & POLLIN) { // answer came in
													memset(handshake_buffer, 0, sizeof(handshake_buffer));
													read_rtrn = read(destfd, handshake_buffer, sizeof(handshake_buffer)); // try to read() a answer from proxy
													if(read_rtrn == 0) {
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														if(tls_decrypt_enabled == true && is_tls == true) {
															SSL_free(tls_client);
															SSL_CTX_free(tls_client_ctx);
														}
														if(close(destfd) < 0) {
															exit(-1); // unknown close() error
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													}
													else if(read_rtrn < 0) {
														exit(-1); // unknown read() error
													}
													if(*(handshake_buffer+1) != 0x00) {
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : proxy denied request\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														if(tls_decrypt_enabled == true && is_tls == true) {
															SSL_free(tls_client);
															SSL_CTX_free(tls_client_ctx);
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(destfd);
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													}
													printf("done!\n");
												}
												else if(timeout_return == 0) { // timeout
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
											}
											else if(timeout_return == 0) { // timeout
												gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												if(tls_decrypt_enabled == true && is_tls == true) {
													SSL_free(tls_client);
													SSL_CTX_free(tls_client_ctx);
												}
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(destfd);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(clientfd);
												return NULL;
											}
										}
										if(tls_decrypt_enabled == true && is_tls == true) {
											// TLS man-in-the-middle forwarding
											tls_dest_ctx = SSL_CTX_new(TLS_client_method());
											SSL_CTX_set_verify(tls_dest_ctx, SSL_VERIFY_NONE, NULL);
											tls_dest = SSL_new(tls_dest_ctx);
											SSL_set_fd(tls_dest, destfd);
											char tls_sni[NI_MAXHOST];
											snprintf(dest_ip, sizeof(dest_ip), "%u.%u.%u.%u", request_details_ip.dst_address[0], request_details_ip.dst_address[1], request_details_ip.dst_address[2], request_details_ip.dst_address[3]); // Convert raw byte array to dotted-decimal string (IPv4)
											struct addrinfo dst_hints, *dst_info;
											memset(&dst_hints, 0, sizeof(dst_hints));
											dst_hints.ai_family = AF_INET;
											dst_hints.ai_socktype = SOCK_STREAM;
											dst_hints.ai_flags = AI_CANONNAME;
											int getaddrinfo_rtrn = getaddrinfo(dest_ip, NULL, &dst_hints, &dst_info);
											if(getaddrinfo_rtrn != 0) {
												if(getaddrinfo_rtrn == EAI_NONAME) { // no hostname found, just leave SNI empty
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] the IP %u.%u.%u.%u could not be resolved : TLS SNI stays empty\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, request_details_ip.dst_address[0], request_details_ip.dst_address[1], request_details_ip.dst_address[2], request_details_ip.dst_address[3]);
												} else {
													exit(-1); // unknown getaddrinfo() error
												}
											} else { // hostname was found
												while(dst_info != NULL) { // loop through dst_info until a hostname for a IPv4 address is found
													if(dst_info->ai_family == AF_INET && dst_info->ai_canonname != NULL) {
														snprintf(tls_sni, sizeof(tls_sni), "%s", dst_info->ai_canonname);
														SSL_set_tlsext_host_name(tls_dest, tls_sni); // set the TLS SNI client hello extension
														break;
													} else {
														dst_info = dst_info->ai_next;
													}
												}
												if(dst_info == NULL || dst_info->ai_canonname == NULL) {
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] the IP %u.%u.%u.%u could not be resolved : TLS SNI stays empty\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, request_details_ip.dst_address[0], request_details_ip.dst_address[1], request_details_ip.dst_address[2], request_details_ip.dst_address[3]);
												}
											}
											freeaddrinfo(dst_info);
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] ATTEMPTING TLS HANDSHAKE WITH DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											while((ssl_rtrn = SSL_connect(tls_dest)) != 1) { // Attempt an TLS handshake with the dest
												switch(SSL_get_error(tls_dest, ssl_rtrn)) {
													case SSL_ERROR_WANT_READ: // handshake not complete yet
														usleep(1000);
														continue;
													case SSL_ERROR_WANT_WRITE: // handshake not complete yet
														usleep(1000);
														continue;
													default:
														printf("failed!\n");
														SSL_free(tls_dest);
														SSL_CTX_free(tls_dest_ctx);
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(destfd);
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
												}
											}
											// TLS handshake complete
											printf("done!\n");
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											while((ssl_rtrn = SSL_write(tls_dest, package, readbytes)) <= 0) {
												switch(SSL_get_error(tls_dest, ssl_rtrn)) {
													case SSL_ERROR_WANT_READ:
														usleep(1000);
														continue;
													case SSL_ERROR_WANT_WRITE:
														usleep(1000);
														continue;
													case SSL_ERROR_ZERO_RETURN:
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														SSL_free(tls_dest);
														SSL_CTX_free(tls_dest_ctx);
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
														if(close(destfd) < 0) {
															exit(-1); // unknown close() error
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													default:
														printf("error!\n");
														exit(-1); // unknown SSL_write() error
												}
											}
											printf("done!\n");
										} else {
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											if(send(destfd, package, readbytes, MSG_NOSIGNAL) < 0) { // forward the request
												if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(close(destfd) < 0) {
														exit(-1);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												} else {
													printf("error!\n");
													exit(-1); // unknown write() error
												}
											} else {
												printf("done!\n");
											}
										}
										struct pollfd fds[2]; // poll() struct array
										fds[0].fd = destfd;
										fds[0].events = POLLIN | POLLRDHUP;
										fds[1].fd = clientfd;
										fds[1].events = POLLIN | POLLRDHUP;
										while(1) {
											timeout_return = poll(fds, 2, 5000);
											if(timeout_return > 0) {
												if(fds[0].revents & POLLIN) {
													memset(package, 0, BUFFERSIZE); // zero out package buffer to avoid garbage data
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_read_ex(tls_dest, package, BUFFERSIZE, &readbytes)) != 1) {
															switch(SSL_get_error(tls_dest, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(destfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(clientfd);
																	return NULL;	
																default:
																	exit(-1); // unknown SSL_read_ex() error
															}
														}
													} else {
														readbytes = read(destfd, package, BUFFERSIZE); // try to read() a answer from dest
														if(readbytes == 0) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															if(close(destfd) < 0) {
																exit(-1); // unknown close() error
															}
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(clientfd);
															return NULL;
														}
														else if(readbytes < 0) {
															exit(-1); // unknown read() error
														}
													}
													if(hexdump_enabled == true) {
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] REPLY PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														hexdump(package, readbytes); // hexdump the reply
													}
													if(logging_enabled == true) { // log the reply if logging enabled
														// log the package content in form of a .bin binary file to the path in the argument
														// if the content is somehow encrypted you need to decrypt it yourself
														// path is argv[argv_pos+1]
														char logname[] = "-reply-";
														char ending[] = ".bin";
														char logcount[10]; // size is 10 because of max int value (10 digits)
														sprintf(logcount, "%u", logcount_replys);
														// construct file name
														char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(logcount)+strlen(ending)+4]; // +4 because of the _ and - added below, and the null byte for strings
														memset(filename, 0, sizeof(filename));
														strcpy(filename, client_ip);
														for(int count = 0; count < sizeof(filename); count++) { // replace dots with _ in the filename (because ipv4 of client is used as filename)
															if(filename[count] == '.') {
																filename[count] = '_';
															}
														}
														strcat(filename, "_");
														strcat(filename, client_port);
														strcat(filename, logname);
														strcat(filename, random_string);
														strcat(filename, "-");
														strcat(filename, logcount);
														strcat(filename, ending);
														logpkg(filename, logpath, package, readbytes);
														logcount_replys++;
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REPLY TO CLIENT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_write(tls_client, package, readbytes)) <= 0) {
															switch(SSL_get_error(tls_client, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(clientfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(destfd);
																	return NULL;
																default:
																	printf("error!\n");
																	exit(-1); // unknown SSL_write() error
															}
														}
														printf("done!\n");
													} else {
														if(send(clientfd, package, readbytes, MSG_NOSIGNAL) < 0) { // forward the answer to the client
															if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
																gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																if(close(clientfd) < 0) {
																	exit(-1);
																}
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(destfd);
																return NULL;
															} else {
																printf("error!\n");
																exit(-1); // unknown write() error
															}
														} else {
															printf("done!\n");
														}
													}
												}
												else if(fds[0].revents & POLLHUP || fds[0].revents & POLLRDHUP) {
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(close(destfd) < 0) {
														exit(-1); // unknown close() error
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												if(fds[1].revents & POLLIN) {
													memset(package, 0, BUFFERSIZE); // zero out package buffer to avoid garbage data
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_read_ex(tls_client, package, BUFFERSIZE, &readbytes)) != 1) {
															switch(SSL_get_error(tls_client, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(clientfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(destfd);
																	return NULL;
																default:
																	exit(-1); // unknown SSL_read_ex() error
															}
														}
													} else {
														readbytes = read(clientfd, package, BUFFERSIZE); // try to read() a new request from client
														if(readbytes == 0) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															if(close(clientfd) < 0) {
																exit(-1); // unknown close() error
															}
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(destfd);
															return NULL;
														}
														else if(readbytes < 0) {
															exit(-1); // unknown read() error
														}
													}
													if(hexdump_enabled == true) {
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														hexdump(package, readbytes); // hexdump the read data
													}
													if(editing_enabled == true) {
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] entering hexedit mode...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														editbuffer(package, readbytes);
														if(hexdump_enabled == true) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] EDITED REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															hexdump(package, readbytes);
														}
													}
													if(logging_enabled == true) {
														// log the package content in form of a .bin binary file to the path in the argument
														// if the content is somehow encrypted you need to decrypt it yourself
														// path is argv[argv_pos+1]
														char logname[] = "-request-";
														char ending[] = ".bin";
														char logcount[10]; // size is 10 because of max int value (10 digits)
														sprintf(logcount, "%u", logcount_requests);
														// construct file name
														char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(logcount)+strlen(ending)+4]; // +4 because of the _ and - added below, and the null byte for strings
														memset(filename, 0, sizeof(filename));
														strcpy(filename, client_ip);
														for(int count = 0; count < sizeof(filename); count++) { // replace dots with _ in the filename (because ipv4 of client is used as filename)
															if(filename[count] == '.') {
																filename[count] = '_';
															}
														}
														strcat(filename, "_");
														strcat(filename, client_port);
														strcat(filename, logname);
														strcat(filename, random_string);
														strcat(filename, "-");
														strcat(filename, logcount);
														strcat(filename, ending);
														logpkg(filename, logpath, package, readbytes);
														logcount_requests++;
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_write(tls_dest, package, readbytes)) <= 0) {
															switch(SSL_get_error(tls_dest, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(destfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(clientfd);
																	return NULL;
																default:
																	printf("error!\n");
																	exit(-1); // unknown SSL_write() error
															}
														}
														printf("done!\n");
													} else {
														if(send(destfd, package, readbytes, MSG_NOSIGNAL) < 0) { // forward the request
															if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
																gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																if(close(destfd) < 0) {
																	exit(-1);
																}
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(clientfd);
																return NULL;
															} else {
																printf("error!\n");
																exit(-1); // unknown write() error
															}
														} else {
															printf("done!\n");
														}
													}
												}
												else if(fds[1].revents & POLLHUP || fds[1].revents & POLLRDHUP) {
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(close(clientfd) < 0) {
														exit(-1); // unknown close() error
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													return NULL;
												}
											}
											else if(timeout_return == 0) {
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] no data to forward to or from client : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(destfd);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(clientfd);
												return NULL;
											}
											else if(timeout_return < 0) {
												exit(-1); // unknown poll() error
											}
										}
									}
									else if(timeout_return == 0) {
										if(forward_to_proxy == true) {
											gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] connecting to proxy failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										} else {
											gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] connecting to package destination failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										}
										if(close(destfd) < 0) {
											exit(-1); // unknown close() error
										}
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										close_connection(clientfd);
										return NULL;
									}
								}
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								close_connection(clientfd);
								return NULL;
							}
							else if(timeout_return == 0) { // request didn't came in after 5 secs
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] no further input from %s:%u : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, client_ip, ntohs(clientaddr.sin_port));
								gettimeofday(&current_time, NULL); printf("[%.6f] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
								close_connection(clientfd);
								return NULL;
							}
						}
						else if(*(package+3) == 0x03) { // if the address type requested by client is DOMAIN
							SOCKS5_request_details_domain *request_details_domain = malloc(sizeof(SOCKS5_request_details_domain)+*(package+4)+2); // +2 for port number at the end
							memset(request_details_domain, 0, (sizeof(SOCKS5_request_details_domain)+*(package+4)+2));
							request_details_domain->version = *package;
							request_details_domain->command = *(package+1);
							request_details_domain->reserved = 0x00;
							request_details_domain->address_type = *(package+3);
							request_details_domain->domain_lenght = *(package+4);
							for(int count = 0; count < request_details_domain->domain_lenght; count++) {
								request_details_domain->domain_and_port[count] = *(package+(5+count));
							}
							char dst_domain[request_details_domain->domain_lenght+1]; // null terminated version for getaddrinfo()
							memset(dst_domain, 0, sizeof(dst_domain));
							for(int count = 0; count < request_details_domain->domain_lenght; count++) { // safe the DOMAIN from request to resolv later if --forward is set
								dst_domain[count] = *(package+(5+count));
							}
							dst_domain[request_details_domain->domain_lenght] = '\0'; // set the null terminator for the getaddrinfo() to resolv the domain
							request_details_domain->domain_and_port[request_details_domain->domain_lenght] = *(package+(5+request_details_domain->domain_lenght));
							request_details_domain->domain_and_port[request_details_domain->domain_lenght+1] = *(package+(6+request_details_domain->domain_lenght));
							uint8_t port_tmp[2];
							port_tmp[0] = (uint8_t)request_details_domain->domain_and_port[request_details_domain->domain_lenght];
							port_tmp[1] = (uint8_t)request_details_domain->domain_and_port[request_details_domain->domain_lenght+1];
							memcpy(&dest_port, port_tmp, 2);
							request_reply.version = 0x05;
							request_reply.reply_code = 0x00; // connection succeeded
							request_reply.reserved = 0x00;
							request_reply.address_type = 0x01;
							request_reply.bnd_address[0] = local_ip[0];
							request_reply.bnd_address[1] = local_ip[1];
							request_reply.bnd_address[2] = local_ip[2];
							request_reply.bnd_address[3] = local_ip[3];
							request_reply.bnd_port = local_port;
							if(send(clientfd, &request_reply, sizeof(request_reply), MSG_NOSIGNAL) < 0) { // send reply (0x00 for connection succeded)
								if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									//free(request_details_domain);
									if(close(clientfd) < 0) {
										exit(-1);
									}
									return NULL;
								} else {
									exit(-1); // unknown write() error
								}
							}
							timeout_return = timeout(clientfd, POLLIN, 5000); // wait 5 seconds for an answer (the actual package to echo and/or decrypt and/or forward)
							if(timeout_return & POLLIN) { // the answer came in
								memset(package, 0, BUFFERSIZE);
								if(tls_decrypt_enabled == true) { // check if decryption is enabled
									if(recv(clientfd, package, 3, MSG_PEEK) < 0) { // peek at the first 3 bytes to check if its indeed a TLS client hello
										exit(-1); // unknown recv() error (too lazy to write further errno handling lol)
									}
									if(package[0] == 0x16 && (((package[1] << 8) | package[2]) == 0x0303 || ((package[1] << 8) | package[2]) == 0x0301)) { // is a TLS client hello
										is_tls = true;
										// TLS man-in-the-middle decryption
										tls_client_ctx = SSL_CTX_new(TLS_server_method());
										uint64_t opts = SSL_OP_IGNORE_UNEXPECTED_EOF | SSL_OP_NO_RENEGOTIATION;
										SSL_CTX_set_options(tls_client_ctx, opts);
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] GENERATING TLS CERT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										tls_cert_and_pkey cert_and_pkey;
										if(gen_tls_cert_and_pkey(&cert_and_pkey, CN, SAN) < 0) {
											printf("failed! signature could not be verified, possible rootCA.key/rootCA.crt mismatch???\n");
											SSL_CTX_free(tls_client_ctx);
											close_connection(clientfd);
											exit(-1);
										} else {
											printf("done!\n");
										}
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] LOADING TLS CERT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										if(SSL_CTX_use_certificate(tls_client_ctx, cert_and_pkey.new_cert) <= 0) { // load TLS server cert
											printf("failed!\n");
											SSL_CTX_free(tls_client_ctx);
											close_connection(clientfd);
											exit(-1);
										} else {
											printf("done!\n");
										}
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] LOADING TLS PRIVATE KEY... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										if(SSL_CTX_use_PrivateKey(tls_client_ctx, cert_and_pkey.new_ppkey) <= 0) { // load TLS server private key
											printf("failed! possible key/cert mismatch???\n");
											SSL_CTX_free(tls_client_ctx);
											close_connection(clientfd);
											exit(-1);
										} else {
											printf("done!\n");
										}
										SSL_CTX_set_verify(tls_client_ctx, SSL_VERIFY_NONE, NULL);
										tls_client = SSL_new(tls_client_ctx);
										SSL_set_fd(tls_client, clientfd);
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] ATTEMPTING TLS HANDSHAKE WITH CLIENT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										while((ssl_rtrn = SSL_accept(tls_client)) != 1) { // Attempt an TLS handshake with the client
											switch(SSL_get_error(tls_client, ssl_rtrn)) {
												case SSL_ERROR_WANT_READ: // handshake not complete yet
													usleep(1000);
													continue;
												case SSL_ERROR_WANT_WRITE: // handshake not complete yet
													usleep(1000);
													continue;
												default:
													printf("failed!\n");
													//free(request_details_domain);
													SSL_free(tls_client);
													SSL_CTX_free(tls_client_ctx);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
											}
										}
										// TLS handshake complete
										printf("done!\n");
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] waiting for the actual request to decrypt...", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										timeout_return = timeout(clientfd, POLLIN, 5000);
										if(timeout_return & POLLIN) {
											memset(package, 0, BUFFERSIZE); // zero out buffer to avoid garbage data
											while((ssl_rtrn = SSL_read_ex(tls_client, package, BUFFERSIZE, &readbytes)) != 1) {
												switch(SSL_get_error(tls_client, ssl_rtrn)) {
													case SSL_ERROR_WANT_READ:
														usleep(1000);
														continue;
													case SSL_ERROR_WANT_WRITE:
														usleep(1000);
														continue;
													case SSL_ERROR_ZERO_RETURN:
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														//free(request_details_domain);
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
														if(close(clientfd) < 0) {
															exit(-1);
														}
														return NULL;
													default:
														printf("error!\n");
														exit(-1); // unknown SSL_read() error
												}
											}
											printf("done!\n");
										}
										else if(timeout_return == 0) {
											gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] no request to decrypt : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											//free(request_details_domain);
											SSL_free(tls_client);
											SSL_CTX_free(tls_client_ctx);
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											close_connection(clientfd);
											return NULL;
										}
										else if(timeout_return < 0) {
											exit(-1); // unknown poll() error
										}
									} else { // is not a TLS client hello, just read()
										is_tls = false;
										memset(package, 0, BUFFERSIZE); // zero out buffer to avoid garbage data
										if((readbytes = read(clientfd, package, BUFFERSIZE)) < 0) {
											exit(-1); // unknown read() error (too lazy to write further errno handling lol)
										}
									}
								} else { // no TLS decryption enabled just read()
									if((readbytes = read(clientfd, package, BUFFERSIZE)) < 0) {
										exit(-1); // unknown read() error (too lazy to write further errno handling lol)
									}
								}
								if(hexdump_enabled == true) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									hexdump(package, readbytes); // hexdump the read data
								}
								if(editing_enabled == true) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] entering hexedit mode...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									//editbuffer(package, readbytes);
									int newlen = editbuffer_new(package, readbytes, random_string);
									if (newlen > 0 && newlen != readbytes) { readbytes = newlen; } // update package len
									if(hexdump_enabled == true) {
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] EDITED REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										hexdump(package, readbytes);
									}
								}
								if(logging_enabled == true) {
									// log the package content in form of a .bin binary file to the path in the argument
									// if the content is somehow encrypted you need to decrypt it yourself
									// path is argv[argv_pos+1]
									char logname[] = "-request-";
									char ending[] = ".bin";
									char logcount[10]; // size is 10 because of max int value (10 digits)
									sprintf(logcount, "%u", logcount_requests);
									// construct file name
									char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(logcount)+strlen(ending)+4]; // +4 because of the _ and - added below, and the null byte for strings
									memset(filename, 0, sizeof(filename));
									strcpy(filename, client_ip);
									for(int count = 0; count < sizeof(filename); count++) { // replace dots with _ in the filename (because ipv4 of client is used as filename)
										if(filename[count] == '.') {
											filename[count] = '_';
										}
									}
									strcat(filename, "_");
									strcat(filename, client_port);
									strcat(filename, logname);
									strcat(filename, random_string);
									strcat(filename, "-");
									strcat(filename, logcount);
									strcat(filename, ending);
									logpkg(filename, logpath, package, readbytes);
									logcount_requests++;
								}
								if(forwarding_enabled == true) {
									if(forward_to_proxy == true) {
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] CONNECTING TO SOCKS5 PROXY... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										destfd = open_socket((bool) false, proxy_addr, proxy_port); // create destination socket and connect it to the proxy
									} else {
										struct addrinfo *dst_info;
										int getaddrinfo_rtrn = getaddrinfo(request_details_domain->domain_and_port, NULL, NULL, &dst_info);
										if(getaddrinfo_rtrn != 0) {
											if(getaddrinfo_rtrn == EAI_NONAME) {
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] the DOMAIN ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												for(int count = 0; count < request_details_domain->domain_lenght; count++) {
													printf("%c", dst_domain[count]);
												}
												printf(" could not be resolved : ignoring\n");
												if(tls_decrypt_enabled == true && is_tls == true) {
													SSL_free(tls_client);
													SSL_CTX_free(tls_client_ctx);
												}
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(clientfd);
												freeaddrinfo(dst_info);
												//free(request_details_domain);
												return NULL;
											} else {
												exit(-1); // unknown getaddrinfo() error
											}
										} else {
											while(dst_info != NULL) { // loop through dst_info until a IPv4 address is found
												if(dst_info->ai_family == AF_INET && dst_info->ai_addr != NULL) {
													break;
												} else {
													dst_info = dst_info->ai_next;
												}
											}
											if(dst_info != NULL && dst_info->ai_family == AF_INET && dst_info->ai_addr != NULL) { // IPv4 for DOMAIN was found
												struct sockaddr_in *dst_addr = (struct sockaddr_in*) dst_info->ai_addr;
												inet_ntop(AF_INET, &dst_addr->sin_addr, dest_ip, sizeof(dest_ip));
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] forwarding to :: ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												for(int count = 0; count < request_details_domain->domain_lenght; count++) {
													printf("%c", dst_domain[count]);
												}
												printf(":%u\n", ntohs(dest_port));
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] resolved dest ip :: %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, dest_ip);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CONNECTING TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												destfd = open_socket((bool) false, dst_addr->sin_addr.s_addr, dest_port); // create destination socket and connect it to destination
											} else {
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] no IPv4 address could be found for the DOMAIN : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												if(tls_decrypt_enabled == true && is_tls == true) {
													SSL_free(tls_client);
													SSL_CTX_free(tls_client_ctx);
												}
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(clientfd);
												freeaddrinfo(dst_info);
												//free(request_details_domain);
												return NULL;
											}
										}
										freeaddrinfo(dst_info);
									}
									timeout_return = timeout(destfd, POLLOUT, 5000);
									if(timeout_return & POLLOUT) { // wait for the destfd socket to become writeable (connected)
										printf("done!\n");
										if(forward_to_proxy == true) {
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] ATTEMPTING SOCKS5 HANDSHAKE WITH PROXY... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											SOCKS5_greeting *proxy_greeting = malloc(sizeof(SOCKS5_greeting) + sizeof(uint8_t));
											if(proxy_greeting == NULL) {
												exit(-1); // unknown malloc() error
											}
											proxy_greeting->version = 0x05;
											proxy_greeting->nmethods = 1;
											proxy_greeting->methods[0] = 0x00;
											if(send(destfd, proxy_greeting, (sizeof(SOCKS5_greeting) + sizeof(uint8_t)), MSG_NOSIGNAL) < 0) { // send socks5 client hello to proxy
												if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													free(proxy_greeting);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													if(close(destfd) < 0) {
														exit(-1);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												} else {
													printf("error!\n");
													exit(-1); // unknown send() error
												}
											}
											free(proxy_greeting);
											timeout_return = timeout(destfd, POLLIN, 5000); // wait for socks5 method selection from the proxy
											if(timeout_return & POLLIN) { // answer came in
												unsigned char handshake_buffer[1024];
												memset(handshake_buffer, 0, sizeof(handshake_buffer));
												int read_rtrn = read(destfd, handshake_buffer, sizeof(handshake_buffer)); // try to read() a answer from proxy
												if(read_rtrn == 0) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													if(close(destfd) < 0) {
														exit(-1); // unknown close() error
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												else if(read_rtrn < 0) {
													exit(-1); // unknown read() error
												}
												if(*handshake_buffer != 0x05) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : wrong version\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												else if(*(handshake_buffer+1) != 0x00) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : NO AUTH method not supported\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												if(send(destfd, request_details_domain, (sizeof(SOCKS5_request_details_domain)+request_details_domain->domain_lenght+2), MSG_NOSIGNAL) < 0) { // send socks5 request details to proxy
													if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														//free(request_details_domain);
														if(tls_decrypt_enabled == true && is_tls == true) {
															SSL_free(tls_client);
															SSL_CTX_free(tls_client_ctx);
														}
														if(close(destfd) < 0) {
															exit(-1);
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													} else {
														printf("error!\n");
														exit(-1); // unknown send() error
													}
												}
												//free(request_details_domain);
												timeout_return = timeout(destfd, POLLIN, 5000); // wait for socks5 request reply from the proxy
												if(timeout_return & POLLIN) { // answer came in
													memset(handshake_buffer, 0, sizeof(handshake_buffer));
													read_rtrn = read(destfd, handshake_buffer, sizeof(handshake_buffer)); // try to read() a answer from proxy
													if(read_rtrn == 0) {
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] proxy closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														//free(request_details_domain);
														if(tls_decrypt_enabled == true && is_tls == true) {
															SSL_free(tls_client);
															SSL_CTX_free(tls_client_ctx);
														}
														if(close(destfd) < 0) {
															exit(-1); // unknown close() error
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													}
													else if(read_rtrn < 0) {
														exit(-1); // unknown read() error
													}
													if(*(handshake_buffer+1) != 0x00) {
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : proxy denied request\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														//free(request_details_domain);
														if(tls_decrypt_enabled == true && is_tls == true) {
															SSL_free(tls_client);
															SSL_CTX_free(tls_client_ctx);
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(destfd);
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													}
													printf("done!\n");
												}
												else if(timeout_return == 0) { // timeout
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(tls_decrypt_enabled == true && is_tls == true) {
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
											}
											else if(timeout_return == 0) { // timeout
												gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] socks5 handshake failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												//free(request_details_domain);
												if(tls_decrypt_enabled == true && is_tls == true) {
													SSL_free(tls_client);
													SSL_CTX_free(tls_client_ctx);
												}
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(destfd);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(clientfd);
												return NULL;
											}
										}
										if(tls_decrypt_enabled == true && is_tls == true) {
											// TLS man-in-the-middle forwarding
											tls_dest_ctx = SSL_CTX_new(TLS_client_method());
											SSL_CTX_set_verify(tls_dest_ctx, SSL_VERIFY_NONE, NULL);
											tls_dest = SSL_new(tls_dest_ctx);
											SSL_set_fd(tls_dest, destfd);
											SSL_set_tlsext_host_name(tls_dest, dst_domain); // set the TLS SNI client hello extension
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] ATTEMPTING TLS HANDSHAKE WITH DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											while((ssl_rtrn = SSL_connect(tls_dest)) != 1) { // Attempt an TLS handshake with the dest
												switch(SSL_get_error(tls_dest, ssl_rtrn)) {
													case SSL_ERROR_WANT_READ: // handshake not complete yet
														usleep(1000);
														continue;
													case SSL_ERROR_WANT_WRITE: // handshake not complete yet
														usleep(1000);
														continue;
													default:
														printf("failed!\n");
														//free(request_details_domain);
														SSL_free(tls_dest);
														SSL_CTX_free(tls_dest_ctx);
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(destfd);
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
												}
											}
											// TLS handshake complete
											printf("done!\n");
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											while((ssl_rtrn = SSL_write(tls_dest, package, readbytes)) <= 0) {
												switch(SSL_get_error(tls_dest, ssl_rtrn)) {
													case SSL_ERROR_WANT_READ:
														usleep(1000);
														continue;
													case SSL_ERROR_WANT_WRITE:
														usleep(1000);
														continue;
													case SSL_ERROR_ZERO_RETURN:
														gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														//free(request_details_domain);
														SSL_free(tls_dest);
														SSL_CTX_free(tls_dest_ctx);
														SSL_free(tls_client);
														SSL_CTX_free(tls_client_ctx);
														if(close(destfd) < 0) {
															exit(-1); // unknown close() error
														}
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														close_connection(clientfd);
														return NULL;
													default:
														printf("error!\n");
														exit(-1); // unknown SSL_write() error
												}
											}
											printf("done!\n");
										} else {
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											if(send(destfd, package, readbytes, MSG_NOSIGNAL) < 0) { // forward the request
												if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
													gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(close(destfd) < 0) {
														exit(-1);
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												} else {
													printf("error!\n");
													exit(-1); // unknown write() error
												}
											} else {
												printf("done!\n");
											}
										}
										struct pollfd fds[2]; // poll() struct array
										fds[0].fd = destfd;
										fds[0].events = POLLIN | POLLRDHUP;
										fds[1].fd = clientfd;
										fds[1].events = POLLIN | POLLRDHUP;
										while(1) {
											timeout_return = poll(fds, 2, 5000);
											if(timeout_return > 0) {
												if(fds[0].revents & POLLIN) {
													memset(package, 0, BUFFERSIZE); // zero out package buffer to avoid garbage data
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_read_ex(tls_dest, package, BUFFERSIZE, &readbytes)) != 1) {
															switch(SSL_get_error(tls_dest, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	//free(request_details_domain);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(destfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(clientfd);
																	return NULL;	
																default:
																	exit(-1); // unknown SSL_read_ex() error
															}
														}
													} else {
														readbytes = read(destfd, package, BUFFERSIZE); // try to read() a answer from dest
														if(readbytes == 0) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															//free(request_details_domain);
															if(close(destfd) < 0) {
																exit(-1); // unknown close() error
															}
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(clientfd);
															return NULL;
														}
														else if(readbytes < 0) {
															exit(-1); // unknown read() error
														}
													}
													if(hexdump_enabled == true) {
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] REPLY PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														hexdump(package, readbytes); // hexdump the reply
													}
													if(logging_enabled == true) { // log the reply if logging enabled
														// log the package content in form of a .bin binary file to the path in the argument
														// if the content is somehow encrypted you need to decrypt it yourself
														// path is argv[argv_pos+1]
														char logname[] = "-reply-";
														char ending[] = ".bin";
														char logcount[10]; // size is 10 because of max int value (10 digits)
														sprintf(logcount, "%u", logcount_replys);
														// construct file name
														char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(logcount)+strlen(ending)+4]; // +4 because of the _ and - added below, and the null byte for strings
														memset(filename, 0, sizeof(filename));
														strcpy(filename, client_ip);
														for(int count = 0; count < sizeof(filename); count++) { // replace dots with _ in the filename (because ipv4 of client is used as filename)
															if(filename[count] == '.') {
																filename[count] = '_';
															}
														}
														strcat(filename, "_");
														strcat(filename, client_port);
														strcat(filename, logname);
														strcat(filename, random_string);
														strcat(filename, "-");
														strcat(filename, logcount);
														strcat(filename, ending);
														logpkg(filename, logpath, package, readbytes);
														logcount_replys++;
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REPLY TO CLIENT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_write(tls_client, package, readbytes)) <= 0) {
															switch(SSL_get_error(tls_client, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	//free(request_details_domain);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(clientfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(destfd);
																	return NULL;
																default:
																	printf("error!\n");
																	exit(-1); // unknown SSL_write() error
															}
														}
														printf("done!\n");
													} else {
														if(send(clientfd, package, readbytes, MSG_NOSIGNAL) < 0) { // forward the answer to the client
															if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
																gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																//free(request_details_domain);
																if(close(clientfd) < 0) {
																	exit(-1);
																}
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(destfd);
																return NULL;
															} else {
																printf("error!\n");
																exit(-1); // unknown write() error
															}
														} else {
															printf("done!\n");
														}
													}
												}
												else if(fds[0].revents & POLLHUP || fds[0].revents & POLLRDHUP) {
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(close(destfd) < 0) {
														exit(-1); // unknown close() error
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												if(fds[1].revents & POLLIN) {
													memset(package, 0, BUFFERSIZE); // zero out package buffer to avoid garbage data
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_read_ex(tls_client, package, BUFFERSIZE, &readbytes)) != 1) {
															switch(SSL_get_error(tls_client, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	//free(request_details_domain);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(clientfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(destfd);
																	return NULL;
																default:
																	exit(-1); // unknown SSL_read_ex() error
															}
														}
													} else {
														readbytes = read(clientfd, package, BUFFERSIZE); // try to read() a new request from client
														if(readbytes == 0) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															//free(request_details_domain);
															if(close(clientfd) < 0) {
																exit(-1); // unknown close() error
															}
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(destfd);
															return NULL;
														}
														else if(readbytes < 0) {
															exit(-1); // unknown read() error
														}
													}
													if(hexdump_enabled == true) {
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														hexdump(package, readbytes); // hexdump the read data
													}
													if(editing_enabled == true) {
														gettimeofday(&current_time, NULL); printf("[%.6f][%s] entering hexedit mode...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														editbuffer(package, readbytes);
														if(hexdump_enabled == true) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] EDITED REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															hexdump(package, readbytes);
														}
													}
													if(logging_enabled == true) {
														// log the package content in form of a .bin binary file to the path in the argument
														// if the content is somehow encrypted you need to decrypt it yourself
														// path is argv[argv_pos+1]
														char logname[] = "-request-";
														char ending[] = ".bin";
														char logcount[10]; // size is 10 because of max int value (10 digits)
														sprintf(logcount, "%u", logcount_requests);
														// construct file name
														char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(logcount)+strlen(ending)+4]; // +4 because of the _ and - added below, and the null byte for strings
														memset(filename, 0, sizeof(filename));
														strcpy(filename, client_ip);
														for(int count = 0; count < sizeof(filename); count++) { // replace dots with _ in the filename (because ipv4 of client is used as filename)
															if(filename[count] == '.') {
																filename[count] = '_';
															}
														}
														strcat(filename, "_");
														strcat(filename, client_port);
														strcat(filename, logname);
														strcat(filename, random_string);
														strcat(filename, "-");
														strcat(filename, logcount);
														strcat(filename, ending);
														logpkg(filename, logpath, package, readbytes);
														logcount_requests++;
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_write(tls_dest, package, readbytes)) <= 0) {
															switch(SSL_get_error(tls_dest, ssl_rtrn)) {
																case SSL_ERROR_WANT_READ:
																	usleep(1000);
																	continue;
																case SSL_ERROR_WANT_WRITE:
																	usleep(1000);
																	continue;
																case SSL_ERROR_ZERO_RETURN:
																	gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	//free(request_details_domain);
																	SSL_free(tls_dest);
																	SSL_CTX_free(tls_dest_ctx);
																	SSL_free(tls_client);
																	SSL_CTX_free(tls_client_ctx);
																	if(close(destfd) < 0) {
																		exit(-1); // unknown close() error
																	}
																	gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																	close_connection(clientfd);
																	return NULL;
																default:
																	printf("error!\n");
																	exit(-1); // unknown SSL_write() error
															}
														}
														printf("done!\n");
													} else {
														if(send(destfd, package, readbytes, MSG_NOSIGNAL) < 0) { // forward the request
															if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
																gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] dest closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																//free(request_details_domain);
																if(close(destfd) < 0) {
																	exit(-1);
																}
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(clientfd);
																return NULL;
															} else {
																printf("error!\n");
																exit(-1); // unknown write() error
															}
														} else {
															printf("done!\n");
														}
													}
												}
												else if(fds[1].revents & POLLHUP || fds[1].revents & POLLRDHUP) {
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													//free(request_details_domain);
													if(close(clientfd) < 0) {
														exit(-1); // unknown close() error
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(destfd);
													return NULL;
												}
											}
											else if(timeout_return == 0) {
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] no data to forward to or from client : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												//free(request_details_domain);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(destfd);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(clientfd);
												return NULL;
											}
											else if(timeout_return < 0) {
												exit(-1); // unknown poll() error
											}
										}
									}
									else if(timeout_return == 0) {
										gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] connecting to package destination failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										//free(request_details_domain);
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										close_connection(clientfd);
										return NULL;
									}
								}
								//free(request_details_domain);
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								close_connection(clientfd);
								return NULL;
							}
							else if(timeout_return == 0) { // answer didn't came in after 10 secs
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] no further input from %s:%u : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port), random_string);
								//free(request_details_domain);
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								close_connection(clientfd);
								return NULL;
							}
						} else { // requested address type is not IPv4 or DOMAIN
							gettimeofday(&current_time, NULL); printf("[%.6f][%s] new connection requested other address type than IPv4 or DOMAIN (proxy only supports IPv4 and DOMAIN): ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
							request_reply.version = 0x05;
							request_reply.reply_code = 0x08; // address type not supported
							request_reply.reserved = 0x00;
							request_reply.address_type = 0x01;
							request_reply.bnd_address[0] = 0x00;
							request_reply.bnd_address[1] = 0x00;
							request_reply.bnd_address[2] = 0x00;
							request_reply.bnd_address[3] = 0x00;
							request_reply.bnd_port = 0x00;
							if(send(clientfd, &request_reply, sizeof(request_reply), MSG_NOSIGNAL) < 0) { // send reply (0x08 : address type not supported)
								if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									if(close(clientfd) < 0) {
										exit(-1);
									}
									return NULL;
								} else {
									exit(-1); // unknown write() error
								}
							}
							gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
							close_connection(clientfd); // immediately close the connection after that (as described in RFC 1928)
							return NULL;
						}
					} else { // requested command is not CONNECT
						gettimeofday(&current_time, NULL); printf("[%.6f][%s] new connection requested other command than CONNECT (proxy only supports CONNECT): ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
						request_reply.version = 0x05;
						request_reply.reply_code = 0x07; // command not supported
						request_reply.reserved = 0x00;
						request_reply.address_type = 0x01;
						request_reply.bnd_address[0] = 0x00;
						request_reply.bnd_address[1] = 0x00;
						request_reply.bnd_address[2] = 0x00;
						request_reply.bnd_address[3] = 0x00;
						request_reply.bnd_port = 0x00;
						if(send(clientfd, &request_reply, sizeof(request_reply), MSG_NOSIGNAL) < 0) { // send reply (0x07 : command not supported)
							if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								if(close(clientfd) < 0) {
									exit(-1);
								}
								return NULL;
							} else {
								exit(-1); // unknown write() error
							}
						}
						gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
						close_connection(clientfd); // immediately close the connection after that (as described in RFC 1928)
						return NULL;
					}
				}
				else if(timeout_return == 0) {
					gettimeofday(&current_time, NULL); printf("[%.6f][%s] new connection didn't send request details after waiting for 10 secs : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
					gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
					close_connection(clientfd);
					return NULL;
				}
			} else {
				gettimeofday(&current_time, NULL); printf("[%.6f][%s] new connection does not support the NO AUTH method : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
				method_selection.version = 0x05;
				method_selection.method = 0xFF; // the "NO ACCEPTABLE METHODS" byte
				if(send(clientfd, &method_selection, sizeof(method_selection), MSG_NOSIGNAL) < 0) { // send method selection to client (no methods accepted)
					if(errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET) {
						gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : continuing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
						if(close(clientfd) < 0) {
							exit(-1);
						}
						return NULL;
					} else {
						exit(-1); // unknown write() error
					}
				}
				// after that the client closes the connection (as described in RFC 1928)
				// TODO: implement a routine to check if connection was shutdown from client
				close(clientfd);
				return NULL;
			}
		} else { // if the version identifier is not 5, close the connection and wait for a new one
			free(package_greeting);
			gettimeofday(&current_time, NULL); printf("[%.6f][%s] new connection is not SOCKS version 5 : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
			gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
			close_connection(clientfd);
			return NULL;
		}
	}
	else if(timeout_return == 0) {
		gettimeofday(&current_time, NULL); printf("[%.6f][%s] No input from client after initial TCP handshake : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
		gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
		close_connection(clientfd);
		return NULL;
	}
}

int main(int argc, char *argv[]) {
	struct timeval start_time; gettimeofday(&start_time, NULL); // get start time of the program (used for timestamp printing)
	struct timeval current_time;
	int listenfd; // connection queue
	short timeout_return; // the value returned by timeout()

	// handling shell arguments
	socks_handler_args *args = malloc(sizeof(socks_handler_args));
	args->start_time = start_time;
	int argv_pos = check_argv(argc, argv, "--port");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] no port number specified: using default value 1080\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		listenfd = open_socket((bool) true, INADDR_ANY, (uint16_t) htons(1080));
	} else {
		if(argc < argv_pos+2) { // check if there is value after --port argument
			gettimeofday(&current_time, NULL); printf("[%.6f] no port number after --port argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		} else {
			char *s = argv[argv_pos+1];
			while (*s) { // check if that value is an actual port (numeric) and not something else
				if(isdigit(*s) == 0) {
					gettimeofday(&current_time, NULL); printf("[%.6f] port number after --port argument is not numeric : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
					exit(1);
				} else {
					s++;
				}
			}
			int listen_port = atoi(argv[argv_pos+1]); // the argument after the found --port is used as port number
			if(listen_port > 65535) { // check if the selected port is higher than the max port
				gettimeofday(&current_time, NULL); printf("[%.6f] port number after --port is higher than 65535 (max port) : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				exit(1);
			}
			gettimeofday(&current_time, NULL); printf("[%.6f] using port number : %u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), listen_port);
			listenfd = open_socket((bool) true, INADDR_ANY, htons(listen_port));
		}
	}
	//char *logpath = NULL;
	argv_pos = check_argv(argc, argv, "--log");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] logging disabled : --log not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		args->logging_enabled = false;
		args->logpath = NULL;
	} else {
		// logging enabled
		if(argc < argv_pos+2) { // check if there is something after --log argument
			gettimeofday(&current_time, NULL); printf("[%.6f] no path behind --log argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		} else {
			if(opendir(argv[argv_pos+1]) == NULL) { // check if the dir behind --log is usable
				switch(errno) {
					case EACCES:
						gettimeofday(&current_time, NULL); printf("[%.6f] permission denied to open dir behind --log argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						exit(1);
					case ENOENT:
						gettimeofday(&current_time, NULL); printf("[%.6f] dir behind --log argument does not exist : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						exit(1);
					case ENOTDIR:
						gettimeofday(&current_time, NULL); printf("[%.6f] dir behind --log argument is not a dir : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						exit(1);
					default:
						exit(-1); // unknown opendir() error
				}
			} else { // is usable
				args->logpath = (char *) malloc(strlen(argv[argv_pos+1])+1);
				strcpy(args->logpath, argv[argv_pos+1]);
				args->logging_enabled = true;
				gettimeofday(&current_time, NULL); printf("[%.6f] logging enabled : writing to %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), argv[argv_pos+1]);
			}
		}
	}
	argv_pos = check_argv(argc, argv, "--forward");
	if(argv_pos == -1) {
		args->forwarding_enabled = false;
		gettimeofday(&current_time, NULL); printf("[%.6f] forwarding disabled : --forward not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	} else {
		args->forwarding_enabled = true;
		gettimeofday(&current_time, NULL); printf("[%.6f] forwarding enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	}
	argv_pos = check_argv(argc, argv, "--hexdump");
	if(argv_pos == -1) {
		args->hexdump_enabled = false;
		gettimeofday(&current_time, NULL); printf("[%.6f] hexdump in STDOUT disabled : --hexdump not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	} else {
		args->hexdump_enabled = true;
		gettimeofday(&current_time, NULL); printf("[%.6f] hexdump enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	}
	bool threading_enabled;
	argv_pos = check_argv(argc, argv, "--threaded");
	if(argv_pos == -1) {
		threading_enabled = false;
		gettimeofday(&current_time, NULL); printf("[%.6f] paralellism disabled : --threaded not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	} else {
		threading_enabled = true;
		gettimeofday(&current_time, NULL); printf("[%.6f] paralellism enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	}
	argv_pos = check_argv(argc, argv, "--edit");
	if(argv_pos == -1) {
		args->editing_enabled = false;
		gettimeofday(&current_time, NULL); printf("[%.6f] editing disabled : --edit not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	} else {
		if(threading_enabled == true) {
			args->editing_enabled = false;
			gettimeofday(&current_time, NULL); printf("[%.6f] editing disabled : editing only supported in single thread mode\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		} else {
			args->editing_enabled = true;
			gettimeofday(&current_time, NULL); printf("[%.6f] editing enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		}
	}
	argv_pos = check_argv(argc, argv, "--tls-decrypt");
	if(argv_pos == -1) {
		args->tls_decrypt_enabled = false;
		gettimeofday(&current_time, NULL); printf("[%.6f] decrypting of TLS requests disabled : --tls-decrypt not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	} else {
		args->tls_decrypt_enabled = true;
		gettimeofday(&current_time, NULL); printf("[%.6f] decrypting of TLS requests enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
	}
	argv_pos = check_argv(argc, argv, "--CN");
	if(argv_pos == -1) {
		if(args->tls_decrypt_enabled == true) {
			gettimeofday(&current_time, NULL); printf("[%.6f] no X509 COMMON NAME specified : using default value\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			args->CN = "localhost";
		}
	} else {
		if(argc < argv_pos+2) {
			gettimeofday(&current_time, NULL); printf("[%.6f] no X509 COMMON NAME after --CN argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		}
		if(args->tls_decrypt_enabled == true) {
			args->CN = argv[argv_pos+1];
			gettimeofday(&current_time, NULL); printf("[%.6f] using X509 COMMON NAME %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), args->CN);
		} else {
			gettimeofday(&current_time, NULL); printf("[%.6f] ignoring --CN : only used when --tls-decrypt is set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			args->CN = NULL;
		}
	}
	argv_pos = check_argv(argc, argv, "--SAN");
	if(argv_pos == -1) {
		if(args->tls_decrypt_enabled == true) {
			gettimeofday(&current_time, NULL); printf("[%.6f] no X509 SAN specified : using default value\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			args->SAN = "localhost";
		}
	} else {
		if(argc < argv_pos+2) {
			gettimeofday(&current_time, NULL); printf("[%.6f] no X509 SAN after --SAN argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		}
		if(args->tls_decrypt_enabled == true) {
			args->SAN = argv[argv_pos+1];
			gettimeofday(&current_time, NULL); printf("[%.6f] using X509 SAN %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), args->SAN);
		} else {
			gettimeofday(&current_time, NULL); printf("[%.6f] ignoring --SAN : only used when --tls-decrypt is set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			args->SAN = NULL;
		}
	}
	argv_pos = check_argv(argc, argv, "--socks5");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] no proxy specified with --socks5 : connecting directly to dest\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		args->forward_to_proxy = false;
	} else {
		if(argc < argv_pos+2) {
			gettimeofday(&current_time, NULL); printf("[%.6f] no IPv4 address after --socks5 argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		}
		if(argc < argv_pos+3) {
			gettimeofday(&current_time, NULL); printf("[%.6f] no port number after --socks5 argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		}
		if(args->forwarding_enabled == true) {
			struct in_addr proxy_addr_in;
			if(inet_pton(AF_INET, argv[argv_pos+1], &proxy_addr_in) <= 0) {
				gettimeofday(&current_time, NULL); printf("[%.6f] invalid IPv4 address after --socks5 argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				exit(1);
			} else {
				args->proxy_addr = proxy_addr_in.s_addr;
			}
			char *s = argv[argv_pos+2];
			while (*s) { // check if that value is an actual port (numeric) and not something else
				if (isdigit(*s) == 0) {
					gettimeofday(&current_time, NULL); printf("[%.6f] port number after --socks5 argument is not numeric : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
					exit(1);
				} else {
					s++;
				}
			}
			int proxy_port = atoi(argv[argv_pos+2]);
			if(proxy_port > 65535) { // check if the selected port is higher than the max port
				gettimeofday(&current_time, NULL); printf("[%.6f] port number after --socks5 is higher than 65535 (max port) : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				exit(1);
			} else {
				args->proxy_port = htons(proxy_port);
			}
			args->forward_to_proxy = true;
			gettimeofday(&current_time, NULL); printf("[%.6f] forwarding to socks5 proxy enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		} else {
			gettimeofday(&current_time, NULL); printf("[%.6f] --socks5 ignored : only used when forwarding is enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			args->forward_to_proxy = false;
		}
	}

	while(1) { // infinite server loop	
		gettimeofday(&current_time, NULL); printf("[%.6f] Listening for new connections...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		timeout_return = timeout(listenfd, POLLIN, 600000); // wait 600000 millisecs (10 mins) for incoming connections
		//timeout_return = timeout(listenfd, POLLIN, 30000);
		if(timeout_return & POLLIN) { // new connection came in
			gettimeofday(&current_time, NULL); printf("[%.6f] new (SYN) connection request came in!\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			struct sockaddr_in clientaddr;
			socklen_t clientlen = sizeof(clientaddr);
			int clientfd = accept4(listenfd, (struct sockaddr*) &clientaddr, &clientlen, SOCK_NONBLOCK);
			if(clientfd > 0) {
				args->clientfd = clientfd;
				args->clientaddr = clientaddr;
				if(threading_enabled == true) {
					// create thread and handle client
					pthread_t tid;
					if(pthread_create(&tid, NULL, handle_socks_request, args) != 0) {
						gettimeofday(&current_time, NULL); printf("[%.6f] error creating new thread : quitting\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						close_connection(clientfd);
						free(args);
						return -1; // unknown pthread_create() error
					}
					pthread_detach(tid);
				} else {
					handle_socks_request(args);
				}
			} else {
				gettimeofday(&current_time, NULL); printf("[%.6f] initial TCP handshake failed for new connection : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			}
		}
		else if(timeout_return == 0) {
			gettimeofday(&current_time, NULL); printf("[%.6f] proxy didn't receive new connections in 10 minutes : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			free(args);
			return 0;
		}
	}
}
