/*
 * SOCKS Protocol Version 5 : implementation based on RFC 1928
 * Copyright (C) 2024 www.github.com/0d0788. All rights reserved.
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
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>

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
	for(int bufferlen_count = 0; bufferlen_count < bufferlen; bufferlen_count = bufferlen_count+16) {
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

void editbuffer(unsigned char *buffer, size_t bufferlen) { // not memory safe the buffers can simply overflow
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

void logpkg(char filename[], char logpath[], char *package, size_t package_len) { // logging helper to reduce code size
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
	fwrite(package, package_len, 1, logfile); // write package to logfile
	if(fclose(logfile) != 0) { // close the log file (every connection got its own)
		exit(-1); // unknown fclose() error
	}
}

void get_local_ip_and_port(int sockfd, uint8_t ip_buffer[4], uint16_t port) {
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(local_addr);
	if (getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len) == -1) {
		exit(-1); // unknown getsockname() error
	}
	memcpy(ip_buffer, &local_addr.sin_addr.s_addr, 4);
	port = local_addr.sin_port;
}

char *get_rand_num_as_string() { // returns a pointer to a random value as string in memory
	int rand_value = arc4random();
	int length = snprintf(NULL, 0, "%u", rand_value);
	char *buffer_rand = malloc(length+1); // +1 for null terminator
	if(buffer_rand == NULL) {
		char msg[] = "malloc() memory allocation failed : quitting\n";
		write(1, msg, sizeof(msg));
		exit(-1); // unknown malloc() error / error while allocating memory
	}
	sprintf(buffer_rand, "%u", rand_value);
	return buffer_rand;
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
	int clientfd;
	struct timeval start_time;
	bool forwarding_enabled;
	bool hexdump_enabled;
	bool editing_enabled;
	bool logging_enabled;
	char *logpath;
	bool tls_decrypt_enabled;
	struct sockaddr_in clientaddr;
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
	int clientfd = func_args->clientfd; // accepted incoming connection from listenfd
	int destfd; // destination where packages are forwarded to (if enabled)
	struct sockaddr_in clientaddr = func_args->clientaddr;
	char client_ip[INET_ADDRSTRLEN+1]; // ip address of the client +1 for null terminator
	memset(client_ip, 0, sizeof(client_ip)); // zero the buffer
	char dest_ip[INET_ADDRSTRLEN+1]; // ip address of the dest +1 for null terminator
	memset(dest_ip, 0, sizeof(dest_ip)); // zero the buffer
	uint32_t dest_addr = 0; // dest ipv4 in network byte order used by connect()
	short timeout_return; // the value returned by timeout()
	SSL_CTX *tls_client_ctx; // TLS client context
	SSL_CTX *tls_dest_ctx; // TLS dest context
	SSL *tls_client; // TLS client object
	SSL *tls_dest; // TLS dest object
	int ssl_rtrn; // the value returned by the openssl SSL_* functions
	bool is_tls; // used to identify if a connected client is really using TLS
	unsigned char package[65536]; // 64KiB buffer used for receiving packages into that buffer
	memset(package, 0, sizeof(package)); // zero the package buffer

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
		uint16_t dst_port;
	} SOCKS5_request_details;
	SOCKS5_request_details request_details;
	memset(&request_details, 0, sizeof(SOCKS5_request_details));
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
	
	char *random_string = get_rand_num_as_string(); // random value used in logfilename to guarantee unique file names and in the STDOUT messages for this connection
	
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
		if(read(clientfd, package, sizeof(package)) < 0) {
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
					memset(package, 0, sizeof(package));
					if((readbytes = read(clientfd, package, sizeof(package))) < 0) { // read the request details into buffer
						exit(-1); // unknown read() error
					}
					request_details.version = *package;
					request_details.command = *(package+1);
					request_details.reserved = 0x00;
					request_details.address_type = *(package+3);
					if(request_details.command == 0x01) { // check if the command in the request details is CONNECT
						if(request_details.address_type == 0x01) { // check if the address type in the request details is IPv4
							request_details.dst_address[0] = *(package+4);
							request_details.dst_address[1] = *(package+5);
							request_details.dst_address[2] = *(package+6);
							request_details.dst_address[3] = *(package+7);
							memcpy(&dest_addr, request_details.dst_address, 4);
							request_details.dst_port = (package[8] << 8) | package[9]; // copy port
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
								memset(package, 0, sizeof(package)); // zero out buffer to avoid garbage data
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
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] LOADING TLS CERT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										if(SSL_CTX_use_certificate_file(tls_client_ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) { // load TLS server cert
											printf("failed!\n");
											exit(-1);
										} else {
											printf("done!\n");
										}
										gettimeofday(&current_time, NULL); printf("[%.6f][%s] LOADING TLS PRIVATE KEY... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										if(SSL_CTX_use_PrivateKey_file(tls_client_ctx, "pkey.pem", SSL_FILETYPE_PEM) <= 0) { // load TLS server private key
											printf("failed! possible key/cert mismatch???\n");
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
											while((ssl_rtrn = SSL_read_ex(tls_client, package, sizeof(package), &readbytes)) != 1) {
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
										memset(package, 0, sizeof(package)); // zero out buffer to avoid garbage data
										if((readbytes = read(clientfd, package, sizeof(package))) < 0) {
											exit(-1); // unknown read() error (too lazy to write further errno handling lol)
										}
									}
								} else { // no TLS decryption enabled just read()
									if((readbytes = read(clientfd, package, sizeof(package))) < 0) {
										exit(-1); // unknown read() error (too lazy to write further errno handling lol)
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
								if(forwarding_enabled == true) {
									// forwarding and answer processing
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] forwarding to :: %u.%u.%u.%u:%u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, request_details.dst_address[0], request_details.dst_address[1], request_details.dst_address[2], request_details.dst_address[3], request_details.dst_port);
									gettimeofday(&current_time, NULL); printf("[%.6f][%s] CONNECTING TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
									destfd = open_socket((bool) false, dest_addr, htons(request_details.dst_port)); // create destination socket and connect it to destination
									timeout_return = timeout(destfd, POLLOUT, 5000);
									if(timeout_return & POLLOUT) { // wait for the destfd socket to become writeable (connected)
										printf("done!\n");
										if(tls_decrypt_enabled == true && is_tls == true) {
											// TLS man-in-the-middle forwarding
											tls_dest_ctx = SSL_CTX_new(TLS_client_method());
											SSL_CTX_set_verify(tls_dest_ctx, SSL_VERIFY_NONE, NULL);
											tls_dest = SSL_new(tls_dest_ctx);
											SSL_set_fd(tls_dest, destfd);
											char tls_sni[NI_MAXHOST];
											snprintf(dest_ip, sizeof(dest_ip), "%u.%u.%u.%u", request_details.dst_address[0], request_details.dst_address[1], request_details.dst_address[2], request_details.dst_address[3]); // Convert raw byte array to dotted-decimal string (IPv4)
											struct addrinfo dst_hints, *dst_info;
											memset(&dst_hints, 0, sizeof(dst_hints));
											dst_hints.ai_family = AF_INET;
											dst_hints.ai_socktype = SOCK_STREAM;
											dst_hints.ai_flags = AI_CANONNAME;
											int getaddrinfo_rtrn = getaddrinfo(dest_ip, NULL, &dst_hints, &dst_info);
											if(getaddrinfo_rtrn != 0) {
												if(getaddrinfo_rtrn == EAI_NONAME) { // no hostname found, just leave SNI empty
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] the IP %u.%u.%u.%u", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, request_details.dst_address[0], request_details.dst_address[1], request_details.dst_address[2], request_details.dst_address[3]);
													printf(" could not be resolved : TLS SNI stays empty\n");
												} else {
													exit(-1); // unknown getaddrinfo() error
												}
											} else { // hostname was found
												while(dst_info != NULL) { // loop through dst_info until a suitable hostname is found
													if(dst_info->ai_family == AF_INET && dst_info->ai_canonname != NULL) {
														snprintf(tls_sni, sizeof(tls_sni), "%s", dst_info->ai_canonname);
														SSL_set_tlsext_host_name(tls_dest, tls_sni); // set the TLS SNI client hello extension
														break;
													} else {
														dst_info = dst_info->ai_next;
													}
												}
												if(dst_info == NULL || dst_info->ai_canonname == NULL) {
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] the IP %u.%u.%u.%u", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, request_details.dst_address[0], request_details.dst_address[1], request_details.dst_address[2], request_details.dst_address[3]);
													printf(" could not be resolved : TLS SNI stays empty\n");
												}
											}
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
											while((ssl_rtrn = SSL_write(tls_dest, package, readbytes)) != 1) {
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
										fds[0].events = POLLIN;
										fds[1].fd = clientfd;
										fds[1].events = POLLIN;
										while(1) {
											timeout_return = poll(fds, 2, 5000);
											if(timeout_return > 0) {
												if(fds[0].revents & POLLIN) {
													memset(package, 0, sizeof(package)); // zero out package buffer to avoid garbage data
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_read_ex(tls_dest, package, sizeof(package), &readbytes)) != 1) {
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
														readbytes = read(destfd, package, sizeof(package)); // try to read() a answer from dest
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
													// Forward the response to the client
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
														while((ssl_rtrn = SSL_write(tls_client, package, readbytes)) != 1) {
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
												else if(fds[0].revents & POLLHUP) {
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													if(close(destfd) < 0) {
														exit(-1); // unknown close() error
													}
													gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
													close_connection(clientfd);
													return NULL;
												}
												if(fds[1].revents & POLLIN) {
													memset(package, 0, sizeof(package)); // zero out package buffer to avoid garbage data
													if(tls_decrypt_enabled == true && is_tls == true) {
														while((ssl_rtrn = SSL_read_ex(tls_client, package, sizeof(package), &readbytes)) != 1) {
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
														readbytes = read(clientfd, package, sizeof(package)); // try to read() a new request from client
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
													// Forward the new request to the dest
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
														while((ssl_rtrn = SSL_write(tls_dest, package, readbytes)) != 1) {
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
												else if(fds[1].revents & POLLHUP) {
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
										gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] connecting to package destination failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
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
						else if(request_details.address_type == 0x03) { // if the address type requested by client is DOMAIN
							uint8_t dst_domain_length = *(package+4);
							char dst_domain[dst_domain_length+1];
							memset(dst_domain, 0, sizeof(dst_domain));
							for(int count = 0; count < dst_domain_length; count++) { // safe the DOMAIN from request to resolv later if --forward is set
								dst_domain[count] = *(package+(5+count));
							}
							dst_domain[dst_domain_length] = '\0'; // set the null terminator for the getaddrinfo() to resolv the domain
							request_details.dst_port = (package[5 + dst_domain_length] << 8) | package[6 + dst_domain_length]; // copy port
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
							if(timeout_return & POLLIN) { // the answer came in
								memset(package, 0, sizeof(package));
								if((readbytes = read(clientfd, package, sizeof(package))) < 0) {
									exit(-1); // unknown read() error (too lazy to write further errno handling lol)
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
								if(forwarding_enabled == true) {
									// forwarding and answer processing
									struct addrinfo *dst_info;
									int getaddrinfo_rtrn = getaddrinfo(dst_domain, NULL, NULL, &dst_info);
									if(getaddrinfo_rtrn != 0) {
										if(getaddrinfo_rtrn == EAI_NONAME) {
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] the DOMAIN ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											for(int count = 0; count < dst_domain_length; count++) {
												printf("%c", dst_domain[count]);
											}
											printf(" could not be resolved : ignoring\n");
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											close_connection(clientfd);
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
											for(int count = 0; count < dst_domain_length; count++) {
												printf("%c", dst_domain[count]);
											}
											printf(":%u\n", request_details.dst_port);
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] resolved dest ip :: %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, dest_ip);
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] CONNECTING TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											destfd = open_socket((bool) false, dst_addr->sin_addr.s_addr, htons(request_details.dst_port)); // create destination socket and connect it to destination
											timeout_return = timeout(destfd, POLLOUT, 5000);
											if(timeout_return & POLLOUT) { // wait for the destfd socket to become writeable (connected)
												printf("done!\n");
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
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
														exit(-1); // unknown write() error
													}
												} else {
													printf("done!\n");
												}
												struct pollfd fds[2]; // poll() struct array
												fds[0].fd = destfd;
												fds[0].events = POLLIN;
												fds[1].fd = clientfd;
												fds[1].events = POLLIN;
												while(1) {
													timeout_return = poll(fds, 2, 5000);
													if(timeout_return > 0) {
														if(fds[0].revents & POLLIN) {
															memset(package, 0, sizeof(package)); // zero out package buffer to avoid garbage data
															readbytes = read(destfd, package, sizeof(package)); // try to read() a answer from dest
															if(readbytes == 0) {
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(destfd);
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(clientfd);
																return NULL;
															}
															else if(readbytes < 0) {
																exit(-1); // unknown read() error
															}
															// Forward the response to the client
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
																	exit(-1); // unknown write() error
																}
															} else {
																printf("done!\n");
															}
														}
														else if(fds[0].revents & POLLHUP) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] dest closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(destfd);
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(clientfd);
															return NULL;
														}
														if(fds[1].revents & POLLIN) {
															memset(package, 0, sizeof(package)); // zero out package buffer to avoid garbage data
															readbytes = read(clientfd, package, sizeof(package)); // try to read() a new request from client
															if(readbytes == 0) {
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(destfd);
																gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
																close_connection(clientfd);
																return NULL;
															}
															else if(readbytes < 0) {
																exit(-1); // unknown read() error
															}
															// Forward the new request to the dest
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
																	exit(-1); // unknown write() error
																}
															} else {
																printf("done!\n");
															}
														}
														else if(fds[1].revents & POLLHUP) {
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] client closed the connection : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(destfd);
															gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															close_connection(clientfd);
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
												gettimeofday(&current_time, NULL); printf("\n[%.6f][%s] connecting to package destination failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(clientfd);
												return NULL;
											}
										} else {
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] no IPv4 address could be found for the DOMAIN : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											close_connection(clientfd);
											return NULL;
										}
									}
								}
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								close_connection(clientfd);
								return NULL;
							}
							else if(timeout_return == 0) { // answer didn't came in after 10 secs
								gettimeofday(&current_time, NULL); printf("[%.6f][%s] no further input from %s:%u : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port), random_string);
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
	int argv_pos = check_argv(argc, argv, "--port");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] no port number specified: using default value 1080\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		listenfd = open_socket((bool) true, INADDR_ANY, (uint16_t) ntohs(1080));
	} else {
		if(argc < argv_pos+2) { // check if there is value after --port argument
			gettimeofday(&current_time, NULL); printf("[%.6f] no port number after --port argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		} else {
			char *s = argv[argv_pos+1];
			while (*s) { // check if that value is an actual port (numeric) and not something else
				if (isdigit(*s) == 0) {
					gettimeofday(&current_time, NULL); printf("[%.6f] port number specified after --port argument is not numeric : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
					exit(1);
				} else {
					s++;
				}
			}
			int listen_port = atoi(argv[argv_pos+1]); // the argument after the found --port is used as port number
			if(listen_port > 65535) { // check if the selected port is higher than the max port
				gettimeofday(&current_time, NULL); printf("[%.6f] specified port number is higher than 65535 (max port) : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				exit(1);
			}
			gettimeofday(&current_time, NULL); printf("[%.6f] using port number : %u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), listen_port);
			listenfd = open_socket((bool) true, INADDR_ANY, ntohs(listen_port));
		}
	}
	bool logging;
	char *logpath = NULL;
	argv_pos = check_argv(argc, argv, "--log");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] logging disabled : --log not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		logging = false;
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
				}
				exit(-1); // unknown opendir() error
			} else { // is usable
				logpath = (char *) malloc(strlen(argv[argv_pos+1])+1); // +1 for null terminator byte
				strcpy(logpath, argv[argv_pos+1]);
				logging = true;
				gettimeofday(&current_time, NULL); printf("[%.6f] logging enabled : writing to %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), argv[argv_pos+1]);
			}
		}
	}
	bool forward;
	argv_pos = check_argv(argc, argv, "--forward");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] forwarding disabled : --forward not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		forward = false;
	} else {
		gettimeofday(&current_time, NULL); printf("[%.6f] forwarding enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		forward = true;
	}
	bool hexd;
	argv_pos = check_argv(argc, argv, "--hexdump");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] hexdump in STDOUT disabled : --hexdump not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		hexd = false;
	} else {
		gettimeofday(&current_time, NULL); printf("[%.6f] hexdump enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		hexd = true;
	}
	bool threading_enabled;
	argv_pos = check_argv(argc, argv, "--threaded");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] paralellism disabled : --threaded not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		threading_enabled = false;
	} else {
		gettimeofday(&current_time, NULL); printf("[%.6f] paralellism enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		threading_enabled = true;
	}
	bool editing;
	argv_pos = check_argv(argc, argv, "--edit");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] editing disabled : --edit not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		editing = false;
	} else {
		if(threading_enabled == true) {
			gettimeofday(&current_time, NULL); printf("[%.6f] editing disabled : editing only supported in single thread mode\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			editing = false;
		} else {
			gettimeofday(&current_time, NULL); printf("[%.6f] editing enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			editing = true;
		}
	}
	bool tls_decrypt;
	argv_pos = check_argv(argc, argv, "--tls-decrypt");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL); printf("[%.6f] decrypting of TLS requests disabled : --tls-decrypt not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		tls_decrypt = false;
	} else {
		gettimeofday(&current_time, NULL); printf("[%.6f] decrypting of TLS requests enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		tls_decrypt = true;
	}

	socks_handler_args *args = malloc(sizeof(socks_handler_args));
	args->start_time = start_time;
	args->forwarding_enabled = forward;
	args->hexdump_enabled = hexd;
	args->editing_enabled = editing;
	args->logging_enabled = logging;
	args->logpath = logpath;
	args->tls_decrypt_enabled = tls_decrypt;

	while(1) { // infinite server loop	
		gettimeofday(&current_time, NULL); printf("[%.6f] Listening for new connections...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		timeout_return = timeout(listenfd, POLLIN, 600000); // wait 600000 millisecs (10 mins) for incoming connections
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
						close(clientfd);
						gettimeofday(&current_time, NULL); printf("[%.6f] error creating new thread : quitting\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						exit(-1); // unknown pthread_create() error
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
			exit(1);
		}
	}
}
