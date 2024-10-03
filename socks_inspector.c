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
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <ctype.h>
#include <sys/time.h>

#define STDOUT 1

int open_socket(bool listening_socket, uint32_t addr, uint16_t port) {

	// opens a socket and either binds a name or connects it based on the (bool) listen argument

	int socketfd; // the socket fd returned by the function
	struct sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(addr);
	serveraddr.sin_port = htons(port);

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

short timeout(int socketfd, short event, int timeout) { // poll() helper to reduce code size
	struct pollfd pollfd;
	pollfd.fd = socketfd;
	pollfd.events = event;
	int poll_return = poll(&pollfd, 1, timeout);
	if(poll_return > 0 && pollfd.revents == event) {
		return pollfd.revents;
	}
	if(poll_return == 0) {
		return 0; // timeout
	}
	if(poll_return < 0) {
		exit(-1); // unknown poll()	error
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

int main(int argc, char *argv[]) {

	struct timeval start_time; gettimeofday(&start_time, NULL); // get start time of the program (used for timestamp printing)
	struct timeval current_time;
	int listenfd; // connection queue
	int clientfd; // accepted incoming connection from listenfd
	int destfd; // destination where packages are forwarded to (if enabled)
	
	// handling shell arguments
	int argv_pos = check_argv(argc, argv, "--port");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL), printf("[%.6f] no port number specified: using default value 1080\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		listenfd = open_socket((bool) true, INADDR_ANY, (uint16_t) 1080);
	} else {
		gettimeofday(&current_time, NULL), printf("[%.6f] using port number : %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), argv[argv_pos+1]);
		uint16_t listen_port = atoi(argv[argv_pos+1]); // the argument after the found --port is used as port number
		listenfd = open_socket((bool) true, INADDR_ANY, listen_port);
	}
	bool logging;
	char *logpath;
	size_t logpath_strsize;
	argv_pos = check_argv(argc, argv, "--log");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL), printf("[%.6f] logging disabled : only echo the package content\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		logging = false;
	} else {
		// logging enabled
		gettimeofday(&current_time, NULL), printf("[%.6f] logging enabled : writing to %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), argv[argv_pos+1]);
		logpath_strsize = sizeof(argv[argv_pos+1]);
		logpath = (char *) malloc(logpath_strsize * sizeof(char));
		strcpy(logpath, argv[argv_pos+1]);
		logging = true;
	}
	bool forward;
	argv_pos = check_argv(argc, argv, "--forward");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL), printf("[%.6f] forwarding of package disabled : --forward not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		forward = false;
	} else {
		forward = true;
	}

	short timeout_return; // the value returned by timeout()
	char package[16384]; // 16KiB buffer used for receiving packages into that buffer

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
	typedef struct {
		uint8_t version;
		uint8_t command;
		uint8_t reserved;
		uint8_t address_type;
		uint8_t dst_address[4]; // 4 octets for IPv4 address
		uint16_t dst_port;
	} SOCKS5_request_details;
	SOCKS5_request_details request_details;
	typedef struct {
		uint8_t version;
		uint8_t reply_code;
		uint8_t reserved;
		uint8_t address_type;
		uint8_t bnd_address[4]; // 4 octets for IPv4 address
		uint16_t bnd_port;
	} SOCKS5_request_reply;
	SOCKS5_request_reply request_reply;

	FILE *logfile; // used if logging is enabled with --log shell argument
	
	while(1) { // infinite server loop

		// the listening socket needs to be non blocking! if not the read syscall blocks until there is something to read and that makes custom timeout implementation impossible
		gettimeofday(&current_time, NULL), printf("[%.6f] Listening for new connections...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		timeout_return = timeout(listenfd, POLLIN, 600000); // wait 600000 secs (10 mins) for incoming connections
		if(timeout_return == POLLIN) { // new connection came in
			gettimeofday(&current_time, NULL), printf("[%.6f] new (SYN) connection request came in!\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			struct sockaddr_in clientaddr;
			socklen_t clientlen = sizeof(clientaddr);
			//clientfd = accept(listenfd, (struct sockaddr*) &clientaddr, &clientlen);
			clientfd = accept4(listenfd, (struct sockaddr*) &clientaddr, &clientlen, SOCK_NONBLOCK);
			if(clientfd > 0) {
				char client_ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &clientaddr.sin_addr, client_ip, sizeof(client_ip)); // convert client ip to string
				gettimeofday(&current_time, NULL), printf("[%.6f] (ACK) CONNECTION REQUEST ACCEPTED from %s:%d\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port));
				timeout_return = timeout(clientfd, POLLIN, 10000); // wait 10 seconds for the SOCKS5 greeting from client
				if(timeout_return == POLLIN) { // there is a package from a connected client
					gettimeofday(&current_time, NULL), printf("[%.6f] starting SOCKS5 handshake for %s:%d\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port));
					if(read(clientfd, package, sizeof(package)) < 0) {
						exit(-1); // unknown read() error
					}
					SOCKS5_greeting *package_greeting = malloc(sizeof(SOCKS5_greeting) + sizeof(uint8_t) * (*(package+1)));
					if(package_greeting == NULL) {
						exit(-1); // unknown malloc() error
					}
					package_greeting->version = *package;
					package_greeting->nmethods = *(package+1);
					for(int count = 0; count < package_greeting->nmethods; count++) {
						package_greeting->methods[count] = *(package+(2+count));
					}
					if(package_greeting->version == 0x05) { // check SOCKS version used by client
						int is_supported;
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
							if(write(clientfd, &method_selection, sizeof(method_selection)) < 0) { // send method selection to client
								exit(-1); // unknown write() error
							}
							timeout_return = timeout(clientfd, POLLIN, 10000); // wait max 10 seconds for an answer from the client (the request details)
							if(timeout_return == POLLIN) { // request details came in from client
								if(read(clientfd, package, sizeof(package)) < 0) { // read the request details into buffer
									exit(-1); // unknown read() error
								}
								request_details.version = *package;
								request_details.command = *(package+1);
								request_details.reserved = 0x00;
								request_details.address_type = *(package+3);
								request_details.dst_address[0] = *(package+4);
								request_details.dst_address[1] = *(package+5);
								request_details.dst_address[2] = *(package+6);
								request_details.dst_address[3] = *(package+7);
								request_details.dst_port = ((uint16_t) *(package+8) << 8) | *(package+9);
								if(request_details.command == 0x01) { // check if the command in the request details is CONNECT
									if(request_details.address_type == 0x01 || request_details.address_type == 0x03) { // check if the address type in the request details is IPv4 or DOMAINNAME
										request_reply.version = 0x05;
										request_reply.reply_code = 0x00; // connection succeeded
										request_reply.reserved = 0x00;
										request_reply.address_type = 0x01;
										request_reply.bnd_address[0] = request_details.dst_address[0];
										request_reply.bnd_address[1] = request_details.dst_address[1];
										request_reply.bnd_address[2] = request_details.dst_address[2];
										request_reply.bnd_address[3] = request_details.dst_address[3];
										request_reply.bnd_port = request_details.dst_port;
										if(write(clientfd, &request_reply, sizeof(request_reply)) < 0) { // send reply (0x00 for connection succeded)
											exit(-1); // unknown write() error
										}
										timeout_return = timeout(clientfd, POLLIN, 10000); // wait 10 seconds for an answer (the actual package to echo and/or forward)
										if(timeout_return == POLLIN) { // the answer came in
											if(read(clientfd, package, sizeof(package)) < 0) {
												exit(-1); // unknown read() error (too lazy to write further errno handling lol)
											}
											gettimeofday(&current_time, NULL), printf("[%.6f] PACKAGE CONTENT (printable chars) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
											for(int count = 0; count < sizeof(package); count++) {
												if(isprint(package[count]) != 0) { // check if the char is printable
													if(write(STDOUT, package+count, sizeof(package[count])) < 0) { // print the printable char
														exit(-1); // unknown write() error
													}
												}
											}
											if(write(STDOUT, "\n\n", 2) < 0) { // double linefeed after EOF
												exit(-1); // unknown write() error
											}
											if(logging == true) {
												// log the package content to a text file based on the path in the argument
												// if the content is somehow encrypted you need to decrypt it yourself
												// path is argv[argv_pos+1]
												char filename[sizeof(client_ip)];
												strcpy(filename, client_ip);
												for(int count = 0; count < sizeof(filename); count++) { // construct the filename
													if(filename[count] == '.') {
														filename[count] = '_';
													}
												}
												char full_path[logpath_strsize+sizeof(filename)];
												strcpy(full_path, logpath);
												if(logpath[logpath_strsize-1] == '/') { // if last char of path is / then just append the filename
													strcat(full_path, filename);
												} else { // else first append / and then the filename for a correct full_path
													strcat(full_path, "/");
													strcat(full_path, filename);
												}
												logfile = fopen(full_path, "a");
												fprintf(logfile, "\nRequest:\n====================\n\n");
												fprintf(logfile, package);
												fprintf(logfile, "\n");
											}
											if(forward == true) {
												// forwarding and answer processing
												/*
												gettimeofday(&current_time, NULL), printf("[%.6f] FORWARDING TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
												// cast the package to a structure representing the package content and change or check values (if needed)
												// int destfd = create_socket((bool) false, IP, PORT); // create destination socket and connect it to destination (from the received package)
												timeout_return = timeout(destfd, POLLOUT, 10000);
												if(timeout_return == POLLOUT) { // wait for the destfd socket to become writeable (connected)
													write(destfd, package, sizeof(package)); // after connecting to the original dest, forward the package with write (destfd is the socket connected to the dest of the package)
												}
												else if(timeout_return == 0) {
													gettimeofday(&current_time, NULL), printf("[%.6f] connecting to package destination failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
													exit(1);
												}
												timeout_return = timeout(destfd, POLLIN, 10000); // wait 10 secs for an answer
												if(timeout_return == POLLIN) { // answer came in
													// read, modify and forward to client
												}
												else if(timeout_return == 0) { // no answer (exceeded timeout)
													gettimeofday(&current_time, NULL), printf("[%.6f] failed to receive an answer : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
													exit(1);
												}
												// close the destfd connection after forwarding (non-persistent behavior)
												gettimeofday(&current_time, NULL), printf("[%.6f] (non-persistent)CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
												if(shutdown(destfd, SHUT_RDWR) < 0) {
													exit(-1); // unknown shutdown() error
												}
												if(close(destfd) < 0) {
													exit(-1); // unknown close() error
												}
												*/
												fprintf(logfile, "\nAnswer:\n====================\n\n");
												fprintf(logfile, package);
												fprintf(logfile, "\n");
											}
											// after the printing, possible forwarding and answer processing, close log file (if logging is enabled) and the connection to the client (non-persistent)
											if(logging == true) {
												if(fclose(logfile) != 0) { // close the log file (every connection got its own)
													exit(-1); // unknown fclose() error
												}
											}
											if(shutdown(clientfd, SHUT_RDWR) < 0) {
												exit(-1); // unknown shutdown() error
											}
											if(close(clientfd) < 0) {
												exit(-1); // unknown close() error
											}
										}
										else if(timeout_return == 0) { // answer didn't came in after 10 secs
											gettimeofday(&current_time, NULL), printf("[%.6f] no further input from %s:%d : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port));
											if(shutdown(clientfd, SHUT_RDWR) < 0) {
												exit(-1); // unknown shutdown() error
											}
											if(close(clientfd) < 0) {
												exit(-1); // unknown close() error
											}
										}
									} else { // requested address type is not IPv4
										gettimeofday(&current_time, NULL), printf("[%.6f] new connection requested other address type than IPv4 (proxy only supports IPv4): ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
										request_reply.version = 0x05;
										request_reply.reply_code = 0x08; // address type not supported
										request_reply.reserved = 0x00;
										request_reply.address_type = 0x01;
										request_reply.bnd_address[0] = 0x00;
										request_reply.bnd_address[1] = 0x00;
										request_reply.bnd_address[2] = 0x00;
										request_reply.bnd_address[3] = 0x00;
										request_reply.bnd_port = 0x00;
										if(write(clientfd, &request_reply, sizeof(request_reply)) < 0) { // send reply (0x08 : address type not supported)
											exit(-1); // unknown write() error
										}
										if(shutdown(clientfd, SHUT_RDWR) < 0) { // immediately close the connection after that (as described in RFC 1928)
											exit(-1); // unknown shutdown() error
										}
										if(close(clientfd) < 0) {
											exit(-1); // unknown close() error
										}
									}
								} else { // requested command is not CONNECT
									gettimeofday(&current_time, NULL), printf("[%.6f] new connection requested other command than CONNECT (proxy only supports CONNECT): ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
									request_reply.version = 0x05;
									request_reply.reply_code = 0x07; // command not supported
									request_reply.reserved = 0x00;
									request_reply.address_type = 0x01;
									request_reply.bnd_address[0] = 0x00;
									request_reply.bnd_address[1] = 0x00;
									request_reply.bnd_address[2] = 0x00;
									request_reply.bnd_address[3] = 0x00;
									request_reply.bnd_port = 0x00;
									if(write(clientfd, &request_reply, sizeof(request_reply)) < 0) { // send reply (0x07 : command not supported)
										exit(-1); // unknown write() error
									}
									if(shutdown(clientfd, SHUT_RDWR) < 0) { // immediately close the connection after that (as described in RFC 1928)
										exit(-1); // unknown shutdown() error
									}
									if(close(clientfd) < 0) {
										exit(-1); // unknown close() error
									}
								}
							}
							else if(timeout_return == 0) {
								gettimeofday(&current_time, NULL), printf("[%.6f] new connection didn't send request details after waiting for 10 secs : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
								if(shutdown(clientfd, SHUT_RDWR) < 0) {
									exit(-1); // unknown shutdown() error
								}
								if(close(clientfd) < 0) {
									exit(-1); // unknown close() error
								}
							}
						} else {
							gettimeofday(&current_time, NULL), printf("[%.6f] new connection does not support the NO AUTH method : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
							method_selection.version = 0x05;
							method_selection.method = 0xFF; // the "NO ACCEPTABLE METHODS" byte
							if(write(clientfd, &method_selection, sizeof(method_selection)) < 0) { // send method selection to client (no methods accepted)
								exit(-1); // unknown write() error
							}
							// after that the client closes the connection (as described in RFC 1928)
							// TODO: implement a routine to check if connection was shutdown from client
						}
					} else { // if the version identifier is not 5, close the connection and wait for a new one
						gettimeofday(&current_time, NULL), printf("[%.6f] new connection is not SOCKS version 5 : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						if(shutdown(clientfd, SHUT_RDWR) < 0) {
							exit(-1); // unknown shutdown() error
						}
						if(close(clientfd) < 0) {
							exit(-1); // unknown close() error
						}
					}
				}
				else if(timeout_return == 0) {
					gettimeofday(&current_time, NULL), printf("[%.6f] No input from client after initial TCP handshake : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
					if(shutdown(clientfd, SHUT_RDWR) < 0) {
						exit(-1); // unknown shutdown() error
					}
					if(close(clientfd) < 0) {
						exit(-1); // unknown close() error
					}
				}
			} else {
				gettimeofday(&current_time, NULL), printf("[%.6f] initial TCP handshake failed for new connection : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			}
		}
		else if(timeout_return == 0) {
			gettimeofday(&current_time, NULL), printf("[%.6f] Proxy didn't receive connections after 10 Minutes... closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		}
	}
}
