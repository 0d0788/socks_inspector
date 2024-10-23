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
	for(int bufferlen_count = 0; bufferlen_count < bufferlen; bufferlen_count = bufferlen_count+16) {
		printf("%08X | ", bufferlen_count);
		int count;
		//int bufferlen_count = bufferlen_count;
		for(count = 0; count < 16 && (count+bufferlen_count) < bufferlen; count++) {
			printf("%02X ", (unsigned char)buffer[bufferlen_count+count]);
		}
		if(count < 15) {
			while(count < 16) {
				printf("%02X ", 0x00);
				count++;
			}
		}
		printf("| ");
		for(count = 0; count < 16 && (count+bufferlen_count) < bufferlen; count++) {
			if(isprint(buffer[bufferlen_count+count]) != 0) { // check if the char is printable
				printf("%c", buffer[bufferlen_count+count]);
			} else {
				printf(".");
			}
		}
		if(count < 15) {
			while(count < 16) {
				printf(".");
				count++;
			}
		}
		printf("\n");
	}
	printf("\n");
}

void editbuffer(char *buffer, size_t bufferlen, char range, char *new_bytes) { // write bytes in new_bytes to the position in range into buffer
	// TODO : write a hexedit function to edit the package on the fly before forwarding it
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
		if(errno != ENOTCONN) {
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
	bool logging_enabled;
	char *logpath;
	struct sockaddr_in clientaddr;
} socks_handler_args;

void *handle_socks_request(void *args) {
	socks_handler_args *func_args = (socks_handler_args*) args;
	struct timeval start_time = func_args->start_time;
	struct timeval current_time;
	bool forwarding_enabled = func_args->forwarding_enabled;
	bool logging_enabled = func_args->logging_enabled;
	char *logpath = func_args->logpath;
	int clientfd = func_args->clientfd; // accepted incoming connection from listenfd
	int destfd; // destination where packages are forwarded to (if enabled)
	struct sockaddr_in clientaddr = func_args->clientaddr;
	char client_ip[INET_ADDRSTRLEN+1]; // ip address of the client +1 for null terminator
	memset(client_ip, 0, sizeof(client_ip)); // zero the buffer
	char dest_ip[INET_ADDRSTRLEN+1]; // ip address of the dest +1 for null terminator
	memset(dest_ip, 0, sizeof(dest_ip)); // zero the buffer
	short timeout_return; // the value returned by timeout()
	char package[32000]; // 32KB buffer used for receiving packages into that buffer
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
		char dst_address[4]; // 4 octets for IPv4 address
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
	
	get_local_ip_and_port(clientfd, local_ip, local_port); // get the local ip and port for the SOCKS5_request_reply.bnd_addr and SOCKS5_request_reply.bnd_port
	char client_port[6];
	sprintf(client_port, "%u", ntohs(clientaddr.sin_port));
	inet_ntop(AF_INET, &clientaddr.sin_addr, client_ip, sizeof(client_ip)); // convert client ip to string
	gettimeofday(&current_time, NULL), printf("[%.6f][%s] (ACK) CONNECTION REQUEST ACCEPTED from %s:%u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, client_ip, ntohs(clientaddr.sin_port));
	timeout_return = timeout(clientfd, POLLIN | POLLPRI, 5000); // wait 5 seconds for the SOCKS5 greeting from client
	if(timeout_return == POLLIN | POLLPRI) { // there is a package from a connected client
		gettimeofday(&current_time, NULL), printf("[%.6f][%s] starting SOCKS5 handshake for %s:%u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, client_ip, ntohs(clientaddr.sin_port));
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
				timeout_return = timeout(clientfd, POLLIN | POLLPRI, 5000); // wait max 5 seconds for an answer from the client (the request details)
				if(timeout_return == POLLIN | POLLPRI) { // request details came in from client
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
							request_details.dst_port = ((unsigned char)package[8] << 8) | (unsigned char)package[9]; // copy port
							request_reply.version = 0x05;
							request_reply.reply_code = 0x00; // connection succeeded
							request_reply.reserved = 0x00;
							request_reply.address_type = 0x01;
							request_reply.bnd_address[0] = local_ip[0];
							request_reply.bnd_address[1] = local_ip[1];
							request_reply.bnd_address[2] = local_ip[2];
							request_reply.bnd_address[3] = local_ip[3];
							request_reply.bnd_port = local_port;
							if(write(clientfd, &request_reply, sizeof(request_reply)) < 0) { // send reply (0x00 for connection succeded)
								exit(-1); // unknown write() error
							}
							timeout_return = timeout(clientfd, POLLIN | POLLPRI, 5000); // wait 5 seconds for an answer (the actual package to echo and/or forward)
							if(timeout_return == POLLIN | POLLPRI) { // the answer came in
								memset(package, 0, sizeof(package));
								if((readbytes = read(clientfd, package, sizeof(package))) < 0) {
									exit(-1); // unknown read() error (too lazy to write further errno handling lol)
								}
								gettimeofday(&current_time, NULL), printf("[%.6f][%s] PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								hexdump(package, readbytes); // hexdump the read data
								if(logging_enabled == true) {
									// log the package content in form of a .bin binary file to the path in the argument
									// if the content is somehow encrypted you need to decrypt it yourself
									// path is argv[argv_pos+1]
									char logname[] = "-request-";
									char ending[] = ".bin";
									// construct file name
									char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(ending)+3]; // +3 because of the _ and - added below, and the null byte for strings
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
									strcat(filename, ending);
									logpkg(filename, logpath, package, sizeof(package));
								}
								/*
								if(forwarding_enabled == true) {
									
								*/
								close_connection(clientfd);
							}
							else if(timeout_return == 0) { // answer didn't came in after 10 secs
								gettimeofday(&current_time, NULL), printf("[%.6f][%s] no further input from %s:%u : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, client_ip, ntohs(clientaddr.sin_port));
								close_connection(clientfd);
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
							request_details.dst_port = ((unsigned char)package[5 + dst_domain_length] << 8) | (unsigned char)package[6 + dst_domain_length]; // copy port
							request_reply.version = 0x05;
							request_reply.reply_code = 0x00; // connection succeeded
							request_reply.reserved = 0x00;
							request_reply.address_type = 0x01;
							request_reply.bnd_address[0] = local_ip[0];
							request_reply.bnd_address[1] = local_ip[1];
							request_reply.bnd_address[2] = local_ip[2];
							request_reply.bnd_address[3] = local_ip[3];
							request_reply.bnd_port = local_port;
							if(write(clientfd, &request_reply, sizeof(request_reply)) < 0) { // send reply (0x00 for connection succeded)
								exit(-1); // unknown write() error
							}
							timeout_return = timeout(clientfd, POLLIN | POLLPRI, 5000); // wait 5 seconds for an answer (the actual package to echo and/or forward)
							if(timeout_return == POLLIN | POLLPRI) { // the answer came in
								memset(package, 0, sizeof(package));
								if((readbytes = read(clientfd, package, sizeof(package))) < 0) {
									exit(-1); // unknown read() error (too lazy to write further errno handling lol)
								}
								gettimeofday(&current_time, NULL), printf("[%.6f][%s] REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								hexdump(package, readbytes); // hexdump the read data
								if(logging_enabled == true) {
									// log the package content in form of a .bin binary file to the path in the argument
									// if the content is somehow encrypted you need to decrypt it yourself
									// path is argv[argv_pos+1]
									char logname[] = "-request-";
									char ending[] = ".bin";
									// construct file name
									char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(ending)+3]; // +3 because of the _ and - added below, and the null byte for strings
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
									strcat(filename, ending);
									logpkg(filename, logpath, package, sizeof(package));
								}
								if(forwarding_enabled == true) {
									// forwarding and answer processing
									struct addrinfo *dst_info;
									int getaddrinfo_rtrn = getaddrinfo(dst_domain, NULL, NULL, &dst_info);
									if(getaddrinfo_rtrn != 0) {
										if(getaddrinfo_rtrn == EAI_NONAME) {
											gettimeofday(&current_time, NULL), printf("[%.6f][%s] the DOMAIN ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											for(int count = 0; count < dst_domain_length; count++) {
												printf("%c", dst_domain[count]);
											}
											printf(" could not be resolved : ignoring\n");
											exit(1);
										} else {
											exit(-1); // unknown getaddrinfo() error
										}
									} else {
										while(dst_info != NULL && dst_info->ai_family != AF_INET) { // loop through dst_info until a IPv4 address is found
											dst_info = dst_info->ai_next;
										}
										if(dst_info != NULL && dst_info->ai_family == AF_INET) { // IPv4 for DOMAIN was found
											struct sockaddr_in *dst_addr = (struct sockaddr_in*) dst_info->ai_addr;
											inet_ntop(AF_INET, &dst_addr->sin_addr, dest_ip, sizeof(dest_ip));
											gettimeofday(&current_time, NULL), printf("[%.6f][%s] forwarding to :: ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											for(int count = 0; count < dst_domain_length; count++) {
												printf("%c", dst_domain[count]);
											}
											printf(":%u\n", request_details.dst_port);
											gettimeofday(&current_time, NULL), printf("[%.6f][%s] resolved dest ip :: %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string, dest_ip);
											gettimeofday(&current_time, NULL), printf("[%.6f][%s] CONNECTING TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											destfd = open_socket((bool) false, dst_addr->sin_addr.s_addr, ntohs(request_details.dst_port)); // create destination socket and connect it to destination (from the received package)
											timeout_return = timeout(destfd, POLLOUT, 5000);
											if(timeout_return == POLLOUT) { // wait for the destfd socket to become writeable (connected)
												printf("done!\n");
												gettimeofday(&current_time, NULL), printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												if(write(destfd, package, sizeof(package)) < 0) { // forward the request
													exit(-1); // unknown write() error
												} else {
													printf("done!\n");
												}
												while(1) {
													timeout_return = timeout(destfd, POLLIN, 5000); // wait 5 secs for an answer
													if(timeout_return == POLLIN) { // answer came in
														memset(package, 0, sizeof(package));
														// Read the response from the destination
														readbytes = read(destfd, package, sizeof(package));
														if(readbytes < 0) { // read the reply
															exit(-1); // unknown read() error
														}
														else if(readbytes == 0) {
															gettimeofday(&current_time, NULL), printf("[%.6f][%s] connection still open but no answer from dest : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															break;
														}
														// Forward the response to the client
														gettimeofday(&current_time, NULL), printf("[%.6f][%s] REPLY PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														hexdump(package, readbytes); // hexdump the reply
														gettimeofday(&current_time, NULL), printf("[%.6f][%s] FORWARDING REPLY TO CLIENT... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														timeout_return = timeout(clientfd, POLLOUT, 5000);
														if(timeout_return == POLLOUT) {
															if(write(clientfd, package, readbytes) < 0) { // forward the answer to the client
																exit(-1); // unknown write() error
															} else {
																printf("done!\n");
															}
														}
														else if(timeout_return == 0) {
															gettimeofday(&current_time, NULL), printf("\n[%.6f][%s] client socket not writable : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															break;
														}
														if(logging_enabled == true) { // log the reply if logging enabled
															// log the package content in form of a .bin binary file to the path in the argument
															// if the content is somehow encrypted you need to decrypt it yourself
															// path is argv[argv_pos+1]
															char logname[] = "-reply-";
															char ending[] = ".bin";
															// construct file name
															char filename[strlen(client_ip)+strlen(client_port)+strlen(logname)+strlen(random_string)+strlen(ending)+3]; // +3 because of the _ and - added below, and the null byte for strings
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
															strcat(filename, ending);
															logpkg(filename, logpath, package, sizeof(package));
														}
													}
													else if(timeout_return == 0) { // no answer (exceeded timeout)
														gettimeofday(&current_time, NULL), printf("[%.6f][%s] no reply from dest : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														break;
													}
													// Check for a new request from the client
													timeout_return = timeout(clientfd, POLLIN | POLLRDHUP, 5000); // wait 5 secs for new request
													if(timeout_return == POLLIN) { // request came in
														memset(package, 0, sizeof(package)); // zero out buffer
														readbytes = read(clientfd, package, sizeof(package));
														if(readbytes < 0) {
															exit(-1); // unknown read() error (too lazy to write further errno handling lol)
														}
														else if(readbytes == 0) {
															gettimeofday(&current_time, NULL), printf("[%.6f][%s] connection still open but no data from client : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															break;
														}
														// Forward the new request to the destination
														gettimeofday(&current_time, NULL), printf("[%.6f][%s] REQUEST PACKAGE CONTENT (hexdump) :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														hexdump(package, readbytes); // hexdump the read data
														gettimeofday(&current_time, NULL), printf("[%.6f][%s] FORWARDING REQUEST TO DEST... ", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														timeout_return = timeout(destfd, POLLOUT, 5000);
														if(timeout_return == POLLOUT) {
															if(write(destfd, package, readbytes) < 0) { // forward the request
																exit(-1); // unknown write() error
															} else {
																printf("done!\n");
															}
														}
														else if(timeout_return == 0) {
															gettimeofday(&current_time, NULL), printf("\n[%.6f][%s] dest socket not writable : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
															break;
														}
													}
													else if(timeout_return == POLLRDHUP) { // client closed connection
														gettimeofday(&current_time, NULL), printf("[%.6f][%s] client closed the connection\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														break;
													}
													else if(timeout_return == 0) { // timeout
														gettimeofday(&current_time, NULL), printf("[%.6f][%s] failed to receive new request from client : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
														break;
													}
												}
												gettimeofday(&current_time, NULL), printf("[%.6f][%s] CLOSING CONNECTION TO DEST...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
												close_connection(destfd);
											}
											else if(timeout_return == 0) {
												gettimeofday(&current_time, NULL), printf("\n[%.6f][%s] connecting to package destination failed : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
											}
										} else {
											gettimeofday(&current_time, NULL), printf("[%.6f][%s] no IPv4 address could be found for the DOMAIN : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
										}
										freeaddrinfo(dst_info);
									}
								}
								gettimeofday(&current_time, NULL), printf("[%.6f][%s] CLOSING CONNECTION TO CLIENT...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
								close_connection(clientfd);
								/*if(close(clientfd) < 0) {
									exit(-1); // unknown close() error
								}*/
							}
							else if(timeout_return == 0) { // answer didn't came in after 10 secs
								gettimeofday(&current_time, NULL), printf("[%.6f][%s] no further input from %s:%u : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port), random_string);
								close_connection(clientfd);
							}
						} else { // requested address type is not IPv4 or DOMAIN
							gettimeofday(&current_time, NULL), printf("[%.6f][%s] new connection requested other address type than IPv4 or DOMAIN (proxy only supports IPv4 and DOMAIN): ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
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
							close_connection(clientfd); // immediately close the connection after that (as described in RFC 1928)
						}
					} else { // requested command is not CONNECT
						gettimeofday(&current_time, NULL), printf("[%.6f][%s] new connection requested other command than CONNECT (proxy only supports CONNECT): ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
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
						close_connection(clientfd); // immediately close the connection after that (as described in RFC 1928)
					}
				}
				else if(timeout_return == 0) {
					gettimeofday(&current_time, NULL), printf("[%.6f][%s] new connection didn't send request details after waiting for 10 secs : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
					close_connection(clientfd);
				}
			} else {
				gettimeofday(&current_time, NULL), printf("[%.6f][%s] new connection does not support the NO AUTH method : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
				method_selection.version = 0x05;
				method_selection.method = 0xFF; // the "NO ACCEPTABLE METHODS" byte
				if(write(clientfd, &method_selection, sizeof(method_selection)) < 0) { // send method selection to client (no methods accepted)
					exit(-1); // unknown write() error
				}
				// after that the client closes the connection (as described in RFC 1928)
				// TODO: implement a routine to check if connection was shutdown from client
			}
		} else { // if the version identifier is not 5, close the connection and wait for a new one
			gettimeofday(&current_time, NULL), printf("[%.6f][%s] new connection is not SOCKS version 5 : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
			close_connection(clientfd);
		}
	}
	else if(timeout_return == 0) {
		gettimeofday(&current_time, NULL), printf("[%.6f][%s] No input from client after initial TCP handshake : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), random_string);
		close_connection(clientfd);
	}
	return NULL;
}

int main(int argc, char *argv[]) {
	struct timeval start_time; gettimeofday(&start_time, NULL); // get start time of the program (used for timestamp printing)
	struct timeval current_time;
	int listenfd; // connection queue
	short timeout_return; // the value returned by timeout()

	// handling shell arguments
	int argv_pos = check_argv(argc, argv, "--port");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL), printf("[%.6f] no port number specified: using default value 1080\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		listenfd = open_socket((bool) true, INADDR_ANY, (uint16_t) ntohs(1080));
	} else {
		if(argc < argv_pos+2) { // check if there is value after --port argument
			gettimeofday(&current_time, NULL), printf("[%.6f] no port number after --port argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		} else {
			char *s = argv[argv_pos+1];
			while (*s) { // check if that value is an actual port (numeric) and not something else
				if (isdigit(*s) == 0) {
					gettimeofday(&current_time, NULL), printf("[%.6f] port number specified after --port argument is not numeric : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
					exit(1);
				} else {
					s++;
				}
			}
			int listen_port = atoi(argv[argv_pos+1]); // the argument after the found --port is used as port number
			if(listen_port > 65535) { // check if the selected port is higher than the max port
				gettimeofday(&current_time, NULL), printf("[%.6f] specified port number is higher than 65535 (max port) : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				exit(1);
			}
			gettimeofday(&current_time, NULL), printf("[%.6f] using port number : %u\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), listen_port);
			listenfd = open_socket((bool) true, INADDR_ANY, ntohs(listen_port));
		}
	}
	bool logging;
	char *logpath = NULL;
	argv_pos = check_argv(argc, argv, "--log");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL), printf("[%.6f] logging disabled : only echo the package content\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		logging = false;
	} else {
		// logging enabled
		if(argc < argv_pos+2) { // check if there is something after --log argument
			gettimeofday(&current_time, NULL), printf("[%.6f] no path behind --log argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		} else {
			if(opendir(argv[argv_pos+1]) == NULL) { // check if the dir behind --log is usable
				switch(errno) {
					case EACCES:
						gettimeofday(&current_time, NULL), printf("[%.6f] permission denied to open dir behind --log argument : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						exit(1);
					case ENOENT:
						gettimeofday(&current_time, NULL), printf("[%.6f] dir behind --log argument does not exist : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						exit(1);
					case ENOTDIR:
						gettimeofday(&current_time, NULL), printf("[%.6f] dir behind --log argument is not a dir : returning\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
						exit(1);
				}
				exit(-1); // unknown opendir() error
			} else { // is usable
				logpath = (char *) malloc(strlen(argv[argv_pos+1])+1); // +1 for null terminator byte
				strcpy(logpath, argv[argv_pos+1]);
				logging = true;
				gettimeofday(&current_time, NULL), printf("[%.6f] logging enabled : writing to %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), argv[argv_pos+1]);
			}
		}
	}
	bool forward;
	argv_pos = check_argv(argc, argv, "--forward");
	if(argv_pos == -1) {
		gettimeofday(&current_time, NULL), printf("[%.6f] forwarding of package disabled : --forward not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		forward = false;
	} else {
		gettimeofday(&current_time, NULL), printf("[%.6f] forwarding enabled\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		forward = true;
	}

	while(1) { // infinite server loop
		gettimeofday(&current_time, NULL), printf("[%.6f] Listening for new connections...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		timeout_return = timeout(listenfd, POLLIN | POLLPRI, 600000); // wait 600000 secs (10 mins) for incoming connections
		if(timeout_return == POLLIN | POLLPRI) { // new connection came in
			gettimeofday(&current_time, NULL), printf("[%.6f] new (SYN) connection request came in!\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			struct sockaddr_in clientaddr;
			socklen_t clientlen = sizeof(clientaddr);
			int clientfd = accept4(listenfd, (struct sockaddr*) &clientaddr, &clientlen, SOCK_NONBLOCK);
			if(clientfd > 0) {
				// create thread and handle client
				pthread_t tid;
				socks_handler_args *args = malloc(sizeof(socks_handler_args));
				args->clientfd = clientfd;
				args->start_time = start_time;
				args->forwarding_enabled = forward;
				args->logging_enabled = logging;
				args->logpath = logpath;
				args->clientaddr = clientaddr;
				if(pthread_create(&tid, NULL, handle_socks_request, args) != 0) {
					close(clientfd);
					gettimeofday(&current_time, NULL), printf("[%.6f] error creating new thread : quitting\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
					exit(-1); // unknown pthread_create() error
				}
				pthread_detach(tid);
			} else {
				gettimeofday(&current_time, NULL), printf("[%.6f] initial TCP handshake failed for new connection : ignoring\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			}
		}
		else if(timeout_return == 0) {
			gettimeofday(&current_time, NULL), printf("[%.6f] proxy didn't receive new connections after 10 minutes : closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		}
	}
}
