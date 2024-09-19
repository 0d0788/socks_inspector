#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>

#define STDOUT 1

int open_socket(bool listening_socket, uint32_t addr, uint16_t port) {

	// opens a socket and either binds a name or connects it based on the (bool) listen argument

	int socketfd; // the socket fd returned by the function
	struct sockaddr_in serveraddr;
	//char msg[]; // the messages printed with write()
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
		gettimeofday(&current_time, NULL), printf("[%.6f] no port number specified: using default value 9050\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		listenfd = open_socket((bool) true, INADDR_ANY, (uint16_t) 9050);
	} else {
		gettimeofday(&current_time, NULL), printf("[%.6f] using port number : %s\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), argv[argv_pos+1]);
		uint16_t listen_port = atoi(argv[argv_pos+1]); // the argument after the found --port is used as port number
		listenfd = open_socket((bool) true, INADDR_ANY, listen_port);
	}

	short timeout_return; // the value returned by timeout()
	char package[16384]; // 16KiB buffer used for receiving packages into that buffer

	// SOCKS5 data formats to parse packages
	struct SOCKS5_greeting {
		uint8_t version;
		uint8_t nmethods;
		uint8_t methods[];
	};
	struct SOCKS5_method_selection {
		uint8_t version;
		uint8_t method;
	};
	struct SOCKS5_request_details {
		uint8_t version;
		uint8_t command;
		uint8_t reserved;
		uint8_t address_type;
		uint8_t dst_address[4]; // 4 octets for IPv4 address
		uint16_t dst_port;
	};
	struct SOCKS5_request_reply {
		uint8_t version;
		uint8_t reply;
		uint8_t reserved;
		uint8_t address_type;
		uint8_t server_address[4]; // 4 octets for IPv4 address
		uint16_t server_port;
	};

	while(1) { // infinite server loop

		// the listening socket needs to be non blocking! if not the read syscall blocks until there is something to read and that makes custom timeout implementation impossible
		gettimeofday(&current_time, NULL), printf("[%.6f] Listening for new connections...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
		timeout_return = timeout(listenfd, POLLIN, 600000); // wait 600000 secs (10 mins) for incoming connections
		if(timeout_return == POLLIN) { // new connection came in
			gettimeofday(&current_time, NULL), printf("[%.6f] new (SYN) connection request came in!\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			struct sockaddr_in clientaddr;
			int clientlen = sizeof(clientaddr);
			clientfd = accept(listenfd, (struct sockaddr*) &clientaddr, &clientlen);
			char client_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &clientaddr.sin_addr, client_ip, sizeof(client_ip)); // convert client ip to string
			gettimeofday(&current_time, NULL), printf("[%.6f] (ACK) CONNECTION REQUEST ACCEPTED from %s:%d\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port));
			timeout_return = timeout(clientfd, POLLIN, 10000); // wait 10 seconds for a new package from connected client
			if(timeout_return == POLLIN) { // there is a package from a connected client
				gettimeofday(&current_time, NULL), printf("[%.6f] NEW PACKAGE from %s:%d\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0), client_ip, ntohs(clientaddr.sin_port));
				if(read(clientfd, package, sizeof(package)) < 0) {
					exit(-1); // unknown read error
				}
				if(check_argv(argc, argv, "--echo") != -1) {
					gettimeofday(&current_time, NULL), printf("[%.6f] PACKAGE CONTENT :\n\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
					write(STDOUT, package, sizeof(package)); // print the package
					write(STDOUT, "\n", 1); // linefeed after EOF
				} else {
					gettimeofday(&current_time, NULL), printf("[%.6f] printing of package content disabled : --echo not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				}
				if(check_argv(argc, argv, "--forward") != -1) {
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
				} else {
					gettimeofday(&current_time, NULL), printf("[%.6f] forwarding of package disabled : --forward not set\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				}
			}
			else if(timeout_return == 0) {
				gettimeofday(&current_time, NULL), printf("[%.6f] No input from client after initial handshake : timeout\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
				exit(1);
			}
			// close the connections after each package forward (non-persistent behavior)
			gettimeofday(&current_time, NULL), printf("[%.6f] (non-persistent)CLOSING CLIENT CONNECTION...\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			if(shutdown(clientfd, SHUT_RDWR) < 0) {
				exit(-1); // unknown shutdown() error
			}
			if(close(clientfd) < 0) { // close the old client connection
				exit(-1); // unknown close() error
			}
			// return to while(1) and wait for new connection
		}
		else if(timeout_return == 0) {
			gettimeofday(&current_time, NULL), printf("[%.6f] Proxy didn't receive connections after 10 Minutes... closing\n", ((double) (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0));
			exit(1);
		}
	}
	return 0;
}
