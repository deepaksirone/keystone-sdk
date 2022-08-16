#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string.h>
#include <keystone.h>
#include "edge_wrapper.h"
#include "encl_message.h"

#define PRINT_MESSAGE_BUFFERS 1

//const char* enc_path = "server_eapp.eapp_riscv";
//const char* runtime_path = "eyrie-rt";

#define PORTNUM 8067
int fd_clientsock;
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

void send_buffer(byte* buffer, size_t len){
  write(fd_clientsock, &len, sizeof(size_t));
  write(fd_clientsock, buffer, len);
}

// This is wrong, what if the first read doesnt return size_t many bytes?
byte* recv_buffer(size_t* len){
  read(fd_clientsock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  read(fd_clientsock, reply, reply_size);
  *len = reply_size;
  return reply;
}

void print_hex_data(unsigned char* data, size_t len){
  unsigned int i;
  std::string str;
  for(i=0; i<len; i+=1){
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
    str += ss.str();
    if(i>0 && (i+1)%8 == 0){
      if((i+1)%32 == 0){
	str += "\n";
      }
      else{
	str += " ";
      }
    }
  }
  printf("%s\n\n",str.c_str());
}

unsigned long print_buffer(char* str){
  printf("[SE] %s",str);
  return strlen(str);
}

void print_value(unsigned long val){
  printf("[SE] value: %u\n",val);
  return;
}

void send_reply(void* data, size_t len){
  printf("[EH] Sending encrypted reply:\n");

  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)data, len);

  send_buffer((byte*)data, len);
}

void* wait_for_client_pubkey(){
  size_t len;
  return recv_buffer(&len);
}

encl_message_t wait_for_message(){

  size_t len;

  void* buffer = recv_buffer(&len);

  printf("[EH] Got an encrypted message:\n");
  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)buffer, len);

  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

void send_report(void* buffer, size_t len)
{
  send_buffer((byte*)buffer, len);
}


void init_network_wait(){

  int fd_sock;
  struct sockaddr_in server_addr;

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0){
    printf("Failed to open socket\n");
    exit(-1);
  }
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORTNUM);
  if( bind(fd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
    printf("Failed to bind socket\n");
    exit(-1);
  }
  listen(fd_sock,2);

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  fd_clientsock = accept(fd_sock, (struct sockaddr*)&client_addr, &client_len);
  if (fd_clientsock < 0){
    printf("No valid client socket\n");
    exit(-1);
  }
}


int32_t initiate_connection(char *hostname, int32_t port) {

	int fd_sock;
	struct sockaddr_in server_addr;
	struct hostent *hostnm = NULL;

  printf("[initiate_connection] Hostname:port %s:%d\n", hostname, port); 

	fd_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (fd_sock < 0) {
		printf("[init] Failed to open socket\n");
		exit(-1);
	}

	memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  in_addr_t saddr;
  if (strcmp(hostname, "keystore.tap") == 0) {
    saddr = inet_addr("127.0.0.1");
    port = 7777; 
  } else {
	  hostnm = gethostbyname(hostname);
    if (hostnm == NULL) {
		  printf("[init] Gethostname failed");
		  exit(-1);
	  }
    saddr = *((unsigned long *)hostnm->h_addr);
  }

  server_addr.sin_port        = htons(port);
  server_addr.sin_addr.s_addr = saddr;

	if (connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 ) {
		printf("[init] connect error");
		exit(-1);
	}

	return fd_sock;
}

int32_t initiate_connection_udp(char *hostname, int32_t port) {

	int fd_sock;
	struct sockaddr_in server_addr;
	struct hostent *hostnm = NULL;

  printf("[initiate_connection_udp] Hostname:port %s:%d\n", hostname, port); 

	fd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd_sock < 0) {
		printf("[initiate_connection_udp] Failed to open socket\n");
		exit(-1);
	}

	memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  in_addr_t saddr;
  if (strcmp(hostname, "keystore.tap") == 0) {
    saddr = inet_addr("127.0.0.1");
    port = 7777; 
  } else {
	  hostnm = gethostbyname(hostname);
    if (hostnm == NULL) {
		  printf("[initiate_connection_udp] Gethostname failed");
		  exit(-1);
	  }
    saddr = *((unsigned long *)hostnm->h_addr);
  }

  server_addr.sin_port        = htons(port);
  server_addr.sin_addr.s_addr = saddr;

	if (connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 ) {
		printf("[initiate_connection_udp] connect error");
		exit(-1);
	}

	return fd_sock;
}


size_t send_message_fd(int32_t fd, void *buffer, size_t size) {
	size_t ret = write(fd, buffer, size);
	fsync(fd);
	return ret;
}

network_recv_data_t receive_message_fd(int32_t fd, size_t size) {
  network_recv_data_t ret;
  void *buffer = malloc(size);
  printf("[host] Reading, sz: %lld\n", size);
  fflush(stdout);
  size_t sz_read = read(fd, buffer, size);
  printf("[host] Read, sz: %lld\n", sz_read);
  fflush(stdout);
  
  ret.size = sz_read;
  ret.data = buffer;

  return ret;
}

void terminate_connection(int32_t fd) {
	close(fd);
}


int main(int argc, char** argv)
{

  	/* Wait for network connection */
  	// init_network_wait();

  	//printf("[EH] Got connection from remote client\n");

  	Keystone::Enclave enclave;
  	Keystone::Params params;
  
  	params.setFreeMemSize(1024 * 1024);
  	params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 1024 * 1024);

  	if(enclave.init(argv[1], argv[2], params) != Keystone::Error::Success){
		printf("HOST: Unable to start enclave\n");
    		exit(-1);
  	}

  	edge_init(&enclave);

  	Keystone::Error rval = enclave.run();
  	printf("rval: %i\n",rval);

  	return 0;
}
