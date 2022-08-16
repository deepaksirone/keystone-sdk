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
#include "HTTPRequest.hpp"
#include "../include/rapidjson/document.h"
#include "../include/rapidjson/writer.h"
#include "../include/rapidjson/stringbuffer.h"

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
		return -1;
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

char *construct_request_json(char *trigger_id, char *oauth_token, uintptr_t nonce, char *params) {
    char *result = (char *)malloc(500 * sizeof(char));
    snprintf(result, 500, "{\"trigger_id\":\"%s\",\"oauth_token\":\"%s\",\"nonce\": %lu, \"params\": \"%s\"}", trigger_id, oauth_token, nonce, params);
    return result;
}

void *hex_string_to_bin(std::string &hexstr, int32_t *sz)
{
    if (hexstr.size() % 2 != 0) {
      printf("[hex_string_to_bin] Error converting hex string to bin array\n");
      return NULL;
    }

    int32_t final_len = hexstr.length() / 2;
    char *array = (char *)malloc(final_len * sizeof(char));

    for (unsigned int i = 0, j = 0; i < hexstr.length(); i += 2, j++) {
      std::string byteString = hexstr.substr(i, 2);
      array[j] = (char) strtol(byteString.c_str(), NULL, 16);
    }

    *sz = final_len;
    return (void *)array;
}

char *lookup_oauth_token(char *trigger_id) {
    //TODO: Test only
    return "5f8eac3ef18e9c3c40a65f1958620ed2d192acd97d0d7f1ffc43b63a9f2bc14a0724c0884b03cd6ed52f68a71581b4dfcc7cafe15f4e334a9baedde47fff5378";
}

void *get_trigger_data(trigger_data_t *data, size_t *trigger_data_sz) {
    //TODO: parse JSON and return JSON with nonce
    char *trigger_id = data->trigger_name;
    char *oauth_token = lookup_oauth_token(trigger_id);
    uintptr_t nonce = data->nonce;
  
    http::Request request{"http://10.141.156.5:7777/event_data/"};

    const std::string body = construct_request_json(trigger_id, oauth_token, nonce, (char *)data->rule_params);
    const auto response = request.send("POST", body, {
        {"Content-Type", "application/json"}
    });

    auto res = std::string{response.body.begin(), response.body.end()};
    std::cout << "Response: " << res << std::endl;
    rapidjson::Document doc;
    if (doc.Parse(res.c_str()).HasParseError()) {
      printf("[Trigger Data] Error Parsing JSON: %s\n", res.c_str());
      *trigger_data_sz = 0;
		  return NULL;
    }

    if (!doc.HasMember("event_ciphertext")) {
      printf("[Trigger Data] Trigger data has no member event_ciphertext\n");
      *trigger_data_sz = 0;
      return NULL;
    }

    if (!doc.HasMember("tag")) {
      printf("[Trigger Data] Trigger data has no member tag\n");
      *trigger_data_sz = 0;
      return NULL;
    }

     if (!doc.HasMember("enc_nonce")) {
      printf("[Trigger Data] Trigger data has no member tag\n");
      *trigger_data_sz = 0;
      return NULL;
    }

    std::string ciphertext(doc["event_ciphertext"].GetString());
    int32_t ciphertext_sz;
    void *ciphertext_bin = hex_string_to_bin(ciphertext, &ciphertext_sz);

    std::string tag(doc["tag"].GetString());
    int32_t tag_sz;
    void *tag_bin = hex_string_to_bin(tag, &tag_sz);

    if (tag_sz > 16) {
      printf("[Trigger Data] Tag size is too big: %d\n", tag_sz);
      *trigger_data_sz = 0;
      return NULL; 
    }

    std::string enc_nonce(doc["enc_nonce"].GetString());
    int32_t enc_nonce_sz;
    void *enc_nonce_bin = hex_string_to_bin(enc_nonce, &enc_nonce_sz);

    if (enc_nonce_sz > 16) {
      printf("[Trigger Data] enc_nonce size is too big: %d\n", enc_nonce_sz);
      *trigger_data_sz = 0;
      return NULL; 
    }

    trigger_response_t *resp = (trigger_response_t *)malloc(sizeof(trigger_response_t) + ciphertext_sz * sizeof(char));
    memcpy(&resp->tag, tag_bin, tag_sz);
    memcpy(&resp->iv, enc_nonce_bin, enc_nonce_sz);
    memcpy(&resp->ciphertext, ciphertext_bin, ciphertext_sz);
    resp->ciphertext_size = ciphertext_sz;

    *trigger_data_sz =  sizeof(trigger_response_t) + ciphertext_sz * sizeof(char);
    return (void *)resp;
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
  
  	params.setFreeMemSize(4 * 4096);
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
