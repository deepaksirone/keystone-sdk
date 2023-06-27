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
#include <thread>
#include <chrono>

#include <keystone.h>
#include <keystone_user.h>
#include "../eapp/rule_keystore.h"
#include "edge_wrapper.h"
#include "encl_message.h"
#include "HTTPRequest.hpp"
#include "../include/rapidjson/document.h"
#include "../include/rapidjson/writer.h"
#include "../include/rapidjson/stringbuffer.h"
#include "../include/crow.h"
#include "../include/semaphore.h"

#define PRINT_MESSAGE_BUFFERS 1

semaphore events_notified;
semaphore actions_sent;

//const char* enc_path = "server_eapp.eapp_riscv";
//const char* runtime_path = "eyrie-rt";
void event_loop(struct keystore_rule *rule, int loop_times);

#define PORTNUM 8067
int fd_clientsock;
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

static int driver_fd = -1;

struct keystore_rule rule;

std::chrono::_V2::system_clock::time_point enclave_start;
std::chrono::_V2::system_clock::time_point enclave_end;

void populate_default(struct keystore_rule *rule)
{
    memcpy(&rule->key_action[0], "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 32);
    memcpy(&rule->key_trigger[0], "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 32);
    rule->num_actions = 1;
    rule->num_triggers = 1;
    rule->rid = 0;

}

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
  //printf("[host] Reading, sz: %lld\n", size);
  //fflush(stdout);
  size_t sz_read = read(fd, buffer, size);
  //printf("[host] Read, sz: %lld\n", sz_read);
  //fflush(stdout);
  
  ret.size = sz_read;
  ret.data = buffer;

  return ret;
}

static char request_json_buffer[500];
char *construct_request_json(char *trigger_id, char *oauth_token, uintptr_t nonce, char *params) {
    char *result = (char *)malloc(500 * sizeof(char));
    //char *result = (char *)result_json_buffer;
    snprintf(result, 500, "{\"trigger_id\":\"%s\",\"oauth_token\":\"%s\",\"nonce\": %lu, \"params\": \"%s\"}", trigger_id, oauth_token, nonce, params);
    return result;
}

static char hexstr_buf[4096 * 2];
void *hex_string_to_bin(std::string &hexstr, int32_t *sz)
{
    if (hexstr.size() % 2 != 0) {
      printf("[hex_string_to_bin] Error converting hex string to bin array\n");
      return NULL;
    }

    int32_t final_len = hexstr.length() / 2;
    char *array = (char *)malloc(final_len * sizeof(char));
    //char *array = (char *)hexstr_buf;

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


uintptr_t get_nonce_SM() {

  uintptr_t nonce;
  FILE *fp = fopen("/dev/urandom", "r+");
  fread(&nonce, 1, sizeof(uintptr_t), fp);
  fclose(fp);

  return nonce;

}

static char trigger_data_buf[4096 * 5];
void *get_trigger_data(trigger_data_t *data, size_t *trigger_data_sz) {
    //TODO: parse JSON and return JSON with nonce
    
    auto get_trigger_data_start_time = std::chrono::high_resolution_clock::now();
    char *trigger_id = data->trigger_name;
    char *oauth_token = lookup_oauth_token(trigger_id);
    //uintptr_t nonce = get_nonce_SM();
    uintptr_t nonce = 0xaaaaaaaa;
    
    //TODO: Request SM for the nonce here
  
    http::Request request{"http://node1.spigot1.cs799-serverless-pg0.wisc.cloudlab.us:80/event_data/"};

    const std::string body = construct_request_json(trigger_id, oauth_token, nonce, (char *)data->rule_params);

    //while (trigger_event_get_data == trigger_event_notified)
    //    std::this_thread::yield();
    
    //trigger_event_get_data++;
    events_notified.acquire();
    
    const auto response = request.send("POST", body, {
        {"Content-Type", "application/json"}
    });

    auto res = std::string{response.body.begin(), response.body.end()};
    //std::cout << "Response: " << res << std::endl;
    rapidjson::Document doc;
    if (doc.Parse(res.c_str()).HasParseError()) {
      printf("[Trigger Data] Error Parsing JSON: %s\n", res.c_str());
      *trigger_data_sz = 0;
		  return NULL;
    }

    if (!doc.HasMember("event_ciphertext")) {
      printf("[Trigger Data] Trigger data has no member event_ciphertext\n");
      printf("[Debug] Response: %s", res.c_str());
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
    //trigger_response_t *resp = (trigger_response_t *)trigger_data_buf;
    memcpy(&resp->tag, tag_bin, tag_sz);
    memcpy(&resp->iv, enc_nonce_bin, enc_nonce_sz);
    memcpy(&resp->ciphertext, ciphertext_bin, ciphertext_sz);
    resp->ciphertext_size = ciphertext_sz;

    *trigger_data_sz =  sizeof(trigger_response_t) + ciphertext_sz * sizeof(char);
    auto get_trigger_data_end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> ms_double = get_trigger_data_end_time - get_trigger_data_start_time;
    
    std::cout << "[get_trigger_data] Exec time: " << ms_double.count() << "ms\n";
    enclave_start = std::chrono::high_resolution_clock::now();
    return (void *)resp;
}

void terminate_connection(int32_t fd) {
	close(fd);
}


//Global map from action_id to OAuth token for the user
std::map<std::string, std::string> action_tokens;

std::string get_action_token(std::string &action_id) {
   std::string s;
   if (action_tokens.find(action_id) == action_tokens.end()) {
      return s;
   }

   return action_tokens[action_id];
}

void register_action_token(std::string &action_id, std::string &token) {
  action_tokens[action_id] = token;
}

char *construct_request_json(char *action_id, std::string &oauth_token, char *params, std::string &ciphertext, std::string &tag, std::string &iv) {
    size_t len_result = strlen(action_id) + oauth_token.size() + strlen(params) + ciphertext.size() + tag.size() + iv.size() + 100;
    char *result = (char *)malloc(len_result * sizeof(char));
    memset(result, 0, len_result);

    snprintf(result, len_result, "{\"action_id\":\"%s\",\"oauth_token\":\"%s\", \"params\": \"\", \"ciphertext\": \"%s\", \"tag\": \"%s\", \"iv\": \"%s\"}", action_id, oauth_token.c_str(), ciphertext.c_str(), tag.c_str(), iv.c_str());
    return result;
}

std::string bytes_to_string(char *bytes, int length) {
    std::stringstream ss;
    ss << std::hex;

    for(int i = 0; i < length; ++i)
      ss << std::setw(2) << std::setfill('0') << (int)bytes[i];

    return ss.str();
}

int32_t send_action_data(action_data_t *data) {
  enclave_end = std::chrono::high_resolution_clock::now();

  actions_sent.release();
  
  rapidjson::Document action_params;
  if (action_params.Parse(data->action_params).HasParseError()) {
      printf("[send_action_data] action params parse error");
      return -1;
  }

  if (!action_params.HasMember("action_url")) {
      printf("[Action Data] Action params has no member tag\n");
      return -1;
  }

  if (!action_params.HasMember("action_id")) {
      printf("[Action Data] Action params has no action_id\n");
      return -1;
  }

  http::Request request{action_params["action_url"].GetString()};
  std::string action_id(action_params["action_id"].GetString());

  std::string ciphertext = bytes_to_string(data->ciphertext, data->ciphertext_size);

  std::string tag = bytes_to_string(data->tag, 16);
  std::string iv = bytes_to_string(data->iv, 16);

  std::string action_token = get_action_token(action_id);
  const std::string body = construct_request_json((char *)action_params["action_id"].GetString(), action_token, data->action_params, ciphertext, tag, iv);

  const auto response = request.send("POST", body, {
        {"Content-Type", "application/json"}
  });
   
  auto res = std::string{response.body.begin(), response.body.end()};
  
  rapidjson::Document doc;
  if (doc.Parse(res.c_str()).HasParseError()) {
    printf("[Action Data] Error Parsing Response JSON: %s\n", res.c_str());
  }

  if (!doc.HasMember("error")) {
      printf("[Action Data] Action response has no error field\n");
      return -1;
  }

  std::string resp(doc["error"].GetString());
  if (resp == "success") {
    return 0;
  }

  printf("[Action Response] Error Response\n");
  return -1;
}

void listener_function(int port) {
    crow::SimpleApp app;
    CROW_ROUTE(app, "/event_notify/").methods("POST"_method) ([] () {
        //Lock trigger_data_lock
        //std::cout << "Got event notification" << std::endl;
        //int prev_sent = trigger_event_action_data_sent;
        //std::lock(trigger_data_lock);
        //trigger_data_lock.lock();
        //  trigger_event_notified++;
        //trigger_data_lock.unlock();
        events_notified.release();

        actions_sent.acquire();
        std::chrono::duration<double, std::milli> ms_double = enclave_end - enclave_start;
        std::cout << "Enclave Exec time: " << ms_double.count() << "ms\n";
        return "success";
    });
    std::cout << "Starting notification server " << std::endl;
    //app.port(port).multithreaded().run();
    app.port(port).concurrency(1).run();
}


int main(int argc, char** argv)
{

    using std::chrono::high_resolution_clock;
    using std::chrono::duration_cast;
    using std::chrono::duration;
    using std::chrono::milliseconds;
  	/* Wait for network connection */
  	// init_network_wait();

  	//printf("[EH] Got connection from remote client\n");

    std::string action_token = "5f8eac3ef18e9c3c40a65f1958620ed2d192acd97d0d7f1ffc43b63a9f2bc14a0724c0884b03cd6ed52f68a71581b4dfcc7cafe15f4e334a9baedde47fff5378";
    std::string action_id = "0";

    register_action_token(action_id, action_token);

    // Spawning listener thread
    std::thread listener_thread(listener_function, 80);

    // Enclave stuff begins --> shazam!
    // Maybe ignore the decryption piece for now
    populate_default(&rule);
    event_loop(&rule, 1000000000);


    
    listener_thread.join();
  
  	return 0;
}
