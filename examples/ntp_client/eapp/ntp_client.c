#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "edge_wrapper.h"
#include "encl_message.h"
#include "app/syscall.h"

#define NTP_TIMESTAMP_DELTA 2208988800ull

#define STARFIVE_VISIONFIVE


#if !defined(STARFIVE_VISIONFIVE)
#define TIMEBASE_FREQ 10000000
#else
#define TIMEBASE_FREQ 6250000
#endif

static uint64_t get_ticks()
{
  uint64_t n;
  __asm__ __volatile__("rdtime %0" : "=r"(n));
  return n;
}

typedef struct
{
    uint8_t li_vn_mode;      // Eight bits. li, vn, and mode.
                             // li.   Two bits.   Leap indicator.
                             // vn.   Three bits. Version number of the protocol.
                             // mode. Three bits. Client will pick mode 3 for client.

    uint8_t stratum;         // Eight bits. Stratum level of the local clock.
    uint8_t poll;            // Eight bits. Maximum interval between successive messages.
    uint8_t precision;       // Eight bits. Precision of the local clock.

    uint32_t rootDelay;      // 32 bits. Total round trip delay time.
    uint32_t rootDispersion; // 32 bits. Max error aloud from primary clock source.
    uint32_t refId;          // 32 bits. Reference clock identifier.

    uint32_t refTm_s;        // 32 bits. Reference time-stamp seconds.
    uint32_t refTm_f;        // 32 bits. Reference time-stamp fraction of a second.

    uint32_t origTm_s;       // 32 bits. Originate time-stamp seconds.
    uint32_t origTm_f;       // 32 bits. Originate time-stamp fraction of a second.

    uint32_t rxTm_s;         // 32 bits. Received time-stamp seconds.
    uint32_t rxTm_f;         // 32 bits. Received time-stamp fraction of a second.

    uint32_t txTm_s;         // 32 bits and the most important field the client cares about. Transmit time-stamp seconds.
    uint32_t txTm_f;         // 32 bits. Transmit time-stamp fraction of a second.

} ntp_packet;              // Total: 384 bits or 48 bytes.

int main()
{
  char *ntp_server = "time.cloudflare.com";
  int ntp_port = 123;
  int host_len = strlen(ntp_server);
  char printf_buffer[100];

  ntp_packet packet = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  memset( &packet, 0, sizeof( ntp_packet ) );

  *( ( char * ) &packet + 0 ) = 0x1b;


  connection_data_t *data_send = (connection_data_t *) malloc(sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
  memset(data_send, 0, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));
  data_send->portnumber = ntp_port;
  memcpy(data_send->hostname, ntp_server, host_len);
  int fpSendRecv = ocall_init_connection_udp(data_send, sizeof(connection_data_t) + (host_len + 1) * sizeof(unsigned char));

  network_send_data_t *data_recv = (network_send_data_t *) malloc(sizeof(network_send_data_t) + sizeof(ntp_packet));
	data_recv->fd = fpSendRecv;
	data_recv->data_len = sizeof(ntp_packet);
	memcpy(data_recv->data, &packet, sizeof(ntp_packet));

  
  uint64_t start_time = get_ticks();

  int ret = (int) ocall_send_buffer_fd(data_recv, sizeof(network_send_data_t) + sizeof(ntp_packet));

  if (ret <= 0) {
    snprintf(printf_buffer, 100, "NTP packet send failed!\n");
    ocall_print_buffer(printf_buffer);
    return -1;
  }

  struct edge_data msg;
  network_recv_request_t req;
	req.fd = fpSendRecv;
	req.req_size = sizeof(packet);

  ret = (int) ocall_recv_buffer_fd(&req, sizeof(network_recv_request_t), &msg);
	if (ret > 0 && msg.size == sizeof(ntp_packet)) {
		copy_from_shared(&packet, msg.offset, msg.size);
  } else {
    //printf("Receive of NTP packet failed!\n");
    snprintf(printf_buffer, 100, "Receive of NTP packet failed!\n");
    ocall_print_buffer(printf_buffer);
    return -1;
  }

  uint64_t time_taken = (get_ticks() - start_time);

  packet.txTm_s = ntohl(packet.txTm_s); // Time-stamp seconds.
  packet.txTm_f = ntohl(packet.txTm_f); // Time-stamp fraction of a second.


  time_t txTm = (time_t) ( packet.txTm_s - NTP_TIMESTAMP_DELTA );

  //printf("TIME since UNIX EPOCH: %lu\nTime_taken_ticks: %lu\n", txTm, time_taken);
  snprintf(printf_buffer, 100, "TIME since UNIX EPOCH: %lu\nTime_taken_ticks: %lu\n", txTm, time_taken);
  ocall_print_buffer(printf_buffer);

  unsigned long time_rval = runtime_set_unix_time(txTm);
  //printf("set_time return val: %lu\n", time_rval);
  snprintf(printf_buffer, 100, "set_time return val: %lu\n", time_rval);
  ocall_print_buffer(printf_buffer);

  uint64_t current_time = get_ticks();
  while (((get_ticks() - current_time)/TIMEBASE_FREQ) < 6) {
     //do nothing for 6 seconds
  }

  //printf("get_unix_time: %lu\n", runtime_get_unix_time());
  time_t retrieved_time = runtime_get_unix_time();
  snprintf(printf_buffer, 100, "get_unix_time: %lu\n", retrieved_time);
  ocall_print_buffer(printf_buffer);

  //setenv("TZ", "UTC+0UTC+0,M3.2.0/2,M11.1.0/2", 1);
  struct tm *time = gmtime(( const time_t* ) &retrieved_time);

  //printf("Time: year: %d, month: %d, day: %d, hour: %d\n", time->tm_year, time->tm_mon, time->tm_mday, time->tm_hour);
  snprintf(printf_buffer, 100, "Time: year: %d, month: %d, day: %d, hour: %d\n", time->tm_year, time->tm_mon, time->tm_mday, time->tm_hour);
  ocall_print_buffer(printf_buffer);

  return 0;
}

