// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// This test must be compiled with libhfnetdriver.a, e.g.:
// hfuzz-clang $CFLAGS $HONGGFUZZ_HOME/libhfnetdriver/libhfnetdriver.a fuzz_netdriver.c

// If the server receives a message the starts with "BOOM" characters then a
// stack-based buffer overflow will happen in this function.
void data_handler(char *data, int len) {
  char buf[3];

  // A few conditions to give it a bit more coverage.
  if (len == 0 || len == 1 || len == 2 || len == 4) {
    return;
  }
  if (data[0] == 'B' &&
      data[1] == 'O' &&
      data[2] == 'O' &&
      data[3] == 'M')
  {
    printf("Overflow about to happen\n");
    memcpy(buf, data, len);
    printf("%s\n", buf);
  }
}

void handle_socket_communication(int sock) {
  char data[1024];
  int packet_num = 0;
  while (1) {
    int len = read(sock, data, 1024);
    data_handler(data, len);

    packet_num++;
    if (packet_num > 20) {
      return;
    }
  }
}

HFND_FUZZING_ENTRY_FUNCTION(int argc, char *argv[]) {
  int sockfd, curr_sockfd;
  socklen_t addr_len;
  struct sockaddr_in serv_addr = (struct sockaddr_in) {0};
  struct sockaddr_in peer_addr = (struct sockaddr_in) {0};

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    printf("socket creation failed\n");
    exit(1);
  }

  int optval = 1;
  int r = setsockopt(sockfd,
                     SOL_SOCKET,
                     SO_REUSEPORT,
                     (const char *)&optval,
                     sizeof(optval));
  if (r < 0) {
    printf("setsockopt failed\n");
    exit(1);
  }

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(8666);

  if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("Error binding socket\n");
    exit(1);
  }

  listen(sockfd, 5);
  addr_len = sizeof(peer_addr);

  while(1) {
    curr_sockfd = accept(sockfd, (struct sockaddr *)&peer_addr, &addr_len);
    if (curr_sockfd < 0) {
      printf("Error accepting socket\n");
      exit(1);
    }
    handle_socket_communication(curr_sockfd);
    shutdown(curr_sockfd, 2);
    close(curr_sockfd);
  }
}
