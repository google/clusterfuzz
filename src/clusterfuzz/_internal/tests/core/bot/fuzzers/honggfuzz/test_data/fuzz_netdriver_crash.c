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

void data_handler(char *data, int len) {
  if (len > 0 && data[0] == 'B')
  {
    char *a = (char*)malloc(1);
    free(a);
    *a = 'A';
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
