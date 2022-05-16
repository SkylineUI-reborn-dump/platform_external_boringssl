/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cutils/sockets.h>
#include <openssl/ctrdrbg.h>

static const int kNumRequestsPerReseed = 256;

static int readfull(int fd, uint8_t *out, size_t out_len) {
  size_t done = 0;

  while (done < out_len) {
    ssize_t n;
    do {
      n = read(fd, out + done, out_len - done);
    } while (n == -1 && errno == EINTR);

    if (n <= 0) {
      return 0;
    }
    done += (size_t)n;
  }

  return 1;
}

static void write_handle_eintr(int fd, const uint8_t *data, size_t data_len) {
  ssize_t n;
  do {
    n = write(fd, data, data_len);
  } while (n == -1 && errno == EINTR);
}

int main(int argc, char **argv) {
  const char *random_path = "/dev/hw_random";
  if (argc == 2) {
    random_path = argv[1];
  }

  const int hwrand_fd = open(random_path, O_RDONLY);
  if (hwrand_fd < 0) {
    perror("prng_seeder: open /dev/hw_random");
    return 1;
  }

  const int sock_fd = android_get_control_socket("prng_seeder");
  if (sock_fd < 0) {
    perror("prng_seeder: android_get_control_socket");
    return 2;
  }

  signal(SIGPIPE, SIG_IGN);

  uint8_t seed[CTR_DRBG_ENTROPY_LEN];
  if (!readfull(hwrand_fd, seed, sizeof(seed))) {
    perror("prng_seeder: readfull");
    return 9;
  }

  CTR_DRBG_STATE *drbg = CTR_DRBG_new();
  if (!CTR_DRBG_init(drbg, seed, NULL, 0)) {
    perror("prng_seeder: CTR_DRBG_init");
    return 10;
  }

  int requests_since_reseed = 0;

  for (;;) {
    const int client_sock = accept(sock_fd, NULL, NULL);
    if (client_sock < 0) {
      if (errno == EINTR) {
        continue;
      }

      perror("prng_seeder: accept");
      return 11;
    }

    uint8_t seed_for_client[496];
    if (!CTR_DRBG_generate(drbg, seed_for_client, sizeof(seed_for_client), NULL, 0)) {
      perror("prng_seeder: CTR_DRBG_generate");
      return 12;
    }

    write_handle_eintr(client_sock, seed_for_client, sizeof(seed_for_client));
    close(client_sock);

    requests_since_reseed++;
    if (requests_since_reseed >= kNumRequestsPerReseed) {
      if (!readfull(hwrand_fd, seed, sizeof(seed))) {
        perror("prng_seeder: readfull");
        return 9;
      }

      if (!CTR_DRBG_reseed(drbg, seed, NULL, 0)) {
        perror("prng_seeder: CTR_DRBG_reseed");
        return 11;
      }

      requests_since_reseed = 0;
    }
  }
}
