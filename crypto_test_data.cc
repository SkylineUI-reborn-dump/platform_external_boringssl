/* Copyright (c) 2017, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdlib.h>
#include <stdio.h>

#include <algorithm>
#include <string>

/* Silence -Wmissing-declarations. */
std::string GetTestData(const char *path);

std::string GetTestData(const char *path) {
  std::string path_str(getenv("BORINGSSL_TEST_DATA_PREFIX"));
  path_str += path;

  FILE *file = fopen(path_str.c_str(), "r");
  if (!file) {
    fprintf(stderr, "Could not open file: %s.\n", path_str.c_str());
    perror("fopen");
    abort();
  }

  std::string ret;
  char buf[2048];
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), file);
    ret.append(buf, n);
    if (feof(file)) {
      break;
    }
    if (ferror(file)) {
      fprintf(stderr, "Error reading from %s\n", path_str.c_str());
      perror("fread");
      abort();
    }
  }

  fclose(file);
  return ret;
}
