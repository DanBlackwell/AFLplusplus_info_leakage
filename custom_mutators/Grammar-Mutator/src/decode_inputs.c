#include "json.h"
#include "base64.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PUBLIC_KEY "PUBLIC"
#define SECRET_KEY "SECRET"

/* Parses a testcase_buf to extract pointers and lengths for public and secret
 * segments of the testcase input. public_input and secret_input are malloced */

void find_public_and_secret_inputs(const char *testcase_buf, uint32_t testcase_len,
                                   uint8_t **public_input, uint32_t *public_len,
                                   uint8_t **secret_input, uint32_t *secret_len) {

  char *raw_public = NULL, *raw_secret = NULL;

  json_char *json = (json_char *)testcase_buf;
  json_value *value = json_parse(json, testcase_len);

  switch (value->type) {
    case json_object: {
      uint32_t len = value->u.object.length;

      for (uint32_t i = 0; i < len; i++) {

        char *name = value->u.object.values[i].name;

        json_type type = value->u.object.values[i].value->type;
        if (type != json_string) {
          printf("Saw json field %s that was not a string (type: %d)\n", name, type);
          exit(1);
          continue;
        }

        char *str = value->u.object.values[i].value->u.string.ptr;
        uint32_t length = value->u.object.values[i].value->u.string.length;

        if (!strcmp(name, PUBLIC_KEY)) {
          raw_public = str;
        } else if (!strcmp(name, SECRET_KEY)) {
          raw_secret = str;
        } else {
          printf("saw json string { \"%s\": \"%.*s\" }\n", name, length, str);
          exit(1);
        }

      }
      break;
    }
    default:
      printf("JSON: %*.s was not a json-object\n", testcase_len, testcase_buf);
      exit(1);
  }

  if (!raw_public) {
    printf("Failed to find PUBLIC in json: %.*s\n", testcase_len, testcase_buf);
    exit(1);
  }

  if (!raw_secret) {
    printf("Failed to find SECRET in json: %.*s\n", testcase_len, testcase_buf);
    exit(1);
  }

  *public_len = Base64decode_len(raw_public);
  *public_input = (uint8_t *)malloc(*public_len);
  *public_len = Base64decode((char *)*public_input, raw_public);

  *secret_len = Base64decode_len(raw_secret);
  *secret_input = (uint8_t *)malloc(*secret_len);
  *secret_len = Base64decode((char *)*secret_input, raw_secret);

  json_value_free(value);
}
