#ifndef __BASE_H__
#define __BASE_H__

#include <string.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

char *base64_decode(const char* data, size_t* dec_data_len);
char *base64_encode(const char* data, size_t len, size_t* enc_data_len);

#endif