#include "base.h"
#include <stdio.h>
int main()
{
    char a[] = "BCasdfsadfsdfasfsadfasdfadsf";
    size_t enc_data_len;
    char *enc = base64_encode(a, strlen(a), &enc_data_len);
    char *dec = base64_decode(enc, &enc_data_len);
    printf("%s", dec);
    return 0;
}