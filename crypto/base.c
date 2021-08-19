#include "base.h"

static char b64_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                            'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                            'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                            'w', 'x', 'y', 'z', '0', '1', '2', '3',
                            '4', '5', '6', '7', '8', '9', '+', '/'
                            };

char *base64_encode(const char* data, size_t len, size_t* enc_data_len)
{
    *enc_data_len = ((3 - len % 3) + len) / 6 * 8;
    char *out = (char *)calloc(1, *enc_data_len + 1);
    if(out == NULL)
        return out;
    
    for(int i = 0, j = 0; i < len; i += 3, j += 4)
    {
        int x = 0;
        x = data[i];
        x = i + 1 < len? x << 8 | data[i + 1] : x << 8;
        x = i + 2 < len? x << 8 | data[i + 2] : x << 8;

        out[j] = b64_table[(x >> 18) & 0x3F];
		out[j + 1] = b64_table[(x >> 12) & 0x3F];

        if(i + 1 < len){
            out[j + 2] = b64_table[(x >> 6) & 0x3F];
        }
        else{
            out[j + 2] = '=';
        }
        if(i + 2 < len){
            out[j + 3] = b64_table[x & 0x3F];
        }
        else{
            out[j + 3] = '=';
        }
    }

    return out;
}

static int get_b64_index(char x)
{
    if(x == '=')
        return 0;
    for(int i = 0; i < 64; i++)
    {
        if(b64_table[i] == x)
            return i;
    }

    return -1;
}


char *base64_decode(const char* data, size_t* dec_data_len)
{
    size_t len = strlen(data);
    assert(len % 4 == 0);
    *dec_data_len = (len * 3) / 4;

    if(data[len - 1] == '=')
        *dec_data_len -= 1;
    if(data[len - 2] == '=')
        *dec_data_len -= 1;

    char *out = calloc(1, *dec_data_len + 2);
    if(out == NULL)
        return NULL;

    for (int i = 0, j = 0; i < len; i += 4, j += 3)
    {
        int x = 0;
        int x_1 = get_b64_index(data[i]);
        int x_2 = get_b64_index(data[i + 1]);
        int x_3 = get_b64_index(data[i + 2]);
        int x_4 = get_b64_index(data[i + 3]);
        if(x_1 == -1 || x_2 == -1 || x_3 == -1 || x_4 == -1)
        {    
            free(out);
            return NULL;    
        }

        x = (x_1 << 18) | (x_2 << 12) | (x_3 << 6) | x_4;

        //memcpy(&out[j], &x, 3);
        //char tmp = out[j];
        //out[j] = out[j + 2];
        //out[j + 2] = tmp;

        out[j] = (x >> 16) & 0xff;
        out[j + 1] = (x >> 8) & 0xff;
        out[j + 2] = x & 0xff;
    }

    return out;

}

