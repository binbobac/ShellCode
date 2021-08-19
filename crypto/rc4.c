void rc4_init(unsigned char* s, unsigned char* key, int len)
{
    unsigned char k[256];
    for (int i = 0; i < 256; i++)
    {
        s[i] = i;
        k[i] = key[i%len];
    }

    for(int i = 0; i < len; i++)
    {
        int j = (i + s[i] + k[i]) % 256;
        unsigned char tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

/*加解密*/
void rc4_crypt(unsigned char* s,unsigned char* data,int len)
{
    int i=0,j=0,t=0;
    int k=0;
    unsigned char tmp;
    for(k=0; k < len; k++)
    {
        i=(i+1)%256;
        j=(j+s[i])%256;
        tmp=s[i];
        s[i]=s[j];
        s[j]=tmp;
        t=(s[i]+s[j])%256;
        data[k]^=s[t];
    }
}