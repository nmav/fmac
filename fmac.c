/*
 * fmac.c file authenticator
 *
 * Copyright (C) 2008 Gennet S.A.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

/* TODO: work with streams
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define MIN(x,y) ((x)<(y)?(x):(y))

static int verify_file(const char * filename);
static int update_file(const char * filename);
static int _gen_key_s2k_simple(void *keyword, int key_size,
				       void *password, int plen);

/* This is a modification of nandwrite to upgrade solos firmware
 */

#define PROGRAM "fmac"
#define PVERSION "0.1"

#define MODE_VERIFY 1
#define MODE_STORE 0


static void display_help(void)
{
    printf
	("Usage: To store auth data: %s -s -p [PASSWORD] [FILE]\n", PROGRAM);
    printf
	("Usage: To verify auth data and extract file: %s -v -p [PASSWORD] [FILE]\n", PROGRAM);
    printf
	("Usage: To verify auth data and keep auth file: %s -k -v -p [PASSWORD] [FILE]\n", PROGRAM);
    printf
	("Usage: To verify auth data and continue on failure: %s -c -v -p [PASSWORD] [FILE]\n", PROGRAM);
}

static void display_version(void)
{
    printf(PROGRAM " " PVERSION "\n"
	   "\n"
	   "Copyright (C) 2008 Gennet S.A. \n"
	   "\n"
	   PROGRAM " comes with NO WARRANTY\n"
	   "to the extent permitted by law.\n"
	   "\n"
	   "You may redistribute copies of " PROGRAM "\n"
	   "under the terms of the GNU General Public Licence.\n"
	   "See the file `COPYING' for more information.\n");
}

static uint8_t gkey[128];
static int gkey_size = 0;
static int mode = 0; /* 0 to store and 1 to verify */
static char* files[256];
static int keep = 0;
static int abort_on_fail = 1;

static void process_options(int argc, char *argv[])
{
    int opt, i;
    char password[128];
    static const char *short_options = "ckhvsp:";
    
    password[0] = password[sizeof(password)-1] = 0;

    while ((opt =
	    getopt(argc, argv, short_options)) >= 0) {
	switch (opt) {
	case 'p':
	    strncpy(password, optarg, sizeof(password)-1);
	    break;
	case '?':
	case 'h':
	    display_help();
            exit(0);
	    break;
	case 'v':
	    mode = MODE_VERIFY;
	    break;
	case 'c':
	    abort_on_fail = 0;
	    break;
	case 'k':
	    keep = 1;
	    break;
	case 's':
	    mode = MODE_STORE;
	    break;
	}
    }

    if (optind >= argc) {
        display_help();
        exit(1);
    }
    
    if (argc - optind >= sizeof(files)/sizeof(char*)) {
        fprintf(stderr, "Too many files specified\n");
        exit(1);
    }

    for (i=0;i<argc - optind;i++) {
        files[i] = argv[optind+i];
    }
    files[i] = 0;
                                                               
    if (password[0] == 0) {
        char* p = getpass("Enter password:");
        if (p == NULL) {
            fprintf(stderr, "You need to specify a password\n");
            exit(1);
        }
        strncpy( password, p, sizeof(password)-1);
    }

    gkey_size = 16;
    if (_gen_key_s2k_simple(gkey, gkey_size,
				       password, strlen(password)) < 0) {
        fprintf(stderr, "Error generating key\n");
        exit(1);
    }

}

#define SHA1_SIZE 20
#define MD5_SIZE 16

#define MAGIC 0xAFED
#define AVERSION 0x01

typedef struct auth_info_st {
    uint16_t magic;
    uint8_t version;
    uint8_t hmac_sha1[SHA1_SIZE];
    uint8_t digest_md5[MD5_SIZE];
} __attribute__((packed)) auth_info_t;

/*
 * Main program
 */
int main(int argc, char **argv)
{
int i=0;
int ret = 0;

    process_options(argc, argv);

    do {
    
        if (mode == MODE_VERIFY) {
            if (verify_file( files[i]) < 0)
                ret = 1;
        } else {
            if (update_file( files[i]) < 0)
                ret = 1;
        }
        i++;    
    } while(files[i] != 0);


    return ret;
}

static char buffer[2048];

static int mycopy( const char* src, const char* dst)
{
    FILE* s,* d;
    int ret = 0;
    
    if (strcmp( src, dst) == 0) {
        /* no need to copy anything */
        return 0;
    }
    
    s = d = NULL;
    
    s = fopen( src, "r");
    if (s == NULL) return -1;

    d = fopen( dst, "w");
    if (d == NULL) {
        ret = -1;
        goto error;
    }
    
    do {
        ret = fread( buffer, 1, sizeof(buffer), s);

        if (ret > 0) {        
            if (fwrite( buffer, 1, ret, d) != ret) {
                ret = -1;
                goto error;
            }
        }
    } while(ret > 0);

error:
    if (d) fclose(d);    
    if (s) fclose(s);    
    return ret;
}

/* Key generation using OpenPGP Simple S2K algorithm - taken from mhash */
static int _gen_key_s2k_simple(void *keyword, int key_size,
				       void *password, int plen)
{
	uint8_t* key;
	uint8_t digest[MD5_SIZE];
	char null = '\0';
	uint32_t i,j, times, total;
        MD5_CTX td;
	uint32_t block_size = MD5_SIZE;

	/* This should never happen, so naturally it is bound to. */

	if (block_size == 0)
	{
		return(-1);
	}

	times = key_size / block_size;

	if (key_size % block_size != 0)
	{
		times++;
	}

	total = times * block_size;

	key = malloc(total);

	if (key == NULL)
	{
		return(-1); /* or what? */
	}

	memset(key, 0, total);

	for (i = 0; i < times; i++) {
                MD5_Init(&td);
		
		for (j = 0; j < i; j++)
		{
                      MD5_Update(&td, &null, 1);
		}
                MD5_Update(&td, password, plen);
                MD5_Final(digest, &td);

		memcpy(&key[i * block_size], digest, block_size);
	}
	memcpy(keyword, key, key_size);
	memset(key, 0, key_size);
	free(key);
	return(0);
}

static int verify_file(const char * filename)
{
    FILE * fd = NULL;
    auth_info_t info;
    int ret = 0, ret2 = 0;
    off_t cur;
    HMAC_CTX ctx1;
    MD5_CTX ctx2;
    unsigned int d_len;
    char md5[MD5_SIZE];
    char sha1[SHA1_SIZE];
    char new_file[strlen(filename)];
    char * p;
    size_t total = 0;
    
    strcpy(new_file, filename);
    
    p = strstr( new_file, ".auth");
    if (p != NULL) {
        *p = 0; /* remove trailing .auth */
    }
    
    fd = fopen( filename, "r");
    if (fd == NULL) {
        fprintf(stderr, "Error opening filename '%s'\n", filename);
        return -1;
    }
    
    if (fseek( fd, -sizeof(auth_info_t), SEEK_END) == -1) {
        fprintf(stderr, "Error seeking in '%s'\n", filename);
        ret = -1;
        goto error;
    }
    
    cur = ftell(fd);
    
    if (fread( &info, 1, sizeof(auth_info_t), fd) < sizeof(auth_info_t)) {
        fprintf(stderr, "Error reading data from '%s'\n", filename);
        ret = -1;
        goto error;
    }
    
    if (info.version != AVERSION || info.magic != MAGIC) {
        fprintf(stderr, "Version or magic mismatch!\n");
        fprintf(stderr, "Found version %d and magic %x\n", info.version, info.magic);
        ret = -1;
        goto error;
    }
    
    if (fseek( fd, 0, SEEK_SET) == -1) {
        fprintf(stderr, "Error seeking in '%s'\n", filename);
        ret = -1;
        goto error;
    }

    HMAC_CTX_init(&ctx1);
    HMAC_Init(&ctx1, gkey, gkey_size, EVP_sha1());
    
    MD5_Init(&ctx2);
    
    do {
        ret = fread( buffer, 1, sizeof(buffer), fd);
        
        if (ret > 0) {
            total+=ret;
            if (total >= cur) {
                ret -= total - cur;
                if (ret > 0) {
                    HMAC_Update(&ctx1, (void*)buffer, ret);
                    MD5_Update(&ctx2, (void*)buffer, ret);
                }
                break;
            }
            
            HMAC_Update(&ctx1, (void*)buffer, ret);
            MD5_Update(&ctx2, (void*)buffer, ret);
        }
    } while(ret > 0);

    d_len = sizeof( sha1);
    HMAC_Final(&ctx1, (void*)sha1, &d_len);
    MD5_Final((void*)md5, &ctx2);
    
    ret = 0;
    
    if (memcmp( md5, info.digest_md5, sizeof(md5)) != 0) {
        fprintf(stderr, "MD5 Checksum failure!\n");
        ret = -1;
    }
    
    if (memcmp( sha1, info.hmac_sha1, sizeof(sha1)) != 0) {
        fprintf(stderr, "SHA1 Authentication code failure!\n");
        if (ret == 0) fprintf(stderr, "Password given must not be correct, or file has been tampered with!\n");
        ret = -1;
    }
    
    fclose(fd);
    fd = NULL;

    if ( ret == 0 || abort_on_fail == 0) {    
        if (ret == 0 && keep == 0) {
            ret2 = rename(filename, new_file);
        } else {
            ret2 = mycopy(filename, new_file);
        }
    
        if (ret2 == -1) {
            fprintf( stderr, "Could not rename file!\n");
        }
    
        if (truncate(new_file, cur) == -1) {
            fprintf(stderr, "Cannot truncate file '%s'\n", new_file);
            ret = -1;
            goto error;
        }
    }
        
    error:
    if (fd) fclose(fd);
    return ret;
}

static int update_file(const char * filename)
{
    FILE * fd = NULL;
    auth_info_t info;
    int ret = 0;
    HMAC_CTX ctx1;
    MD5_CTX ctx2;
    char new_file[ strlen(filename)+sizeof(".auth")];
    unsigned int d_len;
    
    strcpy( new_file, filename);
    strcat( new_file, ".auth");
    
    fd = fopen( filename, "r");
    if (fd == NULL) {
        fprintf(stderr, "Error opening filename '%s'\n", filename);
        return -1;
    }

    fclose(fd);
    fd = fopen( filename, "a+");
    if (fd == NULL) {
        fprintf(stderr, "Error opening filename '%s'\n", filename);
        return -1;
    }
    
    if (fseek( fd, 0, SEEK_SET) == -1) {
        fprintf(stderr, "Error seeking in '%s'\n", filename);
        ret = -1;
        goto error;
    }

    /* start verifying */
    HMAC_CTX_init(&ctx1);
    HMAC_Init(&ctx1, gkey, gkey_size, EVP_sha1());
    
    MD5_Init(&ctx2);
    
    do {
        ret = fread( buffer, 1, sizeof(buffer), fd);
        if (ret > 0) {
            HMAC_Update(&ctx1, (void*)buffer, ret);
            MD5_Update(&ctx2, (void*)buffer, ret);
        }
    } while(ret > 0);
    
    d_len = sizeof(info.hmac_sha1);
    HMAC_Final(&ctx1, info.hmac_sha1, &d_len);
    MD5_Final(info.digest_md5, &ctx2);
    
    info.magic = MAGIC;
    info.version = AVERSION;

    if (fwrite( &info, 1, sizeof(auth_info_t), fd) < sizeof(auth_info_t)) {
        fprintf(stderr, "Error writing data from '%s'\n", filename);
        ret = -1;
        goto error;
    }
    
    fclose(fd);
    fd = NULL;
    
    if (keep == 0) {
        ret = rename( filename, new_file);
    } else {
        ret = mycopy( filename, new_file);
    }
    
    if (ret == -1) {
        fprintf( stderr, "Could not rename file!\n");
    }

 error:
    if (fd) fclose(fd);
    return ret;
}
