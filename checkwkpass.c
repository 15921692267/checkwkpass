/*
检查 mail 密码是否是弱密码

命令行：./checkwkpass wk_pass.txt email.pass.txt

其中：
wk_pass.txt是弱密码文件，每行一个
email.pass.txt是邮件用户 和 加密后的密码，中间空格 或 TAB 隔开

支持的加密密码格式有：
如果密码是 {enc1}xxx，crypt('密码', 'xxx')
如果密码是 {ecn2}xxxx，md5sum('密码')
如果密码是 {ecn8}xxxx，把xxxx decode64转成2进制，然后直接dumphex

为了提高速度，预先将弱密码读入，并生成md5，

将来碰到enc2格式密码时，直接查找hash即可完成验证过程，速度为O(1)
其他格式的密码，则要穷举

*/

#include <openssl/md5.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <ctype.h>

//#define DEBUG 1

#define MY_LEN 1024

#include "uthash.h"

struct pass_struct {
	char md5[33];
	char *pass;
	UT_hash_handle hh;	/* makes this structure hashable */
};

struct pass_struct *all_pass = NULL;

const char *hexDigits = "0123456789abcdef";

char *md5_sum(char *pass)
{
	unsigned char result[17];
	static char md5_r[33];
	char *dest = md5_r;
	int i;

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, pass, strlen(pass));
	MD5_Final(result, &ctx);
	for (i = 0; i < 16; i++) {
		*dest++ = hexDigits[result[i] >> 4];
		*dest++ = hexDigits[result[i] & 0x0F];
	}
	*dest = 0;
	return md5_r;
}

void add_pass(char *pass)
{
	struct pass_struct *s;
	char *md5_r;
	md5_r = md5_sum(pass);

#ifdef DEBUG
	printf("pass: %s, md5: %s ", pass, md5_r);
#endif

	// 先查找是否已经加过了
	HASH_FIND_STR(all_pass, md5_r, s);

	if (s) {
#ifdef DEBUG
		printf("duplicated\n");
#endif
		return;
	}

	s = malloc(sizeof(struct pass_struct));
	if (s == NULL) {
		printf("malloc error, exit\n");
		exit(-1);
	}
	s->pass = malloc(strlen(pass) + 1);
	if (s->pass == NULL) {
		printf("malloc error, exit\n");
		exit(-1);
	}
	strcpy(s->pass, pass);
	strcpy(s->md5, md5_r);
	HASH_ADD_STR(all_pass, md5, s);
#ifdef DEBUG
	printf("added\n");
#endif
}

// enc1, crypt
void checkenc1(const char *email, const char *salt)
{
	char *p;
	struct pass_struct *s;

	for (s = all_pass; s != NULL; s = s->hh.next) {

		p = crypt(s->pass, salt + 6);
#ifdef DEBUG
		printf("enc1, key: %s, salt: %s, crypt: %s\n", s->pass, salt, p);
#endif
		if (strcmp(salt + 6, p) == 0) {
			printf("WK %s %s %s\n", email, s->pass, salt);
			return;
		}
	}
}

// enc2, md5
void checkenc2(const char *email, const char *salt)
{
	struct pass_struct *s;

	HASH_FIND_STR(all_pass, salt + 6, s);
	if (s) {
		printf("WK %s %s %s\n", email, s->pass, salt);
	}
}

unsigned char tohex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	exit(-1);
}

unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char inalphabet[256], decoder[256];

int table_inited = 0;

int decodebase64(unsigned char *s)
{

	int i, bits, c, char_count, errors = 0, len = 0;
	unsigned char *out, *p, *si;

	out = malloc(strlen((const char *)s) + 1);
	if (out == NULL)
		return 0;
	p = out;

	if (table_inited == 0) {
		table_inited = 1;
		for (i = (sizeof alphabet) - 1; i >= 0; i--) {
			inalphabet[alphabet[i]] = 1;
			decoder[alphabet[i]] = i;
		}
	}

	char_count = 0;
	bits = 0;
	si = s;
	while (*si) {
		c = *si;
		if (c == '=')
			break;
		si++;
		if (c > 255 || !inalphabet[c])
			continue;
		bits += decoder[c];
		char_count++;
		if (char_count == 4) {
			*p = ((bits >> 16));
			p++;
			*p = (((bits >> 8) & 0xff));
			p++;
			*p = ((bits & 0xff));
			p++;
			bits = 0;
			char_count = 0;
			len += 3;
		} else {
			bits <<= 6;
		}
	}
	if (*si == '=') {	/* c == '=' */
		switch (char_count) {
		case 1:
			errors++;
			break;
		case 2:
			*p = ((bits >> 10));
			p++;
			len += 1;
			break;
		case 3:
			*p = ((bits >> 16));
			p++;
			*p = (((bits >> 8) & 0xff));
			p++;
			len += 2;
			break;
		}
	} else if (*si == 0) {
		if (char_count) {
			errors++;
		}
	} else
		errors++;
	*p = 0;
	if (errors)
		return 0;
	memcpy(s, out, len);
	s[len] = 0;
	free(out);
	return len;
}

/* return output len
*/
int decodehex(char *s)
{
	int len = 0, i;
	char *out, *p;

	out = malloc(strlen(s) + 1);
	if (out == NULL)
		return 0;
	p = out;

	for (i = 0; i < strlen(s); i += 2) {
		char c1 = *(s + i);
		char c2 = *(s + i + 1);
		if (isxdigit(c1) && isxdigit(c2)) {
			*p = (tohex(c1) << 4) + tohex(c2);
			p++;
			len++;
		} else
			break;
	}
	memcpy(s, out, len);
	s[len] = 0;
	free(out);
	return len;
}

char *dumphex(unsigned char *s, int l)
{
	static char outs[500];
	if (l > 200)
		l = 200;
	int i;
	for (i = 0; i < l; i++)
		sprintf(outs + i * 2, "%02X", s[i]);
	outs[l * 2] = 0;
	return outs;
}

// enc8, decode64, last2 is salt, pass + last2 md5
void checkenc8(const char *email, const char *salt)
{
	struct pass_struct *s;
	static unsigned char salt_buf[MY_LEN];
	unsigned char result[21];
	MD5_CTX ctx;

	strncpy((char *)salt_buf, salt + 6, MY_LEN - 1);
	int l = decodebase64(salt_buf);
#ifdef DEBUG
	printf("docoded ret: %d\n", l);
#endif
	if (l != 20)
		exit(0);

	// 对每个可能的密码，尝试
	for (s = all_pass; s != NULL; s = s->hh.next) {
		MD5_Init(&ctx);
		MD5_Update(&ctx, s->pass, strlen(s->pass));
		MD5_Update(&ctx, salt_buf + 16, 4);
		MD5_Final(result, &ctx);
		if (memcmp(salt_buf, result, 16) == 0) {
			printf("WK %s %s %s\n", email, s->pass, salt);
			return;
		}
	}
}

#define MAXLEN 1024

void checkuser(char *email, char *salt)
{
	if (strncmp(salt, "{enc1}", 6) == 0)
		return checkenc1(email, salt);
	if (strncmp(salt, "{enc2}", 6) == 0)
		return checkenc2(email, salt);
	if (strncmp(salt, "{enc8}", 6) == 0)
		return checkenc8(email, salt);
	printf("unknow slat: %s\n", salt);
	exit(0);
}

int total_wk_pass = 0;

void load_wk_pass(char *wk_pass)
{
	FILE *fp;
	char buf[MAXLEN];
	printf("loading wk_pass file %s\n", wk_pass);
	fp = fopen(wk_pass, "r");
	if (fp == NULL) {
		printf("%s open error\n", wk_pass);
		exit(0);
	}
	while (fgets(buf, MAXLEN, fp)) {
		if (strlen(buf) < 1)
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		add_pass(buf);
		total_wk_pass++;
	}
	fclose(fp);
	printf("loading wk_pass file %s OK, total %d lines\n", wk_pass, total_wk_pass);
}

int main(int argc, char **argv)
{
	FILE *fp;
	char buf[MAXLEN];
	if (argc != 3) {
		printf("usage ./checkwkpass wk_pass.txt email.pass.txt\n");
		exit(0);
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	load_wk_pass(argv[1]);
	fp = fopen(argv[2], "r");
	if (fp == NULL) {
		printf("%s open error\n", argv[2]);
		exit(0);
	}
	while (fgets(buf, MAXLEN, fp)) {
		if (strlen(buf) < 1)
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		char *t = strchr(buf, '\t');
		if (t == NULL) {
			t = strchr(buf, ' ');
			if (t == NULL) {
				printf("SKIP %s\n", buf);
				continue;
			}
		}
		*t = 0;
		t++;
		printf("checking %s\n", buf);
		checkuser(buf, t);
	}
	fclose(fp);
	return 0;
}
