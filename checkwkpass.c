/*
检查 mail 密码是否是弱密码

命令行：./checkwkpass wk_pass.txt email.pass.txt

其中：
wk_pass.txt是弱密码文件，每行一个
email.pass.txt是邮件用户 和 加密后的密码，中间空格 或 TAB 隔开

支持的加密密码格式有：
如果密码是 {enc1}xxx，crypt('密码', 'xxx')
如果密码是 {enc2}xxxx，md5sum('密码')
如果密码是 {enc5}xxx，crypt('密码', 'xxx')，使用带salt MD5，非常慢
如果密码是 {enc8}xxxx，把xxxx decode64转成2进制，然后直接dumphex

为了提高速度，预先将弱密码读入，并生成md5，

将来碰到enc2格式密码时，直接查找hash即可完成验证过程，速度为O(1)
其他格式的密码，则要穷举

*/

#include "mpi.h"

#include <openssl/md5.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <ctype.h>

//#define DEBUG 1

#define MAXLEN 1024

#include "uthash.h"

int my_rank, total_cpu;

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
void checkenc1(const char *email, const char *salt, char *result)
{
	char *p;
	struct pass_struct *s;

	for (s = all_pass; s != NULL; s = s->hh.next) {

		p = crypt(s->pass, salt + 6);
#ifdef DEBUG
		printf("enc1, key: %s, salt: %s, crypt: %s\n", s->pass, salt, p);
#endif
		if (strcmp(salt + 6, p) == 0) {
			snprintf(result, MAXLEN, "RESULTWK %s %s %s", email, s->pass, salt);
			return;
		}
	}
	snprintf(result, MAXLEN, "RESULT");
}

// enc2, md5
void checkenc2(const char *email, const char *salt, char *result)
{
	struct pass_struct *s;

	HASH_FIND_STR(all_pass, salt + 6, s);
	if (s) {
		snprintf(result, MAXLEN, "RESULTWK %s %s %s", email, s->pass, salt);
		return;
	}
	snprintf(result, MAXLEN, "RESULT");
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
void checkenc8(const char *email, const char *salt, char *result)
{
	struct pass_struct *s;
	static unsigned char salt_buf[MAXLEN];
	unsigned char res[21];
	MD5_CTX ctx;

	strncpy((char *)salt_buf, salt + 6, MAXLEN - 1);
	int l = decodebase64(salt_buf);
#ifdef DEBUG
	printf("docoded ret: %d\n", l);
#endif
	if (l != 20) {
		snprintf(result, MAXLEN, "RESULTERROR");
		return;
	}
	// 对每个可能的密码，尝试
	for (s = all_pass; s != NULL; s = s->hh.next) {
		MD5_Init(&ctx);
		MD5_Update(&ctx, s->pass, strlen(s->pass));
		MD5_Update(&ctx, salt_buf + 16, 4);
		MD5_Final(res, &ctx);
		if (memcmp(salt_buf, res, 16) == 0) {
			snprintf(result, MAXLEN, "RESULTWK %s %s %s", email, s->pass, salt);
			return;
		}
	}
	snprintf(result, MAXLEN, "RESULT");
}

void checkuser(char *email, char *salt, char *result)
{
	if (strncmp(salt, "{enc1}", 6) == 0)
		return checkenc1(email, salt, result);
	if (strncmp(salt, "{enc2}", 6) == 0)
		return checkenc2(email, salt, result);
	if (strncmp(salt, "{enc5}", 6) == 0)
		return checkenc1(email, salt, result);
	if (strncmp(salt, "{enc8}", 6) == 0)
		return checkenc8(email, salt, result);
	snprintf(result, MAXLEN, "RESULTUNKOWSALT");
}

int total_wk_pass = 0;

void load_wk_pass(char *wk_pass)
{
	FILE *fp;
	char buf[MAXLEN];
#ifdef DEBUG
	printf("rank %d loading wk_pass file %s\n", my_rank, wk_pass);
#endif
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
#ifdef DEBUG
	printf("rank %d loading wk_pass file %s OK, total %d lines\n", my_rank, wk_pass, total_wk_pass);
#endif
}

char wk_pass_filename[MAXLEN];
char pass_filename[MAXLEN];

void do_job()
{
	char buf[MAXLEN];
	char result[MAXLEN];
	MPI_Status status;
#ifdef DEBUG
	printf("I am slave %d, do the job\n", my_rank);
#endif
	load_wk_pass(wk_pass_filename);
	MPI_Barrier(MPI_COMM_WORLD);
	strcpy(buf, "READY");	// 告诉主进程READY，要求分配任务
	MPI_Send(buf, strlen(buf) + 1, MPI_CHAR, 0, 99, MPI_COMM_WORLD);
	while (1) {
		MPI_Recv(buf, MAXLEN, MPI_CHAR, 0, 99, MPI_COMM_WORLD, &status);
#ifdef DEBUG
		printf("rank %d get %s\n", my_rank, buf);
#endif
		if (memcmp(buf, "TASK", 4) == 0) {
			char *t = strchr(buf + 4, '\t');
			if (t) {
				*t = 0;
				t++;
				checkuser(buf + 4, t, result);
#ifdef DEBUG
				printf("rank %d result: %s\n", my_rank, result);
#endif
				MPI_Send(result, strlen(result) + 1, MPI_CHAR, 0, 99, MPI_COMM_WORLD);
			}
			continue;
		}
		MPI_Finalize();
		exit(0);
	}
}

int main(int argc, char **argv)
{
	char buf[MAXLEN], result[MAXLEN];
	FILE *fp;
	int c;
	double T1, T2, T3, T4;
// T1 主进程开始时间
// T2 所有进程都开始时间
// T3 所有进程都读入文件，等待开始计算时间
// T4 完成时间
	setvbuf(stdout, NULL, _IONBF, 0);

	MPI_Init(&argc, &argv);
	T1 = MPI_Wtime();
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &total_cpu);
#ifdef DEBUG
	printf("my_rank is %d\n", my_rank);
#endif

	while ((c = getopt(argc, argv, "w:p:h")) != EOF) {
		switch (c) {
		case 'w':
			strcpy(wk_pass_filename, optarg);
			break;
		case 'p':
			strcpy(pass_filename, optarg);
			break;
		case 'h':
			printf("Usage: ./checkwkpass -w weak_pass_file -p pass_filename\n");
			MPI_Finalize();
			exit(0);
		}
	}
	MPI_Barrier(MPI_COMM_WORLD);
	T2 = MPI_Wtime();

	if (my_rank != 0)
		do_job();

	MPI_Barrier(MPI_COMM_WORLD);
	T3 = MPI_Wtime();

	printf("I am master\n");
	fp = fopen(pass_filename, "r");
	if (fp == NULL) {
		printf("%s open error\n", pass_filename);
		exit(0);
	}

	int running = 0;
	while (1) {
		// 接收子进程消息
		MPI_Status status;
		MPI_Recv(buf, MAXLEN, MPI_CHAR, MPI_ANY_SOURCE, 99, MPI_COMM_WORLD, &status);
#ifdef DEBUG
		printf("my_rank %d from %d get %s\n", my_rank, status.MPI_SOURCE, buf);
#endif
		if (memcmp(buf, "RESULT", 6) == 0) {
			if (buf[6] != 0)
				printf("%s\n", buf + 6);
			running--;
		}

		result[0] = 0;	// result 这时是准备给节点的消息
		while (fgets(buf, MAXLEN, fp)) {
			if (strlen(buf) < 1)
				continue;
			if (buf[strlen(buf) - 1] == '\n')
				buf[strlen(buf) - 1] = 0;
			char *t = strchr(buf, '\t');
			if (t == NULL) {
				t = strchr(buf, ' ');
				if (t == NULL) {
					if (buf[0] == '{') {
						snprintf(result, MAXLEN, "TASKnousername	%s", buf);
						break;
					} else {
						printf("SKIP %s\n", buf);
						continue;
					}
				}
			}
			*t = 0;
			t++;
			snprintf(result, MAXLEN, "TASK%s	%s", buf, t);
			break;
		}
		if (result[0] == 0) {	// 已经结束了
			strcpy(buf, "END");
			MPI_Send(buf, strlen(buf) + 1, MPI_CHAR, status.MPI_SOURCE, 99, MPI_COMM_WORLD);
			if (running == 0) {	// 所有都结束
				MPI_Finalize();
				T4 = MPI_Wtime();
				printf("all done, total_cpu=%d T2-T1=%.2f T3-T2=%.2f T4-T3=%.2f\n", total_cpu, T2 - T1, T3 - T2, T4 - T3);
				exit(0);
			}
			continue;
		}
		running++;
		MPI_Send(result, strlen(result) + 1, MPI_CHAR, status.MPI_SOURCE, 99, MPI_COMM_WORLD);
	}
}
