
#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tree.h"

struct td_arg {
	long i;
	int nobjs;
};

static inline uint64_t
rdtsc(void)
{
	uint32_t eax = 0, edx;

	__asm__ __volatile__("rdtscp"
				: "+a" (eax), "=d" (edx)
				:
				: "%ecx", "memory");

	return (((uint64_t)edx << 32) | eax);
}

static uint64_t __thread allocsize;

#define RB_CMP(T)								\
static inline int								\
rb_##T##_mb_cmp(struct T *search, struct T *cmp)				\
{										\
										\
	if (search->keylen == cmp->keylen) {					\
		return memcmp(search->key, cmp->key, search->keylen);		\
	} else {								\
		return (search->keylen > cmp->keylen) ? 1 : -1;			\
	}									\
}

struct rb {
	RB_ENTRY(rb) entry;
	uint32_t keylen;
	char key[];
};

struct rbh {
	RB_HEAD(rb_t, rb) head;
};

RB_CMP(rb);
RB_GENERATE(rb_t, rb, entry, rb_rb_mb_cmp);

void *
thr_rb_worker(void *o)
{
	struct td_arg *args = (struct td_arg *)o;
	struct rb **keys, *rb;
	struct rbh rbh;
	long int i = 0;
	struct stat sb;
	uint64_t s, e;
	char fname[8];
	uint64_t off;
	int fd, len;
	char td[4];
	char *buf;

	RB_INIT(&rbh.head);

	snprintf(td, 4, "td%ld", args->i+1);
	snprintf(fname, 8, "words%ld", args->i + 1);
	fd = open(fname, O_RDONLY);
	
	if (fstat(fd, &sb) < 0) {
		perror("fstat");
	}

	buf = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
	}

	keys = calloc(args->nobjs, sizeof(*keys));
	off = 0;
	s = rdtsc();
	for (i = 0; i < args->nobjs; i++) {
		char *nl;

		nl = memchr(buf, '\n', sb.st_size - off);
		*nl = '\0';

		len = strlen(buf);
		rb = calloc(1, sizeof(*rb) + len);
		rb->keylen = len;

		keys[i] = rb;
		memcpy(rb->key, buf, rb->keylen);

		off += len + 1;

		allocsize += sizeof(*rb) + rb->keylen;
		RB_INSERT(rb_t, &rbh.head, rb);
		rb = RB_FIND(rb_t, &rbh.head, rb);
		buf = nl + 1;
	}
	e = rdtsc();

	fprintf(stderr, "RBT: T%ld: %"PRIu64" alloced %"PRIu64"\n", args->i, e-s, allocsize);

	s = rdtsc();
	for (i = 0; i < args->nobjs; i++) {
		rb = RB_FIND(rb_t, &rbh.head, keys[i]);
		__asm__ __volatile__ ("" : : : "memory");
	}
	e = rdtsc();

	fprintf(stderr, "LUT: T%ld: %"PRIu64" alloced %"PRIu64"\n", args->i, e-s, allocsize);

	return NULL;
}

void
usage(void)
{
	fprintf(stderr, "Usage: ht <tds> <objs>\n"
			"\ttds:\tNumber of threads to spawn\n"
			"\tobjs:\tNumber of objects per thread\n"
	       );
	exit(-1);
}

int
main(int argc, char **argv)
{
	long int ntds = 0, nobjs = 0, i;
	struct td_arg *args;
	pthread_attr_t attr;
	pthread_t *tds;

	if (argc < 3) {
		usage();
	}

	ntds = strtol(argv[1], NULL, 10);
	if (ntds <= 0 || (errno == ERANGE && ntds == LONG_MAX)) {
		usage();
	}

	nobjs = strtol(argv[2], NULL, 10);
	if (nobjs <= 0 || (errno == ERANGE && nobjs == LONG_MAX)) {
		usage();
	}

	tds = malloc(ntds * sizeof(*tds));
	args = malloc(ntds * sizeof(*args));

	pthread_attr_init(&attr);
	for (i = 0; i < ntds; i++) {
		args[i].i = i;
		args[i].nobjs = nobjs;
		pthread_create(&tds[i], &attr, thr_rb_worker, &args[i]);
	}

	for (i = 0; i < ntds; i++) {
		pthread_join(tds[i], NULL);
	}

	return 0;
}
