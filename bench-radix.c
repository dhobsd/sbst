
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

#include "radix.h"

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

struct td_arg {
	long i;
	int nobjs;
};

struct rn {
	char *key;
};

void *
thr_cb_worker(void *o)
{
	struct td_arg *args = (struct td_arg *)o;
	struct rxt_node *root;
	long int i = 0;
	struct stat sb;
	uint64_t s, e;
	char fname[8];
	uint64_t off;
	char **keys;
	int fd, len;
	char td[4];
	char *buf;

	root = rxt_init();
	allocsize = 0;

	snprintf(td, 4, "td%ld", args->i+1);
	snprintf(fname, 8, "words%ld", args->i + 1);
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "fname %s\n", fname);
		perror("open");
	}
	
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
		struct rn *r;
		char *nl;

		nl = memchr(buf, '\n', sb.st_size - off);
		*nl = '\0';

		keys[i] = buf;

		r = calloc(1, sizeof(*r));
		r->key = strdup(buf);

		len = strlen(buf);
		off += len + 1;

		rxt_put(buf, r, root);
		r = rxt_get(buf, root);
		buf = nl + 1;
		allocsize += sizeof (*r) + len;
	}
	e = rdtsc();

	fprintf(stderr, "AGT: T%ld: %"PRIu64" alloced %"PRIu64"\n", args->i, e-s, allocsize);

	s = rdtsc();
	for (i = 0; i < args->nobjs; i++) {
		struct rn *r __attribute__((unused));
		r = rxt_get(keys[i], root);
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
		pthread_create(&tds[i], &attr, thr_cb_worker, &args[i]);
	}

	for (i = 0; i < ntds; i++) {
		pthread_join(tds[i], NULL);
	}

	return 0;
}
