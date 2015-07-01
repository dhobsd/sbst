/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2010 Redpill Linpro AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

/*
 * This macro can be used in .h files to isolate bits that the manager
 * should not (need to) see, such as pthread mutexes etc.
 */
#define VARNISH_CACHE_CHILD	1

/*
 * Prints information and backtraces every time a refcount on an object is
 * incremented or decremented. Obviously not great for production :P.
 */
#define OC_REFCNT_DBG		0

#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif

#if defined(HAVE_EPOLL_CTL)
#include <sys/epoll.h>
#endif

#define CRYPTO_dynlock_value	lock
#include <openssl/ssl.h>

#include "vqueue.h"
#include "vtree.h"

#include "vsb.h"

#include "libvarnish.h"

#include "common.h"
#include "heritage.h"
#include "miniobj.h"
#include "vtypes.h"
#include "sessions.h"

enum {
	/* Fields from the first line of HTTP proto */
	HTTP_HDR_REQ,
	HTTP_HDR_URL,
	HTTP_HDR_PROTO,
	HTTP_HDR_STATUS,
	HTTP_HDR_RESPONSE,
#define	HTTP_HDR_TOPURL HTTP_HDR_RESPONSE
	/* HTTP header lines */
	HTTP_HDR_FIRST,
};

struct cli;
struct vsb;
struct sess;
struct director;
struct object;
struct objhead;
struct objcore;
struct workreq;
struct esidata;
struct vrt_backend;
struct cli_proto;
struct VSHA256Context;
struct vsyslog_entry;
struct smp_object;
struct smp_seg;
struct geoipdb;
struct GeoIPRecordTag;

struct lock { void *priv; };		// Opaque
struct rwlock { void *priv; };		// Opaque

#define DIGEST_LEN		32


/*--------------------------------------------------------------------
 * Pointer aligment magic
 */

#define PALGN		(sizeof(void *) - 1)
#define PAOK(p)		(((uintptr_t)(p) & PALGN) == 0)
#define PRNDDN(p)	((uintptr_t)(p) & ~PALGN)
#define PRNDUP(p)	(((uintptr_t)(p) + PALGN) & ~PALGN)

/*--------------------------------------------------------------------*/

typedef struct {
	char			*b;
	char			*e;
} txt;

/*--------------------------------------------------------------------*/

enum step {
#define STEP(l, u)	STP_##u,
#include "steps.h"
#undef STEP
};

struct vcls;

struct service {
	unsigned	magic;
#define SERVICE_MAGIC	0x1a9312bb
	struct lock	lck;
	unsigned	max_conn;
	unsigned	max_threads;
	unsigned	n_conn;
	unsigned	n_obj;
	unsigned	n_oc;
	unsigned	n_oh;
	unsigned	n_nuke;
	unsigned	n_threads;
	char*           name;
	struct vcls     *active_vcl;
};


/*--------------------------------------------------------------------
 * Workspace structure for quick memory allocation.
 */

struct ws {
	unsigned		magic;
#define WS_MAGIC		0x35fac554
	const char		*id;		/* identity */
	char			*s;		/* (S)tart of buffer */
	char			*f;		/* (F)ree pointer */
	char			*r;		/* (R)eserved length */
	char			*e;		/* (E)nd of buffer */
	int			overflow;	/* workspace overflowed */
};

/*--------------------------------------------------------------------
 * HTTP Request/Response/Header handling structure.
 */

enum httpwhence {
	HTTP_Rx	 = 1,
	HTTP_Tx  = 2,
	HTTP_Obj = 3
};

/* NB: remember to update http_Copy() if you add fields */
struct http {
	unsigned		magic;
#define HTTP_MAGIC		0x6428b5c9

	struct ws		*ws;

	unsigned char		conds;		/* If-* headers present */
	enum httpwhence		logtag;
	int			status;
	double			protover;

	unsigned		shd;		/* Size of hd space */
	txt			*hd;
	unsigned char		*hdf;
#define HDF_FILTER		(1 << 0)	/* Filtered by Connection */
#define HDF_COPY		(1 << 1)	/* Copy this field */
	unsigned		nhd;		/* Next free hd */
};

/*--------------------------------------------------------------------
 * HTTP Protocol connection structure
 */

struct http_conn {
	unsigned		magic;
#define HTTP_CONN_MAGIC		0x3e19edd1

	int			fd;
	struct vbe_conn		*vc;
	struct ws		*ws;
	txt			rxbuf;
	txt			pipeline;
	char			*max_pipeline;
};

/*--------------------------------------------------------------------*/

struct acct {
	double			first;
#define ACCT(foo)	uint64_t	foo;
#include "acct_fields.h"
#undef ACCT
};

/*--------------------------------------------------------------------*/

#define L0(n)
#define L1(n)			int n;
#define MAC_STAT(n, t, l, f, e)	L##l(n)
struct dstat {
#include "stat_field.h"
};
#undef MAC_STAT
#undef L0
#undef L1

/*--------------------------------------------------------------------*/

struct wq;

struct worker {
	unsigned		magic;
#define WORKER_MAGIC		0x6391adcf
	struct objhead		*nobjhead;
	struct objcore		*nobjcore;
	void			*nhashpriv;
	struct dstat		stats;

	double			lastused;

	pthread_cond_t		cond;

	VTAILQ_ENTRY(worker)	list;
	struct workreq		*wrq;

	int			*wfd;
	unsigned		werr;	/* valid after WRK_Flush() */
	struct vbe_conn		*wvc;
	struct iovec		*iov;
	unsigned		siov;
	unsigned		niov;
	ssize_t			liov;

	struct VCL_conf		*vcl;

	unsigned char		*wlb, *wlp, *wle;
	unsigned		wlr;

	struct VSHA256Context	*sha256ctx;

	struct http_conn	htc[1];
	struct ws		ws[1];
	struct http		*http[4];
	struct http		*bereq;
	struct http		*beresp1;
	struct http		*beresp;

	enum body_status	body_status;
	unsigned		cacheable;
	unsigned		gzip;
	unsigned		stream_pass;
	unsigned		stream_miss;
	double			age;
	double			entered;
	double			ttl;
	double                  orig_ttl;
	double			grace;
	unsigned		do_esi;

	/* Timeouts */
	double			connect_timeout;
	double			first_byte_timeout;
	double			between_bytes_timeout;

	struct wq		*qp;
#ifdef SYS_gettid
	pid_t			tid;
#endif

	unsigned		crc32_objects_fromdisk;
	unsigned		crc32_objects_incore;
	unsigned		crc32_stores_fromdisk;
	unsigned		crc32_stores_incore;

	const char		*error_reason;
	uint64_t                bytes_written;

};

/* Work Request for worker thread ------------------------------------*/

/*
 * This is a worker-function.
 * XXX: typesafety is probably not worth fighting for
 */

typedef void workfunc(struct worker *, void *priv);

struct workreq {
	VTAILQ_ENTRY(workreq)	list;
	workfunc		*func;
	void			*priv;
};

/* Storage -----------------------------------------------------------*/

struct storage {
#define STORAGE_MAGIC		0x1a4e51c0
	VSTAILQ_ENTRY(storage)	list;

	unsigned char		*ptr;
	unsigned		len;
	unsigned		space;
	unsigned		magic;

	struct stevedore	*stevedore;

	void			*priv;
	int			fd;
	off_t			where;
};

/* Object core structure ---------------------------------------------
 * Objects have sideways references in the binary heap and the LRU list
 * and we want to avoid paging in a lot of objects just to move them up
 * or down the binheap or to move a unrelated object on the LRU list.
 * To avoid this we use a proxy object, objcore, to hold the relevant
 * housekeeping fields parts of an object.
 */

struct streamsess;

struct objcore {
	unsigned		magic;
#define OBJCORE_MAGIC		0x4d301302
	unsigned		refcnt;
	unsigned char           *vary;

	int			hits;

	struct object		*obj;
	struct objhead		*objhead;
	double			timer_when;
	uint64_t		flags;
#define OC_F_ONLRU		(((uint64_t) 1)<<0)
#define OC_F_BUSY		(((uint64_t) 1)<<1)
#define OC_F_PASS		(((uint64_t) 1)<<2)
#define OC_F_PERSISTENT		(((uint64_t) 1)<<3)
#define OC_F_LRUDONTMOVE	(((uint64_t) 1)<<4)
#define OC_F_REMOVING		(((uint64_t) 1)<<5)
#define OC_F_NOEXPIRE           (((uint64_t) 1)<<6)
#define OC_F_PURGED             (((uint64_t) 1)<<7)
#define OC_F_STORE_DROPPED	(((uint64_t) 1)<<8)
#define OC_F_REAPING            (((uint64_t) 1)<<9)	
#define OC_F_REMOVED            (((uint64_t) 1)<<10)
#define OC_F_SSD_ON_DISK        (((uint64_t) 1)<<11)
#define OC_F_DIRECT_STORED      (((uint64_t) 1)<<12)
#define OC_F_DIRECT_NEED_LOAD   (((uint64_t) 1)<<13)
#define OC_F_DIRECT_DROP_OBJ    (((uint64_t) 1)<<14)
#define OC_F_BUSY_DELIVER	(((uint64_t) 1)<<15)
#define OC_F_BUSY_FAIL		(((uint64_t) 1)<<16)
#define OC_F_REFCNT_REF	(((uint64_t) 1)<<17)
#define OC_F_REFCNT_FINDBAN	(((uint64_t) 1)<<18)
#define OC_F_REFCNT_EXPTIMER	(((uint64_t) 1)<<19)
#define OC_F_REFCNT_LOOKUP2	(((uint64_t) 1)<<20)
#define OC_F_REFCNT_NUKEONE	(((uint64_t) 1)<<21)
#define OC_F_REFCNT_REMOVE	(((uint64_t) 1)<<22)
#define OC_F_REFCNT_DELIVER	(((uint64_t) 1)<<23)
#define OC_F_REFCNT_DONE_GRACE	(((uint64_t) 1)<<24)
#define OC_F_REFCNT_HIT	(((uint64_t) 1)<<25)
#define OC_F_REFCNT_HITPASS	(((uint64_t) 1)<<26)
#define OC_F_REFCNT_DROPOC_DEREF	(((uint64_t) 1)<<27)
#define OC_F_REFCNT_PURGE_DEREF	(((uint64_t) 1)<<28)
#define OC_F_REFCNT_DROP_GRACE	(((uint64_t) 1)<<29)
#define OC_F_REFCNT_DROP	(((uint64_t) 1)<<30)
#define OC_F_REFCNT_UNBUSY_GRACE	(((uint64_t) 1)<<31)
#define OC_F_REFCNT_SSD_REAPER	(((uint64_t) 1)<<32)
#define OC_F_REFCNT_SSD_WRITER	(((uint64_t) 1)<<33)
#define OC_F_REFCNT_SSD_ALLOC	(((uint64_t) 1)<<34)
#define OC_F_REFCNT_SSD_FLUSH	(((uint64_t) 1)<<35)
#define OC_F_REFCNT_SSD_WRITER_DEREF	(((uint64_t) 1)<<36)
#define OC_F_REFCNT_SSD_WRITER_DEREF2	(((uint64_t) 1)<<37)
#define OC_F_REFCNT_SSD_DROP_OC	(((uint64_t) 1)<<38)
#define OC_F_REFCNT_LURKER	(((uint64_t) 1)<<39)
#define OC_F_REFCNT_MEMFREE_REF	(((uint64_t) 1)<<40)
#define OC_F_REFCNT_MEMFREE_DEREF	(((uint64_t) 1)<<41)
#define OC_F_REFCNT_LOOKUP	(((uint64_t) 1)<<42)
#define OC_F_REFCNT_REFRESH_DROP	(((uint64_t) 1)<<43)
#define OC_F_REFCNT_INSERT	(((uint64_t) 1)<<44)
#define OC_F_REFCNT_INJECT	(((uint64_t) 1)<<45)
#define OC_F_REFCNT_DROPOC	(((uint64_t) 1)<<46)
#define OC_F_SURROGATE		(((uint64_t) 1)<<47)
#define OC_F_REFCNT_GRACE	(((uint64_t) 1)<<48)
#define OC_F_REFCNT_PURGE	(((uint64_t) 1)<<49)
#define OC_F_REFCNT_LOG		(((uint64_t) 1)<<50)
#define OC_F_REFCNT_STREAM	(((uint64_t) 1)<<51)
#define OC_F_SURROGATE_PURGE	(((uint64_t) 1)<<52)
#define OC_F_REFCNT_SK_CLONE    (((uint64_t) 1)<<53)

	unsigned		timer_idx;
	VTAILQ_ENTRY(objcore)	list;
	VLIST_ENTRY(objcore)	lru_list;
	VTAILQ_HEAD(,oc_sk)	*sk_list;
	struct smp_seg		*smp_seg;

	double			last_lru;
	double			last_use;

	/* added for safety, wastes memory, so sue me */				
        uint32_t                obj_crc32;
	uint32_t                obj_len;
	uint32_t                store_crc32;
	uint32_t                store_len;
	struct storage          *objstore;
	double			ttl;
	double			age;
	unsigned		ims;
#define OC_IMS_LAST_MODIFIED	(1<<0)
#define OC_IMS_ETAG		(1<<1)
#define OC_IMS_USED		(1<<2)

	/* this should be analyzed to be unions */
	uint32_t                seg;
	uint32_t                seg_offset;
	uint                    primary;
	uint                    secondary;
	uint                    no_background_fetch;

	/* backend we are fetching from */
	char                    *backend;

	struct streamsess	*ssp;
};

/*--------------------------------------------------------------------*/

struct lru {
	unsigned		magic;
#define LRU_MAGIC		0x3fec7bb0
	VLIST_HEAD(,objcore)	lru_head;
	struct objcore		*memmark;
	struct objcore		senteniel;
};

/* Object structure --------------------------------------------------*/

struct object {
	unsigned		magic;
#define OBJECT_MAGIC		0x32851d42
	unsigned		xid;
	struct storage		*objstore;
	struct objcore		*objcore;

	struct ws		ws_o[1];
	unsigned char		*vary;

	unsigned		response;

	unsigned		smp_index;

	unsigned		cacheable;

	unsigned		len;

	double			entered;
	double			grace;
	double                  orig_ttl;
	
	double			last_modified;

	struct http		*http;

	VSTAILQ_HEAD(, storage)	store;

	struct esidata		*esidata;

	struct service		*service;

};

/* -------------------------------------------------------------------*/

struct geoiprecord {
	unsigned		magic;
#define GEOIPRECORD_MAGIC	0x601b3ff8
	struct geoipdb		*gidb;
	struct GeoIPRecordTag	*record;
};

/* -------------------------------------------------------------------*/

struct streamstate;

struct sess {
	unsigned		magic;
#define SESS_MAGIC		0x2c2f9c5a
	int			fd;
	int			id;
	unsigned		xid;

	signed int		restarts;
	int			esis;

	uint8_t			hash_ignore_busy;
	uint8_t			hash_always_miss;

	struct worker		*wrk;

	socklen_t		remote_sockaddrlen;
	socklen_t		local_sockaddrlen;

	struct sockaddr		*remote_sockaddr;
	struct sockaddr		*local_sockaddr;

	struct listen_sock	*mylsock;

	/* formatted ascii client address */
	char                    addr[TCP_ADDRBUFSIZE];
	char			port[TCP_PORTBUFSIZE];
	char			*client_identity;

	/* HTTP request */
	const char		*doclose;
	struct http		*http;
	struct http		*http0;

	struct ws		ws[1];
	char			*ws_ses;	/* WS above session data */
	char			*ws_req;	/* WS above request data */

	unsigned char		digest[DIGEST_LEN];

	struct http_conn	htc[1];

	/* Timestamps, all on TIM_real() timescale */
	double			t_open;
	double			t_req;
	double			t_resp;
	double			t_end;

	/* Acceptable grace period */
	double			grace;
	struct objcore		*grace_oc;
	struct objcore          *ims_oc;
	struct objcore		*hitpass_oc;

	enum step		step;
	unsigned		cur_method;
	unsigned		handling;
	unsigned char		pass;
	unsigned char		sendbody;
	int			err_code;
	const char		*err_reason;
	unsigned		extracted_postbody;
	char			*postbody;

	VTAILQ_ENTRY(sess)	list;

	struct director		*director;
	struct director         *orig_director;
	struct vbe_conn		*vbe;
	struct object		*obj;
	struct objcore		*objcore;
	struct objhead		*objhead;
	struct VCL_conf		*vcl;
	struct VCL_conf         *orig_vcl;

	/* Various internal stuff */
	struct sessmem		*mem;

	struct workreq		workreq;
	struct acct		acct_tmp;
	struct acct		acct_req;
	struct acct		acct_ses;

#if defined(HAVE_EPOLL_CTL)
	struct epoll_event ev;
	uint64_t		waiters;
#endif

	enum session_state      status;
	char                    status_msg1[255];
	char                    status_msg2[255];

	char			fastly_status[4];
	const char		*fastly_service_id;
	const char		*fastly_state;
	int			fastly_relay_traffic;

	struct geoiprecord	*geoip_record;

	/* used when we are doing a shielded response */
	unsigned int            is_local_shield		: 1;
	/* used when this request is being shielded */
	unsigned int            is_local_edge		: 1;
	unsigned int		serving_stale		: 1;
	unsigned int		head_request		: 1;
	unsigned int		background_fetch	: 1;  /* this is a bgfetch req */
	unsigned int		allow_background_fetch	: 1;  /* bgfetch enabled */
	unsigned int		esi_allow_inside_cdata	: 1;
	int			disable_esi		: 1;
	unsigned int		fastly_waited		: 1;
	unsigned int		geoip_use_x_forwarded_for : 1;
	unsigned int		losthdr			: 1;
	unsigned int		unused_flagspace	: 21;

	struct objcore          *refresh_oc;

	double                  sess_timeout;

	struct service          *service;

	unsigned                total_retrans;

	/* The protocol handled by the servers fronting Varnish.
	   Currently, this will be either NULL (meaning "http")
	   or "https". */
	const char		*fastly_protocol;

	/* for apache-style logging: %I, %O, cached time.end */
	uint64_t		req_header_bytes_read;
	uint64_t		req_body_bytes_read;
	uint64_t		resp_header_bytes_written;
	uint64_t		resp_body_bytes_written;
	double			log_time;
	unsigned		resp_completed;

	socklen_t		client_sockaddrlen;
	socklen_t		server_sockaddrlen;

	struct sockaddr		*client_sockaddr;
	struct sockaddr		*server_sockaddr;

	const char		*geoip_ip_override;


	/* for streamed range requests
	 * (XXX: size_t, but that's a separate mission) */
	unsigned		low;
	unsigned		high;
	struct streamstate	*sstp;

	/* moved from worker to sess */
	struct http		*resp;

	unsigned		remote_closed;
};

/* -------------------------------------------------------------------*/

/* Backend connection */
struct vbe_conn {
	unsigned		magic;
#define VBE_CONN_MAGIC		0x0c5e6592
	VTAILQ_ENTRY(vbe_conn)	list;
	struct backend		*backend;
	int			fd;

	uint8_t			recycled;

	/* Timeouts */
	double			first_byte_timeout;
	double			between_bytes_timeout;
	
	double			addrchange;

	SSL			*ssl;

        double                  last_used;
	double                  idle_time;
};

struct sk_oc {
	struct objcore		*oc;
	struct oc_sk		*oc_sk;
	struct sktree		*skt;
	VRB_ENTRY(sk_oc)	entry;
};


struct oc_sk {
	struct sktree		*sk;
	struct sk_oc		*sk_oc;
	VTAILQ_ENTRY(oc_sk)	entry;
};

struct sktree {
	void			*key;
	VRB_HEAD(sk_oct,sk_oc)	oc_tree;
	VRB_ENTRY(sktree)	entry;
	uint32_t		prefix;
	uint32_t		keylen;
};

static inline int
rb_sk_oc_cmp(struct sk_oc *a, struct sk_oc *b)
{

	if (a->oc == b->oc) {
		return 0;
	}

	return (a->oc - b->oc > 0) ? 1 : -1;
}

/*
 * Special multi-byte comparator for surrogate keys. The keys are padded to the
 * nearest 8 bytes. The tree is sorted first by length, then by key. Searches
 * increment the prefix as they go so that shared prefixes can be elided on
 * depth traversal.
 *
 * The sys/tree.h API guarantees that our inserted or sought after node is
 * provided first to the comparator interface in all cases. If many keys share
 * the same prefix, they are then sorted by their first differing series of 8
 * bytes. Providing this state gives our red-black tree a neat prefix-trie-like
 * behavior.
 *
 * We could modify the VRB API to remove the need to store the state in the
 * node. I don't think this is super urgent because it only saves us 4 bytes
 * per key.
 */
#define RB_CMP(T)								\
static inline int								\
rb_##T##_mb_cmp(struct T *search, struct T *cmp)				\
{										\
										\
	/* First, we sort the tree by key length. */				\
	if (search->keylen == cmp->keylen) {					\
		uint64_t *skey = search->key;					\
		uint64_t *ckey = cmp->key;					\
										\
		/* If the keys are equal length, skip our already-compared */	\
		/* prefix. */							\
		skey += search->prefix;						\
		ckey += search->prefix;						\
										\
		/* Compare bytes while our total search doesn't exceed the */	\
		/* key length and the prefix of these two nodes continues to */	\
		/* match. Only increment in the body because we want to do */	\
		/* additional comparisons when on the final or first */		\
		/* differing quadword. */					\
		while (++search->prefix * 8 < search->keylen &&			\
		    *skey++ == *ckey++) ;					\
										\
		/* If we've compared the whole key, determine whether there */	\
		/* was a match and return order otherwise. */			\
		if (search->prefix * 8 == search->keylen) {			\
			search->prefix = 0;					\
										\
			if (*skey == *ckey) {					\
				return 0;					\
			} else {						\
				return *skey > *ckey ? 1 : -1;			\
			}							\
		}								\
										\
		/* We matched as much of the prefix as possible but these */	\
		/* keys differ before the last 8 bytes. */			\
		return *skey > *ckey ? 1 : -1;					\
	} else {								\
		return (search->keylen > cmp->keylen) ? 1 : -1;			\
	}									\
}

struct sidtree {
	struct lock			mtx;
	void				*key;
	VRB_HEAD(sktree_t, sktree)	sktree;
	VRB_ENTRY(sidtree)		entry;
	uint32_t			prefix;
	uint32_t			keylen;
};

/* Publish channel */
struct vpub_channel;

/* Prototypes etc ----------------------------------------------------*/

/* cache_acceptor.c */
void vca_return_session(struct sess *sp);
void vca_close_session(struct sess *sp, const char *why);
void vca_tcpinfo_session(struct sess *sp, const char *why);
void VCA_Prep(struct sess *sp);
void VCA_WaiterInit(void **priv);
void VCA_Init(void);
void VCA_Shutdown(void);
const char *VCA_waiter_name(void);
extern pthread_t VCA_thread;

/* cache_backend.c */

struct vbe_conn *VBE_GetFd(const struct director *, struct sess *sp);
int VBE_Healthy(double now, const struct director *, uintptr_t target);
int VBE_Healthy_sp(const struct sess *sp, const struct director *);
void VBE_CloseFd(struct sess *sp);
void VBE_RecycleFd(struct sess *sp);
void VBE_AddHostHeader(struct sess *sp);
void VBE_Poll(void);
void VBE_UpdateKeepalive(const struct sess *sp, int success);

/* cache_backend_cfg.c */
void VBE_Init(void);
struct backend *VBE_AddBackend(struct cli *cli, const struct vrt_backend *vb);

/* cache_backend_poll.c */
void VBP_Init(void);
void VBP_UpdateHealth(uint16_t status, struct sockaddr_in *s4, struct sockaddr_in6 *s6, struct backend *bp);
void VBP_FullCheck(struct backend *bp);

/* cache_center.c [CNT] */
void CNT_Session(struct sess *sp);
void CNT_Init(void);

/* cache_cli.c [CLI] */
void CLI_Init(void);
void CLI_Run(void);
void CLI_AddFuncs(struct cli_proto *p);
extern pthread_t cli_thread;
#define ASSERT_CLI() do {assert(pthread_self() == cli_thread);} while (0)

/* cache_dns.c */
void DNS_Init(void);

/* cache_expiry.c */
void EXP_Insert(struct object *o);
void EXP_Inject(struct objcore *oc, struct lru *lru, double ttl);
void EXP_Init(void);
void EXP_Rearm(const struct object *o);
int EXP_Touch(const struct object *o);
int EXP_NukeOne(const struct sess *sp, struct lru *lru);
void EXP_MemFree(struct lru *lru, uint64_t freemem, void *start, int fd);
void EXP_Remove(const struct sess *sp, struct objcore *oc);

/* cache_fetch.c */
int FetchHdr(struct sess *sp);
int FetchBody(struct sess *sp);
int FetchReqBody(struct sess *sp);
void Fetch_Init(void);

/* cache_geoip.c */

/* XXX: malloc something in Init() instead? */
#define GEOIP_FAILED ((void *)1)

void VGEO_Lookup(struct sess *sp);
void VGEO_Free_Record(struct sess *sp);
void VGEO_Init(void);

/* cache_healthcheck.c */
void HC_Init(void);
bool HC_IsMaster(struct backend *b);
void HC_SendHealth(struct sess *sp, uint16_t health, struct backend *b, bool newaddr);

/* cache_http.c */
unsigned HTTP_estimate(unsigned nhttp);
void HTTP_Copy(struct http *to, const struct http * const fm);
struct http *HTTP_create(void *p, unsigned nhttp);
const char *http_StatusMessage(unsigned);
unsigned http_EstimateWS(const struct http *fm, unsigned how, unsigned *nhd);
void HTTP_Init(void);
void http_ClrHeader(struct http *to);
unsigned http_Write(struct worker *w, const struct http *hp, int resp);
void http_CopyResp(const struct http *to, const struct http *fm);
void http_SetResp(const struct http *to, const char *proto, const char *status,
    const char *response);
void http_FilterFields(struct sess *sp, int fd, struct http *to,
    const struct http *fm, unsigned how, int reset);
void http_FilterHeader(struct sess *sp, unsigned how);
void http_PutProtocol(struct sess *sp, int fd, const struct http *to,
    const char *protocol);
void http_PutStatus(struct sess *sp, int fd, struct http *to, int status);
void http_PutResponse(struct sess *sp, int fd, const struct http *to,
    const char *response);
void http_PrintfHeader(struct sess *sp, int fd, struct http *to,
    const char *fmt, ...)
    __attribute__((format(printf,4,5)));
void http_SetHeader(struct sess *sp, int fd, struct http *to, const char *hdr);
void http_SetH(const struct http *to, unsigned n, const char *fm);
void http_ForceGet(const struct http *to);
void http_Setup(struct http *ht, struct ws *ws);
int http_GetHdr(const struct http *hp, const char *hdr, char **ptr);
int http_GetHdrField(const struct http *hp, const char *hdr,
    const char *field, char **ptr);
int http_GetStatus(const struct http *hp);
const char *http_GetReq(const struct http *hp);
int http_HdrIs(const struct http *hp, const char *hdr, const char *val);
int http_DissectRequest(struct sess *sp);
int http_DissectResponse(struct sess *sp, const struct http_conn *htc,
    struct http *hp);
const char *http_DoConnection(const struct http *hp);
void http_CopyHome(struct sess *sp, int fd, const struct http *hp);
void http_Unset(struct http *hp, const char *hdr);
void http_CollectHdr(struct http *hp, const char *hdr);
bool HTTP_BodylessResponse(const struct http *hp);

/* cache_httpconn.c */
void HTC_Init(struct http_conn *htc, struct ws *ws, int fd,
    struct vbe_conn *vc);
int HTC_Reinit(struct http_conn *htc);
int HTC_Rx(struct http_conn *htc, int recv);
int HTC_Read(struct http_conn *htc, void *d, unsigned len);
int HTC_Read_Nonblock(struct http_conn *htc, void *d, unsigned len);
int HTC_Readahead(struct http_conn *htc, unsigned len);
int HTC_Complete(struct http_conn *htc, int recv);

#define HTTPH(a, b, c, d, e, f, g) extern char b[];
#include "http_headers.h"
#undef HTTPH

/* cache_jemalloc.c */

void JEM_Init(void);

/* cache_main.c */
void THR_SetName(const char *name);
const char* THR_GetName(void);
void THR_SetSession(const struct sess *sp);
const struct sess * THR_GetSession(void);

/* cache_lck.c */
void LCK_Init(void);

/* Internal functions, call only through macros below */
void Lck__Lock(struct lock *lck, const char *p, const char *f, int l, uint64_t *wait);
void Lck__Unlock(struct lock *lck, const char *p, const char *f, int l, uint64_t *held);
void Lck__CondWait(pthread_cond_t *cond, struct lock *lck, uint64_t *held, uint64_t *condstat);
int Lck__Trylock(struct lock *lck, const char *p, const char *f, int l);
void Lck__New(struct lock *lck, const char *w);
void Lck__Assert(const struct lock *lck, int held);

/* public interface: */
void Lck_Delete(struct lock *lck);

#define Lck_New(a) Lck__New(a, #a);
#define Lck_Lock(a, b)										\
	do {											\
		setrip();									\
		Lck__Lock(a, __func__, __FILE__, __LINE__, &VSL_stats->lock_cycles_wait_##b);	\
		setrip();									\
	} while (0)

#define Lck_Unlock(a, b)									\
	do {											\
		Lck__Unlock(a, __func__, __FILE__, __LINE__, &VSL_stats->lock_cycles_held_##b);	\
		setrip();									\
	} while (0)

#define Lck_CondWait(pt, a, b)											\
	do {													\
		Lck__CondWait(pt, a, &VSL_stats->lock_cycles_held_##b, &VSL_stats->lock_cycles_cond_##b);	\
		setrip();											\
	} while (0);

#define Lck_Trylock(a) Lck__Trylock(a, __func__, __FILE__, __LINE__)
#define Lck_AssertHeld(a) Lck__Assert(a, 1)
#define Lck_AssertNotHeld(a) Lck__Assert(a, 0)

/* cache_memory.c */
void MEM_Alloc(struct worker *, void * volatile *, size_t);
void MEM_Realloc(struct worker *, void * volatile *, size_t);
void MEM_Free(struct worker *, void *volatile *, void (*foo) (const struct sess *, void *));
void MEM_Init(void);

/* cache_panic.c */
void PAN_Init(void);
void PAN_WS(const struct ws *ws);
void PAN_VBE(const struct vbe_conn *vbe);
void PAN_Storage(const struct storage *st);
void PAN_TXT(const char *id, const txt t);
void PAN_HTTP(const char *id, const struct http *h);
void PAN_HTTPConn(const struct http_conn *htc);
void PAN_Object(const struct object *o);
void PAN_ObjCore(const struct objcore *oc, const char *name);
void PAN_Service(const struct service *srv);
void PAN_VCL(const struct VCL_conf *vcl);
void PAN_WRK(const struct worker *wrk);
void PAN_Sess(const char *id, const struct sess *sp);
void PAN_Backtrace(void);
void PAN_SoftPanic(void);

/* cache_pipe.c */
void PipeSession(struct sess *sp);

/* cache_pool.c */
void WRK_Init(void);
int WRK_Queue(struct workreq *wrq);
int WRK_QueueSession(struct sess *sp);
void WRK_SumStat(struct worker *w);
void * WRK_Waiter(const struct worker *w);
void WRK_Tickle(void);

void WRW_Reserve(struct worker *w, int *fd, struct vbe_conn *vc);
unsigned WRW_Flush(struct worker *w);
unsigned WRW_FlushRelease(struct worker *w);
unsigned WRW_Write(struct worker *w, const void *ptr, int len);
unsigned WRW_WriteH(struct worker *w, const txt *hh, const char *suf);
#ifdef SENDFILE_WORKS
void WRW_Sendfile(struct worker *w, int fd, off_t off, unsigned len);
#endif  /* SENDFILE_WORKS */
void WRW_Init(void);

typedef void *bgthread_t(struct sess *, void *priv);
void WRK_BgThread(pthread_t *thr, const char *name, bgthread_t *func,
    void *priv);
void WRK_QuittableThread(pthread_t *thr, const char *name, bgthread_t *func,
    void *priv);

/* cache_publish.c */
void VPUB_Init(void);
void VPUB_ThreadInit(void);
void VPUB_ThreadCleanup(void);
int  VPUB_Publish(struct vpub_channel *channel, const char *fmt, ...)
    __attribute__((format(printf,2,3)));
struct vpub_channel * VPUB_GetChannel(const char *name);

/* cache_rwlock.c */

/* Internal functions, call only through macros below */
void RWL__ReadLock(struct rwlock *lck, const char *p, const char *f, int l, uint64_t *wait);
void RWL__WriteLock(struct rwlock *lck, const char *p, const char *f, int l, uint64_t *wait);
void RWL__ReadUnlock(struct rwlock *lck, const char *p, const char *f, int l, uint64_t *held);
void RWL__WriteUnlock(struct rwlock *lck, const char *p, const char *f, int l, uint64_t *held);
int RWL__TryReadLock(struct rwlock *lck, const char *p, const char *f, int l);
int RWL__TryWriteLock(struct rwlock *lck, const char *p, const char *f, int l);
void RWL__AssertWrite(const struct rwlock *lck, int held);
void RWL__New(struct rwlock *lck, const char *w);

/* public interface: */
void RWL_Delete(struct rwlock *lck);

#define RWL_New(a) RWL__New(a, #a);
#define RWL_ReadLock(a, b)										\
	do {												\
		setrip();										\
		RWL__ReadLock(a, __func__, __FILE__, __LINE__, &VSL_stats->rwl_r_cycles_wait_##b);	\
		setrip();										\
	} while (0)

#define RWL_WriteLock(a, b)										\
	do {												\
		setrip();										\
		RWL__WriteLock(a, __func__, __FILE__, __LINE__, &VSL_stats->rwl_w_cycles_wait_##b);	\
		setrip();										\
	} while (0)

#define RWL_ReadUnlock(a, b)										\
	do {												\
		RWL__ReadUnlock(a, __func__, __FILE__, __LINE__, &VSL_stats->rwl_r_cycles_held_##b);	\
		setrip();										\
	} while (0)

#define RWL_WriteUnlock(a, b)										\
	do {												\
		RWL__WriteUnlock(a, __func__, __FILE__, __LINE__, &VSL_stats->rwl_w_cycles_held_##b);	\
		setrip();										\
	} while (0)

#define RWL_TryReadLock(a) RWL__TryReadLock(a, __func__, __FILE__, __LINE__)
#define RWL_TryWriteLock(a) RWL__TryWriteLock(a, __func__, __FILE__, __LINE__)
#define RWL_AssertWriteHeld(a) RWL__AssertWrite(a, 1)
#define RWL_AssertWriteNotHeld(a) RWL__AssertWrite(a, 0)

/* cache_session.c [SES] */
void SES_Init(void);
struct sess *SES_New(void);
struct sess *SES_Alloc(void);
struct sess *SES_Clone(const struct sess *sp);
void SES_Delete(struct sess *sp);
void SES_Charge(struct sess *sp);

/* cache_shmlog.c */
void VSL_Init(void);
#ifdef SHMLOGHEAD_MAGIC
void VSL(enum shmlogtag tag, int id, const char *fmt, ...)
    __attribute__((format(printf,3,4)));
void WSLR(struct worker *w, enum shmlogtag tag, int id, txt t);
void WSL(struct worker *w, enum shmlogtag tag, int id, const char *fmt, ...)
    __attribute__((format(printf,4,5)));
void WSL_Flush(struct worker *w, int overflow);

#define DSL(flag, tag, id, ...)					\
	do {							\
		if (params->diag_bitmap & (flag))		\
			VSL((tag), (id), __VA_ARGS__);		\
	} while (0)

#define WSP(sess, tag, ...)					\
	WSL((sess)->wrk, tag, (sess)->fd, __VA_ARGS__)

#define WFETCH(sess, htc, tag, ...) do {			\
	WSL((sess)->wrk, tag, (sess)->fd, __VA_ARGS__);		\
	WSL((sess)->wrk, tag, (htc)->fd, __VA_ARGS__);		\
	} while (0)

#define WSPR(sess, tag, txt)					\
	WSLR((sess)->wrk, tag, (sess)->fd, txt)

#define INCOMPL() do {							\
	VSL(SLT_Debug, 0, "INCOMPLETE AT: %s(%d)", __func__, __LINE__); \
	fprintf(stderr,							\
	    "INCOMPLETE AT: %s(%d)\n",					\
	    (const char *)__func__, __LINE__);				\
	abort();							\
	} while (0)

#define IMPOSS() do {							\
	VSL(SLT_Debug, 0, "SHOULD NOT BE POSSIBLE AT: %s(%d)", __func__,\
	    __LINE__);							\
	fprintf(stderr,							\
	    "SHOULD NOT BE POSSIBLE: %s(%d)\n",				\
	    (const char *)__func__, __LINE__);				\
	abort();							\
	} while (0)

#endif

/* cache_ssl.c */
void VSSL_error(const char *file, int line, const char *message);
SSL_CTX *VSSL_CTX_new(void);
void VSSL_CTX_load_default_CAs(SSL_CTX *ctx);
void VSSL_CTX_load_CA(SSL_CTX *ctx, const char *pemstring);
void VSSL_CTX_load_client_cert(SSL_CTX *ctx, const char *certstring,
    const char *keystring);
void VSSL_Init(void);
SSL *VSSL_new(SSL_CTX *bctx);
int VSSL_cert_check(int fd, SSL *ssl, char *hostname, const char **errstr);
void VSSL_connect_stats(int fd, SSL *ssl);
int VSSL_Connect(struct sess *sp, struct vbe_conn *vc);
void VSSL_error_trace_vsb(struct vsb *sb, int indent);
void VSSL_error_trace_vsl(int fd);
void VSSL_error_trace_wsl(struct worker *w, int fd);
void VSSL_error_trace_f(FILE *f);
ssize_t VSSL_read(struct vbe_conn *vc, void *buf, size_t count);
ssize_t VSSL_write(struct vbe_conn *vc, const void *buf, size_t count);
void VSSL_close(struct vbe_conn *vc);
void VSSL_ThreadCleanup(void *arg);
ssize_t VSSL_writev(struct vbe_conn *vc, const struct iovec *iov, int iovcnt);
void VSSL_pipe(struct sess *sp);

/* cache_stream.c */
int VST_PassStreamBody(struct sess *sp);
int VST_DeliverChunked(struct streamsess *ssp);
unsigned VST_GetLength(const struct object *obj);
void *VST_Streamer(void *priv);
void VST_FetchStreamBody(struct sess *sp);
int VST_StreamBusyBody(struct sess *sp);
void VST_SspGet(struct streamsess *ssp);
void VST_SspRelease(struct streamsess *ssp);
void VST_Init(void);

/* cache_surrogate.c */
void SK_Init(void);
void SK_Insert_Key(struct sess *sp, char *key);
void SK_Remove_Key(struct sess *sp, char *key);
void SK_Remove_OC(const struct sess *sp, struct objcore *oc);
void SK_Clone_OC(struct sess *sp, struct objcore *old_oc, struct objcore *new_oc);

/* cache_log.c */
void VLOG_Init(void);
void VLOG_Log(const char *log, uint32_t loglen);

/* cache_response.c */
void RES_BuildHttp(struct sess *sp, int reset);
unsigned RES_WriteObj(struct sess *sp);

/* cache_vary.c */
int VRY_Create(const struct sess *sp, const struct http *hp, struct vsb **sb);
int VRY_Match(const struct sess *sp, const unsigned char *vary);

/* cache_vcl.c */
void VCL_Init(void);
void VCL_Refresh(struct VCL_conf **vcc);
void VCL_Rel(struct VCL_conf **vcc);
void VCL_Get(struct VCL_conf **vcc);
void VCL_GetRef(struct VCL_conf *vc);
void VCL_Poll(void);
int VCL_Switch(struct VCL_conf **vcc, char *);
struct service * VCL_GetService(char *);
int VCL_SwitchByService(struct VCL_conf **vcc, struct service *service);
struct director *VCL_Get_Director(struct VCL_conf *vcc, char *name);

#define VCL_MET_MAC(l,u,b) void VCL_##l##_method(struct sess *);
#include "vcl_returns.h"
#undef VCL_MET_MAC

/* cache_vrt.c */
void VRT_Init(void);

/* cache_vrt_esi.c */

unsigned ESI_Deliver(struct sess *);
void ESI_Destroy(struct object *);
void ESI_Parse(struct sess *);

/* cache_vrt_stats.c */
void VRT_Stats_Init(void);

/* cache_ws.c */

void WS_Init(struct ws *ws, const char *id, void *space, unsigned len);
unsigned WS_Reserve(struct ws *ws, unsigned bytes);
void WS_Release(struct ws *ws, unsigned bytes);
void WS_ReleaseP(struct ws *ws, char *ptr);
void WS_Assert(const struct ws *ws);
void WS_Reset(struct ws *ws, char *p);
char *WS_Alloc(struct ws *ws, unsigned bytes);
char *WS_Dup(struct ws *ws, const char *);
char *WS_Snapshot(struct ws *ws);
unsigned WS_Free(const struct ws *ws);

/* rfc2616.c */
double RFC2616_Ttl(const struct sess *sp);
enum body_status RFC2616_Body(struct sess *sp);

/* storage_synth.c */
struct vsb *SMS_Makesynth(struct object *obj);
void SMS_Finish(struct object *obj);

/* storage_persistent.c */
void SMP_Fixup(struct sess *sp, const struct objhead *oh, struct objcore *oc);
void SMP_BANchanged(const struct object *o, double t);
void SMP_TTLchanged(const struct object *o);
void SMP_FreeObj(const struct object *o);
void SMP_Ready(void);
void SMP_NewBan(double t0, const char *ban);

/* storage_ssd.c */
struct objcore * SSD_record_hit (struct sess *sp, struct objcore *oc);
void SSD_remove_oc(struct sess *sp, struct objcore *oc);

struct objcore * SSD_direct_record_hit (struct sess *sp, struct objcore *oc);
void SSD_direct_remove_oc(struct sess *sp, struct objcore *oc);
void SSD_direct_save_oc(struct sess *sp, struct objcore *oc);
int SSD_direct_fixup(struct sess *sp, const struct objhead *oh, struct objcore *oc);
void SSD_direct_storage_fixup(struct sess *sp, const struct objhead *oh, struct objcore *oc);
/*
 * A normal pointer difference is signed, but we never want a negative value
 * so this little tool will make sure we don't get that.
 */

static inline unsigned
pdiff(const void *b, const void *e)
{

	assert(b <= e);
	return
	    ((unsigned)((const unsigned char *)e - (const unsigned char *)b));
}

static inline void
Tcheck(const txt t)
{

	AN(t.b);
	AN(t.e);
	assert(t.b <= t.e);
}

/*
 * unsigned length of a txt
 */

static inline unsigned
Tlen(const txt t)
{

	Tcheck(t);
	return ((unsigned)(t.e - t.b));
}

static inline void
Tadd(txt *t, const char *p, int l)
{
	Tcheck(*t);

	if (l <= 0) {
	} if (t->b + l < t->e) {
		memcpy(t->b, p, l);
		t->b += l;
	} else {
		t->b = t->e;
	}
}

static inline unsigned
ObjIsBusy(const struct object *o)
{
	CHECK_OBJ_NOTNULL(o, OBJECT_MAGIC);
	CHECK_OBJ_NOTNULL(o->objcore, OBJCORE_MAGIC);
	return (o->objcore->flags & OC_F_BUSY);
}

/* Thread-local random state for random_r. Instantiated in cache_pool.c */
extern __thread struct random_data randbuf;

/* Thread-local thread ID, also instantiated in cache_pool.c */
extern __thread pid_t tid;
extern __thread uint8_t ripidx;
extern __thread uint8_t ripctr;
/* It is extremely important that these fields remain cacheline aligned */
struct rip_ring {
	char		name[64];
	uintptr_t	rip[32];
};
extern struct rip_ring *rip_ring;

#define initrip(R, T, M, I, C)			\
	do {					\
		T = syscall(SYS_gettid);	\
		if (T > M) {			\
			T = 0;			\
		}				\
		memset(&R[T], 0, sizeof (*R));	\
		I = 0;				\
		C = 0;				\
	} while (0)

#define setrip()										\
	do {											\
		uint64_t setrip__rip;								\
		__asm__ __volatile__("leaq 0(%%rip), %0" : "=q" (setrip__rip));			\
		rip_ring[tid].rip[ripidx++ & 31] = (((uintptr_t)ripctr++ << 56)|setrip__rip);	\
	} while (0)

