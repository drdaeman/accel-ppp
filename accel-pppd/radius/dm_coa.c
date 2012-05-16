#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "crypto.h"

#include "triton.h"
#include "events.h"
#include "log.h"

#include "radius_p.h"

#include "memdebug.h"

#define PD_COA_PORT 3799

struct dm_coa_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
};

static struct dm_coa_serv_t serv;

static int dm_coa_check_RA(struct rad_packet_t *pack, const char *secret)
{
	uint8_t RA[16];
	MD5_CTX ctx;

	memset(RA, 0, 16);
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, pack->buf, 4);
	MD5_Update(&ctx, RA, 16);
	MD5_Update(&ctx, pack->buf + 20, pack->len - 20);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(RA, &ctx);

	return memcmp(RA, pack->buf + 4, 16);
}

static void dm_coa_set_RA(struct rad_packet_t *pack, const char *secret)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, pack->buf, pack->len);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(pack->buf + 4, &ctx);
}

static int dm_coa_send_ack(int fd, struct rad_packet_t *req, struct sockaddr_in *addr)
{
	struct rad_packet_t *reply;
	uint8_t RA[16];

	memcpy(RA, req->buf + 4, sizeof(RA));

	reply = rad_packet_alloc(req->code == CODE_COA_REQUEST ? CODE_COA_ACK : CODE_DISCONNECT_ACK);
	if (!reply)
		return -1;

	reply->id = req->id;
	
	if (rad_packet_build(reply, RA)) {
		rad_packet_free(reply);
		return -1;
	}

	dm_coa_set_RA(reply, conf_dm_coa_secret);

	if (conf_verbose) {
		log_ppp_info2("send ");
		rad_packet_print(reply, NULL, log_ppp_info2);
	}

	rad_packet_send(reply, fd, addr);
	
	rad_packet_free(reply);

	return 0;
}

static int dm_coa_send_nak(int fd, struct rad_packet_t *req, struct sockaddr_in *addr, int err_code)
{
	struct rad_packet_t *reply;
	uint8_t RA[16];

	memcpy(RA, req->buf + 4, sizeof(RA));

	reply = rad_packet_alloc(req->code == CODE_COA_REQUEST ? CODE_COA_NAK : CODE_DISCONNECT_NAK);
	if (!reply)
		return -1;

	reply->id = req->id;

	if (err_code)
		rad_packet_add_int(reply, NULL, "Error-Cause", err_code);

	if (rad_packet_build(reply, RA)) {
		rad_packet_free(reply);
		return -1;
	}

	dm_coa_set_RA(reply, conf_dm_coa_secret);

	if (conf_verbose) {
		log_ppp_info2("send ");
		rad_packet_print(reply, NULL, log_ppp_info2);
	}

	rad_packet_send(reply, fd, addr);
	
	rad_packet_free(reply);

	return 0;
}

int dm_coa_free(struct radius_pd_t *rpd)
{
	int c;

	c = __sync_sub_and_fetch(&rpd->dm_coa_req->counter, 1);
	if (!c) {
		if (rpd->dm_coa_req->res)
			dm_coa_send_nak(serv.hnd.fd, rpd->dm_coa_req->pack, &rpd->dm_coa_req->addr, 0);
		else
			dm_coa_send_ack(serv.hnd.fd, rpd->dm_coa_req->pack, &rpd->dm_coa_req->addr);

		rad_packet_free(rpd->dm_coa_req->pack);
		_free(rpd->dm_coa_req);

		pthread_mutex_lock(&rpd->lock);
		rpd->dm_coa_req = NULL;
		pthread_mutex_unlock(&rpd->lock);
	}
	return c;
}

static void disconnect_request(struct radius_pd_t *rpd)
{
	if (conf_verbose) {
		log_ppp_info2("recv ");
		rad_packet_print(rpd->dm_coa_req->pack, NULL, log_ppp_info2);
	}

	dm_coa_free(rpd);

	ppp_terminate(rpd->ppp, TERM_ADMIN_RESET, 0);
}

static void coa_request(struct radius_pd_t *rpd)
{
	struct ev_radius_t ev = {
		.ppp = rpd->ppp,
		.request = rpd->dm_coa_req->pack,
	};

	if (conf_verbose) {
		log_ppp_info2("recv ");
		rad_packet_print(rpd->dm_coa_req->pack, NULL, log_ppp_info2);
	}

	triton_event_fire(EV_RADIUS_COA, &ev);

	if (ev.res)
		__sync_add_and_fetch(&rpd->dm_coa_req->res, 1);
	
	dm_coa_free(rpd);
}

void dm_coa_cancel(struct radius_pd_t *rpd)
{
	triton_cancel_call(rpd->ppp->ctrl->ctx, (triton_event_func)disconnect_request);
	triton_cancel_call(rpd->ppp->ctrl->ctx, (triton_event_func)coa_request);
	dm_coa_free(rpd);
}

static int dm_coa_read_session_match(struct radius_pd_t *rpd, void *data)
{
	struct rad_dm_coa_req_t *req = (struct rad_dm_coa_req_t *)data;

	if (rpd->dm_coa_req) {
		pthread_mutex_unlock(&rpd->lock);
		return -1;
	}

	__sync_add_and_fetch(&req->counter, 1);
	rpd->dm_coa_req = req;

	if (req->pack->code == CODE_DISCONNECT_REQUEST)
		triton_context_call(rpd->ppp->ctrl->ctx, (triton_event_func)disconnect_request, rpd);
	else
		triton_context_call(rpd->ppp->ctrl->ctx, (triton_event_func)coa_request, rpd);

	pthread_mutex_unlock(&rpd->lock);
	return 0;
}

static int dm_coa_read(struct triton_md_handler_t *h)
{
	struct rad_dm_coa_req_t *req;
	int err_code, res;

	while (1) {
		req = (struct rad_dm_coa_req_t *)_malloc(sizeof(*req));
		req->counter = 0;
		req->res = 0;

		if (rad_packet_recv(h->fd, &req->pack, &req->addr)) {
			_free(req);
			return 0;
		}

		if (!req->pack) {
			_free(req);
			continue;
		}

		if (req->pack->code != CODE_DISCONNECT_REQUEST && req->pack->code != CODE_COA_REQUEST) {
			log_warn("radius:dm_coa: unexpected code (%i) received\n", req->pack->code);
			goto out_err_no_reply;
		}

		if (dm_coa_check_RA(req->pack, conf_dm_coa_secret)) {
			log_warn("radius:dm_coa: RA validation failed\n");
			goto out_err_no_reply;
		}

		if (conf_verbose) {
			log_debug("recv ");
			rad_packet_print(req->pack, NULL, log_debug);
		}

		if (rad_check_nas_pack(req->pack)) {
			log_warn("radius:dm_coa: NAS identification failed\n");
			err_code = 403;
			goto out_err;
		}

		res = rad_find_sessions_pack(req->pack, &dm_coa_read_session_match, (void *)req);
		if (res <= 0) {
			if (res == 0) {
				log_warn("radius:dm_coa: no session(s) found\n");
				err_code = 503;
			} else if (res == -2) {
				log_warn("radius:dm_coa: unknown session identification attribute(s) found\n");
				err_code = 401;
			} else {
				log_warn("radius:dm_coa: no valid matching attributes found\n");
				err_code = 402;
			}
			goto out_err;
		} else if (conf_verbose) {
			log_ppp_info2("radius:dm_coa: %d session(s) matched request\n", res);
		}

		continue;

	out_err:
		dm_coa_send_nak(h->fd, req->pack, &req->addr, err_code);

	out_err_no_reply:
		rad_packet_free(req->pack);
		_free(req);
	}
}

static void dm_coa_close(struct triton_context_t *ctx)
{
	struct dm_coa_serv_t *serv = container_of(ctx, typeof(*serv), ctx);
	triton_md_unregister_handler(&serv->hnd);
	close(serv->hnd.fd);
	triton_context_unregister(ctx);
}

static struct dm_coa_serv_t serv = {
	.ctx.close = dm_coa_close,
	.ctx.before_switch = log_switch,
	.hnd.read = dm_coa_read,
};

static void init(void)
{
	struct sockaddr_in addr;

	if (!conf_dm_coa_secret) {
		log_emerg("radius: no dm_coa_secret specified, DM/CoA disabled...\n");
		return;
	}

	serv.hnd.fd = socket (PF_INET, SOCK_DGRAM, 0);
  if (serv.hnd.fd < 0) {
    log_emerg("radius:dm_coa: socket: %s\n", strerror(errno));
    return;
  }
	
	fcntl(serv.hnd.fd, F_SETFD, fcntl(serv.hnd.fd, F_GETFD) | FD_CLOEXEC);

  addr.sin_family = AF_INET;
  addr.sin_port = htons (conf_dm_coa_port);
	if (conf_dm_coa_server)
	  addr.sin_addr.s_addr = conf_dm_coa_server;
	else
		addr.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    log_emerg("radius:dm_coa: bind: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
  }

	if (fcntl(serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("radius:dm_coa: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
	}
	
	triton_context_register(&serv.ctx, NULL);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&serv.ctx);
}

DEFINE_INIT(52, init);
