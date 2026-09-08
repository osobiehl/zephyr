/*
 * SPDX-FileCopyrightText: Copyright The Zephyr Project Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/fdtable.h>
#include <zephyr/ztest.h>
#include <zephyr/zvfs/eventfd.h>

#define INTERVAL_MS 40
#define TIMEOUT_MS  160
#define FUZZ_MS     30

/* A filtering socket consumes control packets without reporting application
 * data, as TLS does during a handshake. Forward preparation and update to the
 * real socket backend to exercise its registration and signal lifecycle.
 */
static struct {
	int socket;
	uint32_t updates;
	uint32_t discarded;
	bool already;
} filter;
static int sender;
static int filtered_fd;
static struct net_sockaddr_in destination;
static struct k_thread sender_thread;
static bool sender_started;
static K_THREAD_STACK_DEFINE(sender_stack, 1024);

static int filter_ioctl(void *obj, unsigned int request, va_list args)
{
	const struct fd_op_vtable *vtable;
	struct k_mutex *lock;
	struct zsock_pollfd *pfd;
	struct k_poll_event **pev;
	void *socket_obj;
	int ret;

	ARG_UNUSED(obj);
	if (request != ZFD_IOCTL_POLL_PREPARE && request != ZFD_IOCTL_POLL_UPDATE) {
		return -EOPNOTSUPP;
	}

	pfd = va_arg(args, struct zsock_pollfd *);
	pev = va_arg(args, struct k_poll_event **);
	if (request == ZFD_IOCTL_POLL_UPDATE) {
		/* Bound a stale-signal spin even when simulator time stops. */
		zassert_true(++filter.updates < 20U, "poll retry did not block");
	}
	socket_obj = zvfs_get_fd_obj_and_vtable(filter.socket, &vtable, &lock);
	zassert_not_null(socket_obj);
	zassert_ok(k_mutex_lock(lock, K_FOREVER));
	if (request == ZFD_IOCTL_POLL_PREPARE) {
		struct k_poll_event *end = va_arg(args, struct k_poll_event *);

		ret = zvfs_fdtable_call_ioctl(vtable, socket_obj, request, pfd, pev, end);
		if (ret == 0 && filter.already) {
			filter.already = false;
			ret = -EALREADY;
		}
	} else {
		ret = zvfs_fdtable_call_ioctl(vtable, socket_obj, request, pfd, pev);
	}
	zassert_ok(k_mutex_unlock(lock));

	if (request == ZFD_IOCTL_POLL_UPDATE && ret == 0 &&
	    (pfd->revents & ZSOCK_POLLIN) != 0) {
		char packet;
		int received;

		received = zsock_recv(filter.socket, &packet, sizeof(packet), ZSOCK_MSG_DONTWAIT);
		if (received < 0 && errno == EAGAIN) {
			pfd->revents = 0;
			(*pev - 1)->state = K_POLL_STATE_NOT_READY;
			return -EAGAIN;
		}
		zassert_equal(received, sizeof(packet));
		if (packet == 'c') {
			filter.discarded++;
			pfd->revents = 0;
			(*pev - 1)->state = K_POLL_STATE_NOT_READY;
			return -EAGAIN;
		}
		if (packet == 'e') {
			pfd->revents = ZSOCK_POLLERR;
		}
	}

	return ret;
}

static const struct fd_op_vtable filter_vtable = {
	.ioctl = filter_ioctl,
};

static void send_packet(char packet)
{
	zassert_equal(zsock_sendto(sender, &packet, sizeof(packet), 0,
				  (struct net_sockaddr *)&destination, sizeof(destination)),
		      sizeof(packet));
}

static void send_packets(void *packets, void *unused1, void *unused2)
{
	const char *next = packets;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	while (*next != '\0') {
		k_msleep(INTERVAL_MS);
		send_packet(*next++);
	}
}

static void start_sender(const char *packets)
{
	sender_started = true;
	k_thread_create(&sender_thread, sender_stack, K_THREAD_STACK_SIZEOF(sender_stack),
			send_packets, (void *)packets, NULL, NULL, K_PRIO_PREEMPT(1), 0,
			K_NO_WAIT);
}

static void finish_sender(void)
{
	zassert_ok(k_thread_join(&sender_thread, K_SECONDS(1)));
	sender_started = false;
}

static void before(void *fixture)
{
	net_socklen_t addrlen = sizeof(destination);

	ARG_UNUSED(fixture);
	memset(&filter, 0, sizeof(filter));
	filter.socket = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_UDP);
	zassert_true(filter.socket >= 0);
	sender = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_UDP);
	zassert_true(sender >= 0);
	destination = (struct net_sockaddr_in) {
		.sin_family = NET_AF_INET,
		.sin_addr.s_addr = NET_INADDR_ANY,
	};
	zassert_ok(zsock_bind(filter.socket, (struct net_sockaddr *)&destination,
			     sizeof(destination)));
	zassert_ok(zsock_getsockname(filter.socket, (struct net_sockaddr *)&destination,
				    &addrlen));
	zassert_equal(zsock_inet_pton(NET_AF_INET, "127.0.0.1", &destination.sin_addr), 1);
	filtered_fd = zvfs_alloc_fd(&filter, &filter_vtable);
	zassert_true(filtered_fd >= 0);
}

static void after(void *fixture)
{
	ARG_UNUSED(fixture);
	if (sender_started) {
		k_thread_abort(&sender_thread);
		sender_started = false;
	}
	zvfs_free_fd(filtered_fd);
	zassert_ok(zsock_close(filter.socket));
	zassert_ok(zsock_close(sender));
}

ZTEST(socket_poll_retry, test_no_wait)
{
	struct zsock_pollfd pfd = {.fd = filtered_fd, .events = ZSOCK_POLLIN};
	int64_t start;

	send_packet('c');
	k_msleep(INTERVAL_MS);
	start = k_uptime_get();
	zassert_equal(zsock_poll(&pfd, 1, 0), 0);
	zassert_equal(pfd.revents, 0);
	zassert_true(k_uptime_get() - start < FUZZ_MS);
	zassert_equal(filter.discarded, 1);

	/* A second call must be able to register the same socket again. */
	zassert_equal(zsock_poll(&pfd, 1, 0), 0);
}

static void check_deadline(bool already)
{
	struct zsock_pollfd pfd = {.fd = filtered_fd, .events = ZSOCK_POLLIN};
	int64_t start;
	int64_t elapsed;

	filter.already = already;
	if (already) {
		send_packet('c');
		k_msleep(INTERVAL_MS);
	}
	start_sender("cc");
	start = k_uptime_get();
	zassert_equal(zsock_poll(&pfd, 1, TIMEOUT_MS), 0);
	elapsed = k_uptime_get() - start;
	zassert_true(elapsed >= TIMEOUT_MS && elapsed <= TIMEOUT_MS + FUZZ_MS,
		     "deadline changed: %lld ms", (long long)elapsed);
	zassert_equal(pfd.revents, 0);
	zassert_equal(filter.discarded, already ? 3 : 2);
	finish_sender();
}

ZTEST(socket_poll_retry, test_finite_deadline)
{
	check_deadline(false);
}

ZTEST(socket_poll_retry, test_already_ready_deadline)
{
	check_deadline(true);
}

ZTEST(socket_poll_retry, test_infinite_wait)
{
	struct zsock_pollfd pfd = {.fd = filtered_fd, .events = ZSOCK_POLLIN};

	start_sender("ccd");
	zassert_equal(zsock_poll(&pfd, 1, -1), 1);
	zassert_equal(pfd.revents, ZSOCK_POLLIN);
	zassert_equal(filter.discarded, 2);
	finish_sender();
}

ZTEST(socket_poll_retry, test_error_after_retry)
{
	struct zsock_pollfd pfd = {.fd = filtered_fd, .events = ZSOCK_POLLIN};

	start_sender("ce");
	zassert_equal(zsock_poll(&pfd, 1, TIMEOUT_MS), 1);
	zassert_equal(pfd.revents, ZSOCK_POLLERR);
	finish_sender();
	zassert_equal(zsock_poll(&pfd, 1, 0), 0);
}

ZTEST(socket_poll_retry, test_mixed_ready)
{
	int event = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	struct zsock_pollfd fds[] = {
		{.fd = filtered_fd, .events = ZSOCK_POLLIN},
		{.fd = sender, .events = ZSOCK_POLLIN},
		{.fd = event, .events = ZSOCK_POLLIN},
	};
	zvfs_eventfd_t value;

	zassert_true(event >= 0);
	for (size_t i = 0; i < 3U; i++) {
		send_packet('c');
		k_msleep(INTERVAL_MS);
		zassert_ok(zvfs_eventfd_write(event, 1));
		zassert_equal(zsock_poll(fds, ARRAY_SIZE(fds), -1), 1);
		zassert_equal(fds[0].revents, 0);
		zassert_equal(fds[1].revents, 0);
		zassert_equal(fds[2].revents, ZSOCK_POLLIN);
		zassert_ok(zvfs_eventfd_read(event, &value));
		zassert_equal(zsock_poll(fds, ARRAY_SIZE(fds), 0), 0);
	}
	zassert_equal(filter.discarded, 3);
	zassert_ok(zvfs_close(event));
}

ZTEST_SUITE(socket_poll_retry, NULL, NULL, before, after, NULL);
