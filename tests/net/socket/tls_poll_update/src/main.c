/*
 * SPDX-FileCopyrightText: Copyright The Zephyr Project Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/fdtable.h>
#include <zephyr/ztest.h>
#include <zephyr/zvfs/eventfd.h>

static struct {
	struct zsock_pollfd fds[2];
	struct k_poll_event events[3];
	struct k_poll_event *client_end;
	struct k_poll_event *events_end;
	struct k_sem *handshake;
	bool prepared;
} test;

static int poll_ioctl(struct zsock_pollfd *pfd, unsigned int request,
		      struct k_poll_event **event, struct k_poll_event *end)
{
	const struct fd_op_vtable *vtable;
	struct k_mutex *lock;
	void *obj;
	int ret;

	obj = zvfs_get_fd_obj_and_vtable(pfd->fd, &vtable, &lock);
	zassert_not_null(obj);
	zassert_ok(k_mutex_lock(lock, K_FOREVER));
	ret = zvfs_fdtable_call_ioctl(vtable, obj, request, pfd, event, end);
	zassert_ok(k_mutex_unlock(lock));
	return ret;
}

static void notify_eventfd(struct k_work *work)
{
	ARG_UNUSED(work);
	zassert_ok(zvfs_eventfd_write(test.fds[1].fd, 1));
}

static K_WORK_DELAYABLE_DEFINE(notify, notify_eventfd);

static int prepare_client(size_t capacity)
{
	struct k_poll_event *event = test.events;
	int ret;

	ret = poll_ioctl(&test.fds[0], ZFD_IOCTL_POLL_PREPARE, &event,
			 test.events + capacity);
	if (ret == 0 || ret == -EALREADY) {
		test.prepared = true;
		test.client_end = event;
		test.handshake = test.events[0].sem;
	}
	return ret;
}

static void prepare_events(void)
{
	struct k_poll_event *event;
	int ret;

	ret = prepare_client(ARRAY_SIZE(test.events));
	zassert_true(ret == 0 || ret == -EALREADY);
	zassert_equal(test.events[0].type, K_POLL_TYPE_SEM_AVAILABLE);
	event = test.client_end;
	zassert_ok(poll_ioctl(&test.fds[1], ZFD_IOCTL_POLL_PREPARE, &event,
			      test.events + ARRAY_SIZE(test.events)));
	test.events_end = event;
}

static void update_pending_handshake(void)
{
	struct k_poll_event *event = test.events;

	/* Exercise a retry after an update while the handshake was pending.
	 * This also releases the original NSOS registration, isolating the TLS
	 * event transition from duplicate host registration during preparation.
	 */
	zassert_ok(poll_ioctl(&test.fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL));
	zassert_equal_ptr(event, test.client_end);
	zassert_equal(test.fds[0].revents, 0);
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	memset(&test, 0, sizeof(test));
	test.fds[0].fd = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_DTLS_1_2);
	zassert_true(test.fds[0].fd >= 0);
	test.fds[1].fd = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	zassert_true(test.fds[1].fd >= 0);
	test.fds[0].events = ZSOCK_POLLIN;
	test.fds[1].events = ZSOCK_POLLIN;
}

static void after(void *fixture)
{
	struct k_work_sync sync;

	ARG_UNUSED(fixture);
	(void)k_work_cancel_delayable_sync(&notify, &sync);
	if (test.prepared) {
		struct k_poll_event *event = test.events;

		/* Only the notification is simulated, not a cryptographic
		 * handshake. Clear it before update checks the TLS session.
		 * Finish the backend update even after a failed assertion.
		 */
		k_sem_reset(test.handshake);
		for (size_t i = 0; i < ARRAY_SIZE(test.events); i++) {
			test.events[i].state = K_POLL_STATE_NOT_READY;
		}
		test.fds[0].revents = 0;
		zassert_ok(poll_ioctl(&test.fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL));
	}
	zassert_ok(zsock_close(test.fds[0].fd));
	zassert_ok(zvfs_close(test.fds[1].fd));
}

ZTEST(tls_poll_update, test_prepare_no_space)
{
	/* The physical array includes guards to detect writes past the supplied
	 * capacity without corrupting unrelated memory on a failing build.
	 */
	zassert_equal(prepare_client(0), -ENOMEM);
	zassert_is_null(test.events[0].obj);
}

ZTEST(tls_poll_update, test_prepare_single_slot)
{
	struct k_poll_event *event = test.events;
	int ret = prepare_client(1);

	if (IS_ENABLED(CONFIG_NET_NATIVE_OFFLOADED_SOCKETS)) {
		/* NSOS needs its signal slot in addition to the semaphore. */
		zassert_equal(ret, -ENOMEM);
	} else {
		/* Native UDP can replace the semaphore in the last available
		 * slot. Its masked backend update must not access the next slot.
		 */
		zassert_ok(ret);
		k_sem_give(test.handshake);
		zassert_ok(k_poll(test.events, 1, K_NO_WAIT));
		zassert_equal(poll_ioctl(&test.fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL),
			      -EAGAIN);
		zassert_equal_ptr(event, test.events + 1);
	}
	zassert_is_null(test.events[1].obj);
}

ZTEST(tls_poll_update, test_pending_handshake)
{
	prepare_events();
	update_pending_handshake();
}

ZTEST(tls_poll_update, test_handshake_event_span)
{
	struct k_poll_event *event = test.events;

	prepare_events();
	update_pending_handshake();
	k_sem_give(test.handshake);
	zassert_ok(k_poll(test.events, test.events_end - test.events, K_NO_WAIT));
	zassert_equal(poll_ioctl(&test.fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL),
		      -EAGAIN);
	zassert_equal_ptr(event, test.client_end, "TLS changed its prepared event span");
}

ZTEST(tls_poll_update, test_following_descriptor_wakeup)
{
	struct k_poll_event *event = test.events;
	zvfs_eventfd_t value;
	int64_t start;
	int64_t elapsed;
	int ret;

	prepare_events();
	update_pending_handshake();
	k_sem_give(test.handshake);
	zassert_ok(k_poll(test.events, test.events_end - test.events, K_NO_WAIT));
	zassert_equal(poll_ioctl(&test.fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL),
		      -EAGAIN);
	zassert_ok(poll_ioctl(&test.fds[1], ZFD_IOCTL_POLL_UPDATE, &event, NULL));

	/* Like the shared poll loop, use the cursor left by update as the end
	 * of the next wait. A short TLS update omits the following fd's event.
	 */
	zassert_true(k_work_schedule(&notify, K_MSEC(40)) >= 0);
	start = k_uptime_get();
	ret = k_poll(test.events, event - test.events, K_MSEC(160));
	elapsed = k_uptime_get() - start;
	zassert_ok(ret, "Following descriptor did not wake poll");
	zassert_true(elapsed >= 40 && elapsed < 120, "Poll woke after %lld ms",
		     (long long)elapsed);

	k_sem_reset(test.handshake);
	event = test.events;
	zassert_ok(poll_ioctl(&test.fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL));
	zassert_equal_ptr(event, test.client_end);
	zassert_ok(poll_ioctl(&test.fds[1], ZFD_IOCTL_POLL_UPDATE, &event, NULL));
	zassert_equal_ptr(event, test.events_end);
	zassert_equal(test.fds[1].revents, ZSOCK_POLLIN);
	zassert_ok(zvfs_eventfd_read(test.fds[1].fd, &value));
}

ZTEST_SUITE(tls_poll_update, NULL, NULL, before, after, NULL);
