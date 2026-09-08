/*
 * SPDX-FileCopyrightText: Copyright The Zephyr Project Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/sys/fdtable.h>
#include <zephyr/zvfs/eventfd.h>

static int checked(int result)
{
	__ASSERT(result >= 0, "Socket operation failed: %d, errno %d", result, errno);
	return result;
}

static void heartbeat(void *unused1, void *unused2, void *unused3)
{
	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	ARG_UNUSED(unused3);

	while (true) {
		k_sleep(K_SECONDS(1));
		printk("TICK %lld\n", (long long)k_uptime_get());
	}
}

K_THREAD_DEFINE(ticker, 1024, heartbeat, NULL, NULL, NULL, 5, 0, 0);

static uint16_t bind_socket(int fd)
{
	struct net_sockaddr_in address = {
		.sin_family = NET_AF_INET,
		.sin_addr.s_addr = NET_INADDR_ANY,
	};
	net_socklen_t len = sizeof(address);

	checked(zsock_bind(fd, (struct net_sockaddr *)&address, sizeof(address)));
	checked(zsock_getsockname(fd, (struct net_sockaddr *)&address, &len));
	return net_ntohs(address.sin_port);
}

static int poll_ioctl(struct zsock_pollfd *pfd, unsigned int request,
		      struct k_poll_event **event, struct k_poll_event *end)
{
	const struct fd_op_vtable *vtable;
	struct k_mutex *lock;
	void *obj;
	int ret;

	obj = zvfs_get_fd_obj_and_vtable(pfd->fd, &vtable, &lock);
	__ASSERT_NO_MSG(obj != NULL);
	checked(k_mutex_lock(lock, K_FOREVER));
	ret = zvfs_fdtable_call_ioctl(vtable, obj, request, pfd, event, end);
	checked(k_mutex_unlock(lock));
	return ret;
}

static int client_eventfd;

static void notify_client_eventfd(struct k_work *work)
{
	ARG_UNUSED(work);
	checked(zvfs_eventfd_write(client_eventfd, 1));
}

static void check_client_poll(void)
{
	struct zsock_pollfd fds[] = {
		{
			.fd = checked(zsock_socket(NET_AF_INET, NET_SOCK_DGRAM,
						   NET_IPPROTO_DTLS_1_2)),
			.events = ZSOCK_POLLIN,
		},
		{
			.fd = checked(zvfs_eventfd(0, ZVFS_EFD_NONBLOCK)),
			.events = ZSOCK_POLLIN,
		},
	};
	struct k_poll_event events[3] = {0};
	struct k_poll_event *client_end;
	struct k_poll_event *event_end;
	struct k_poll_event *event = events;
	struct k_sem *handshake;
	struct k_work_delayable notify;
	struct k_work_sync sync;
	zvfs_eventfd_t value;
	int64_t start;
	int64_t elapsed;
	int ret;

	/* A full event array must not be overwritten by the handshake slot. */
	ret = poll_ioctl(&fds[0], ZFD_IOCTL_POLL_PREPARE, &event, events);
	__ASSERT_NO_MSG(ret == -ENOMEM);
	__ASSERT_NO_MSG(event == events && events[0].obj == NULL);

	ret = poll_ioctl(&fds[0], ZFD_IOCTL_POLL_PREPARE, &event,
			 events + ARRAY_SIZE(events));
	__ASSERT_NO_MSG(ret == 0 || ret == -EALREADY);
	client_end = event;
	checked(poll_ioctl(&fds[1], ZFD_IOCTL_POLL_PREPARE, &event,
			   events + ARRAY_SIZE(events)));
	event_end = event;

	/* Simulate the client handshake notification independently of the
	 * handshake's own I/O. Update must consume the original event span.
	 */
	__ASSERT_NO_MSG(events[0].type == K_POLL_TYPE_SEM_AVAILABLE);
	handshake = events[0].sem;
	k_sem_give(handshake);
	checked(k_poll(events, event_end - events, K_NO_WAIT));
	event = events;
	ret = poll_ioctl(&fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL);
	__ASSERT_NO_MSG(ret == -EAGAIN && event == client_end);
	checked(poll_ioctl(&fds[1], ZFD_IOCTL_POLL_UPDATE, &event, NULL));
	__ASSERT_NO_MSG(event == event_end && fds[1].revents == 0);

	/* The completed semaphore must not wake a retry. The following fd must
	 * still wake it promptly, using the same prepared kernel events.
	 */
	__ASSERT_NO_MSG(k_poll(events, event_end - events, K_NO_WAIT) == -EAGAIN);
	client_eventfd = fds[1].fd;
	k_work_init_delayable(&notify, notify_client_eventfd);
	checked(k_work_schedule(&notify, K_MSEC(40)));
	start = k_uptime_get();
	checked(k_poll(events, event_end - events, K_MSEC(160)));
	elapsed = k_uptime_get() - start;
	(void)k_work_cancel_delayable_sync(&notify, &sync);
	__ASSERT(elapsed >= 40 && elapsed < 120, "Mixed poll woke after %lld ms",
		 (long long)elapsed);
	/* Only the completion notification was simulated, not a cryptographic
	 * handshake. Restore it before update checks the TLS session itself.
	 */
	k_sem_reset(handshake);
	event = events;
	checked(poll_ioctl(&fds[0], ZFD_IOCTL_POLL_UPDATE, &event, NULL));
	__ASSERT_NO_MSG(event == client_end && fds[0].revents == 0);
	checked(poll_ioctl(&fds[1], ZFD_IOCTL_POLL_UPDATE, &event, NULL));
	__ASSERT_NO_MSG(event == event_end && fds[1].revents == ZSOCK_POLLIN);
	checked(zvfs_eventfd_read(fds[1].fd, &value));

	/* A subsequent poll must be able to register the same socket again. */
	fds[0].events = 0;
	ret = checked(zsock_poll(fds, ARRAY_SIZE(fds), 0));
	__ASSERT_NO_MSG(ret == 0);
	checked(zsock_close(fds[0].fd));
	checked(zvfs_close(fds[1].fd));
	printk("CLIENT_POLL_OK\n");
}

struct client_handshake {
	int client;
	int server;
	int eventfd;
	struct net_sockaddr_in address;
};

static K_THREAD_STACK_DEFINE(client_stack, 4096);
static K_THREAD_STACK_DEFINE(server_stack, 4096);

static void client_send(void *arg, void *unused1, void *unused2)
{
	struct client_handshake *test = arg;
	char data = 'q';

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	checked(zsock_connect(test->client, (struct net_sockaddr *)&test->address,
			      sizeof(test->address)));
	__ASSERT_NO_MSG(zsock_send(test->client, &data, sizeof(data), 0) == sizeof(data));
}

static void server_receive(void *arg, void *unused1, void *unused2)
{
	struct client_handshake *test = arg;
	struct net_sockaddr_in peer;
	net_socklen_t len = sizeof(peer);
	char data;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	__ASSERT_NO_MSG(zsock_recvfrom(test->server, &data, sizeof(data), 0,
				      (struct net_sockaddr *)&peer, &len) == sizeof(data));
	__ASSERT_NO_MSG(data == 'q');

	/* Complete the handshake before waking the fd after the TLS client.
	 * Send encrypted data later, so it cannot hide a missed eventfd wakeup.
	 */
	k_msleep(40);
	checked(zvfs_eventfd_write(test->eventfd, 1));
	k_msleep(40);
	data = 'r';
	__ASSERT_NO_MSG(zsock_sendto(test->server, &data, sizeof(data), 0,
				    (struct net_sockaddr *)&peer, len) == sizeof(data));
}

static void check_client_handshake(void)
{
	struct client_handshake test = {
		.client = checked(zsock_socket(NET_AF_INET, NET_SOCK_DGRAM,
						NET_IPPROTO_DTLS_1_2)),
		.server = checked(zsock_socket(NET_AF_INET, NET_SOCK_DGRAM,
						NET_IPPROTO_DTLS_1_2)),
		.eventfd = checked(zvfs_eventfd(0, ZVFS_EFD_NONBLOCK)),
		.address.sin_family = NET_AF_INET,
	};
	struct zsock_pollfd fds[] = {
		{.fd = test.client, .events = ZSOCK_POLLIN},
		{.fd = test.eventfd, .events = ZSOCK_POLLIN},
	};
	struct k_thread client_thread;
	struct k_thread server_thread;
	const sec_tag_t tag = 1;
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	zvfs_eventfd_t value;
	char data;

	checked(zsock_setsockopt(test.client, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
				&tag, sizeof(tag)));
	checked(zsock_setsockopt(test.server, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
				&tag, sizeof(tag)));
	checked(zsock_setsockopt(test.server, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE,
				&role, sizeof(role)));
	test.address.sin_port = net_htons(bind_socket(test.server));
	__ASSERT_NO_MSG(zsock_inet_pton(NET_AF_INET, "127.0.0.1", &test.address.sin_addr) == 1);

	k_thread_create(&server_thread, server_stack, K_THREAD_STACK_SIZEOF(server_stack),
			server_receive, &test, NULL, NULL, K_PRIO_PREEMPT(1), 0, K_NO_WAIT);
	/* Start the client's handshake after poll has prepared its events. */
	k_thread_create(&client_thread, client_stack, K_THREAD_STACK_SIZEOF(client_stack),
			client_send, &test, NULL, NULL, K_PRIO_PREEMPT(1), 0, K_MSEC(40));
	__ASSERT_NO_MSG(zsock_poll(fds, ARRAY_SIZE(fds), 1000) == 1);
	__ASSERT_NO_MSG(fds[0].revents == 0 && fds[1].revents == ZSOCK_POLLIN);
	checked(zvfs_eventfd_read(test.eventfd, &value));

	__ASSERT_NO_MSG(zsock_poll(fds, ARRAY_SIZE(fds), 1000) == 1);
	__ASSERT_NO_MSG(fds[0].revents == ZSOCK_POLLIN && fds[1].revents == 0);
	__ASSERT_NO_MSG(zsock_recv(test.client, &data, sizeof(data), ZSOCK_MSG_DONTWAIT) ==
		       sizeof(data));
	__ASSERT_NO_MSG(data == 'r');
	checked(k_thread_join(&client_thread, K_SECONDS(1)));
	checked(k_thread_join(&server_thread, K_SECONDS(1)));
	checked(zsock_close(test.client));
	checked(zsock_close(test.server));
	checked(zvfs_close(test.eventfd));
	printk("CLIENT_HANDSHAKE_OK\n");
}

int main(void)
{
	static const unsigned char psk[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	static const char identity[] = "poll_test";
	const sec_tag_t tag = 1;
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	struct zsock_pollfd fds[3];
	uint16_t dtls_port;
	uint16_t udp_port;
	int timeout = -1;

	checked(tls_credential_add(tag, TLS_CREDENTIAL_PSK, psk, sizeof(psk)));
	checked(tls_credential_add(tag, TLS_CREDENTIAL_PSK_ID, identity, sizeof(identity) - 1));

	check_client_poll();
	check_client_handshake();
	if (!IS_ENABLED(CONFIG_NET_NATIVE_OFFLOADED_SOCKETS)) {
		return 0;
	}

	/* Reserve one session so an abandoned peer fills the two-entry pool. */
	checked(zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TLS_1_2));
	fds[0].fd = checked(zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_DTLS_1_2));
	checked(zsock_setsockopt(fds[0].fd, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
				&tag, sizeof(tag)));
	checked(zsock_setsockopt(fds[0].fd, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE,
				&role, sizeof(role)));
	dtls_port = bind_socket(fds[0].fd);
	fds[1].fd = checked(zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_UDP));
	udp_port = bind_socket(fds[1].fd);
	fds[2].fd = checked(zvfs_eventfd(0, ZVFS_EFD_NONBLOCK));
	for (size_t i = 0; i < ARRAY_SIZE(fds); i++) {
		fds[i].events = ZSOCK_POLLIN;
	}
	printk("READY %u %u\n", dtls_port, udp_port);

	while (true) {
		int64_t start = k_uptime_get();
		int ret = checked(zsock_poll(fds, ARRAY_SIZE(fds), timeout));

		if (timeout >= 0) {
			printk("POLL %d %d %lld\n", timeout, ret,
			       (long long)(k_uptime_get() - start));
			timeout = -1;
		}
		if ((fds[0].revents & ZSOCK_POLLHUP) != 0) {
			printk("CLOSED\n");
		}
		if ((fds[0].revents & ZSOCK_POLLERR) != 0) {
			printk("SOCKET_ERROR\n");
		}
		for (size_t i = 0; i < 2U; i++) {
			struct net_sockaddr_in peer;
			net_socklen_t len = sizeof(peer);
			char data[64];
			int received;

			if ((fds[i].revents & ZSOCK_POLLIN) == 0) {
				continue;
			}
			received = checked(zsock_recvfrom(fds[i].fd, data, sizeof(data),
							 ZSOCK_MSG_DONTWAIT,
							 (struct net_sockaddr *)&peer, &len));
			checked(zsock_sendto(fds[i].fd, data, received, 0,
					     (struct net_sockaddr *)&peer, len));
			if (i == 1U && received == 1) {
				if (data[0] == 'e') {
					checked(zvfs_eventfd_write(fds[2].fd, 1));
				} else if (data[0] == 'z' || data[0] == 'f') {
					timeout = data[0] == 'z' ? 0 : 250;
					printk("POLL_START %d\n", timeout);
				}
			}
		}
		if ((fds[2].revents & ZSOCK_POLLIN) != 0) {
			zvfs_eventfd_t value;

			checked(zvfs_eventfd_read(fds[2].fd, &value));
			printk("EVENT\n");
		}
	}
	return 0;
}
