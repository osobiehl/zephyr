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

static void check_client_poll(void)
{
	struct zsock_pollfd pfd = {
		.fd = checked(zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_DTLS_1_2)),
		.events = ZSOCK_POLLIN,
	};
	struct k_poll_event events[3];
	struct k_poll_event *event_end;
	struct k_poll_event *event = events;
	const struct fd_op_vtable *vtable;
	struct k_mutex *lock;
	void *obj;
	int ret;

	obj = zvfs_get_fd_obj_and_vtable(pfd.fd, &vtable, &lock);
	__ASSERT_NO_MSG(obj != NULL);
	checked(k_mutex_lock(lock, K_FOREVER));
	ret = zvfs_fdtable_call_ioctl(vtable, obj, ZFD_IOCTL_POLL_PREPARE,
				     &pfd, &event, events + ARRAY_SIZE(events));
	__ASSERT_NO_MSG(ret == 0 || ret == -EALREADY);
	checked(k_mutex_unlock(lock));
	event_end = event;

	/* Isolate the client handshake notification from the handshake's own
	 * socket polling. Updating it must release the NSOS registration that
	 * was prepared alongside the semaphore, even when another fd is ready
	 * and poll() will return without retrying.
	 */
	__ASSERT_NO_MSG(events[0].type == K_POLL_TYPE_SEM_AVAILABLE);
	k_sem_give(events[0].sem);
	checked(k_poll(events, event_end - events, K_NO_WAIT));
	event = events;
	checked(k_mutex_lock(lock, K_FOREVER));
	ret = zvfs_fdtable_call_ioctl(vtable, obj, ZFD_IOCTL_POLL_UPDATE, &pfd, &event);
	__ASSERT_NO_MSG(ret == -EAGAIN);
	__ASSERT_NO_MSG(event == event_end);
	checked(k_mutex_unlock(lock));

	/* A subsequent poll must be able to register the same socket again. */
	pfd.events = 0;
	ret = checked(zsock_poll(&pfd, 1, 0));
	__ASSERT_NO_MSG(ret == 0);
	checked(zsock_close(pfd.fd));
	printk("CLIENT_POLL_OK\n");
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
