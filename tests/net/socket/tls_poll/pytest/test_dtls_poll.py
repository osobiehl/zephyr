# SPDX-FileCopyrightText: Copyright The Zephyr Project Contributors
# SPDX-License-Identifier: Apache-2.0

import contextlib
import re
import select
import shutil
import socket
import subprocess
import time

import pytest
from twister_harness import DeviceAdapter


class Client:
    def __init__(self, port):
        self.process = subprocess.Popen(
            [
                'openssl',
                's_client',
                '-dtls1_2',
                '-brief',
                '-connect',
                f'127.0.0.1:{port}',
                '-psk',
                '0102030405060708090a0b0c0d0e0f10',
                '-psk_identity',
                'poll_test',
                '-cipher',
                'PSK-AES256-CBC-SHA384',
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

    def receive(self, marker, timeout=2):
        deadline = time.monotonic() + timeout
        output = b''
        while marker not in output:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                break
            chunk = self.process.stdout.read(4096)
            if not chunk:
                break
            output += chunk
        return output

    def handshake(self):
        output = self.receive(b'CONNECTION ESTABLISHED')
        return b'CONNECTION ESTABLISHED' in output

    def echo(self):
        self.process.stdin.write(b'probe\n')
        assert b'probe\n' in self.receive(b'probe\n'), 'Encrypted echo failed'

    def close(self, graceful=False):
        try:
            if graceful:
                self.process.stdin.write(b'Q\n')
                self.process.wait(timeout=2)
        finally:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=2)
            self.process.stdin.close()
            self.process.stdout.close()


@contextlib.contextmanager
def client(port, graceful=False):
    peer = Client(port)
    try:
        yield peer
    finally:
        peer.close(graceful)


def read_match(dut, pattern):
    lines = dut.readlines_until(regex=pattern, timeout=3)
    return re.search(pattern, lines[-1])


@pytest.fixture
def server(unlaunched_dut: DeviceAdapter):
    if shutil.which('openssl') is None:
        pytest.skip('OpenSSL is required')
    ciphers = subprocess.run(
        ['openssl', 'ciphers', 'PSK-AES256-CBC-SHA384'],
        capture_output=True,
        text=True,
        check=False,
    )
    if ciphers.returncode != 0 or 'PSK-AES256-CBC-SHA384' not in ciphers.stdout:
        pytest.skip('OpenSSL does not support PSK-AES256-CBC-SHA384')
    dut = unlaunched_dut
    dut.launch()
    ready = read_match(dut, r'READY (\d+) (\d+)')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        control.settimeout(2)
        control.connect(('127.0.0.1', int(ready[2])))
        yield dut, int(ready[1]), control


def command(control, data):
    control.send(data)
    assert control.recv(64) == data, 'Ordinary UDP descriptor stopped responding'


def check_mixed(dut, control):
    for _ in range(3):
        command(control, b'e')
        read_match(dut, r'^EVENT$')
        command(control, b'udp')


def test_abandoned_sessions(server):
    dut, port, control = server
    with client(port) as peer:
        assert peer.handshake(), 'Initial handshake failed'
    abandoned = time.monotonic()

    # A second peer cannot use either occupied session slot. Killing OpenSSL
    # omits close_notify, leaving expiry as the only way to reclaim the slot.
    with client(port) as peer:
        assert not peer.handshake(), 'The two-entry session pool was not full'
    check_mixed(dut, control)

    for _ in range(2):
        time.sleep(max(0, abandoned + 6 - time.monotonic()))
        with client(port) as peer:
            assert peer.handshake(), 'Session expiry did not restore connectivity'
            peer.echo()
        abandoned = time.monotonic()
        check_mixed(dut, control)
    tick = read_match(dut, r'TICK (\d+)')
    assert int(tick[1]) >= 1000, 'Simulator clock stopped'


def test_graceful_reconnect(server):
    dut, port, control = server
    for _ in range(3):
        with client(port, graceful=True) as peer:
            assert peer.handshake(), 'Handshake after graceful close failed'
            peer.echo()
            check_mixed(dut, control)
        read_match(dut, r'^CLOSED$')


def test_handshake_poll_deadline(server):
    dut, port, control = server
    command(control, b'f')
    read_match(dut, r'POLL_START 250')
    with client(port, graceful=True) as peer:
        assert peer.handshake(), 'Handshake failed'
        # Handshake records wake the underlying socket without application data.
        result = read_match(dut, r'POLL 250 (\d+) (\d+)')
        assert int(result[1]) == 0
        assert 250 <= int(result[2]) <= 300, 'Poll deadline changed across retries'
        peer.echo()
        command(control, b'z')
        result = read_match(dut, r'POLL 0 (\d+) (\d+)')
        assert int(result[1]) == 0
        assert int(result[2]) <= 10, 'Zero-time poll blocked'
        check_mixed(dut, control)
