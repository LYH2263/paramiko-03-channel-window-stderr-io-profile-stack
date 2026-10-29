# Copyright (C) 2017  Jeff Forcier <jeff@bitprophet.org>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Unit tests for the per-Channel I/O profile stack (window feedback and stderr
merge axes), split per observable exit point:

* ``Channel.send``  -> MSG_CHANNEL_DATA
* ``Channel.send_stderr`` -> MSG_CHANNEL_EXTENDED_DATA (code=1)
* ``Channel.recv`` / ``recv_stderr`` -> in_buffer / in_stderr_buffer
* ``Channel._check_add_window`` -> MSG_CHANNEL_WINDOW_ADJUST (or silence)
* ``Channel._feed_extended`` -> primary vs stderr buffer routing
* ``Channel.set_combine_stderr`` / forbid_merge / dual_required
* ``Channel.makefile`` / ``makefile_stderr`` stay distinct file exits
* the shared, per-channel-isolated Transport mount and stack mechanics

The wire is observed with a recording fake transport; no socket is opened.
"""

import threading
import unittest

from paramiko.channel import (
    Channel,
    ChannelFile,
    ChannelStderrFile,
    ChannelIOProfile,
    EffectiveChannelIOProfile,
    ChannelIOProfileStack,
    ChannelIOProfileMount,
    STDERR_SEPARATE,
    STDERR_COMBINE_TO_STDOUT,
    STDERR_FORBID_MERGE,
    WINDOW_THRESHOLD_BATCH,
    WINDOW_ACK_EVERY_READ,
    WINDOW_SUPPRESS_ACK,
    OUTBOUND_PARTIAL_OK,
    OUTBOUND_ALL_OR_FAIL,
    OUTBOUND_DATA_VS_EXTENDED,
    STREAM_PRIMARY_OK,
    STREAM_STDERR_OK,
    STREAM_DUAL_REQUIRED,
    OUTBOUND_KIND_DATA,
    OUTBOUND_KIND_EXTENDED_DATA,
)
from paramiko.common import (
    MSG_CHANNEL_DATA,
    MSG_CHANNEL_EXTENDED_DATA,
    MSG_CHANNEL_WINDOW_ADJUST,
)
from paramiko.message import Message
from paramiko.py3compat import byte_ord
from paramiko.ssh_exception import ChannelProfileError


class RecordingTransport (object):
    """
    Minimal stand-in for `.Transport`: records outgoing messages and can
    simulate the peer reopening the outbound window after each DATA/
    EXTENDED_DATA message so all_or_fail loops progress deterministically.
    """

    def __init__(self, channel, reopen_window=0):
        self.channel = channel
        self.reopen_window = reopen_window
        self.messages = []
        # real Transports expose the shared profile mount
        self.channel_io_profiles = ChannelIOProfileMount()

    def get_log_channel(self):
        return 'paramiko.transport'

    def _send_user_message(self, m):
        data = m.asbytes()
        self.messages.append(data)
        kind = byte_ord(data[:1])
        if self.reopen_window and kind in (
            MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA,
        ):
            parsed = Message(data)
            parsed.get_byte()
            parsed.get_int()
            if kind == MSG_CHANNEL_EXTENDED_DATA:
                parsed.get_int()
            payload = parsed.get_binary()
            reopen = self.reopen_window
            if len(payload) < reopen:
                reopen = len(payload)
            if reopen:
                # a packet arriving off the wire is parsed from position 0
                adjust = Message()
                adjust.add_int(reopen)
                adjust.rewind()
                self.channel._window_adjust(adjust)


def parse_message(data):
    """Break a captured channel message into its observable pieces."""
    m = Message(data)
    kind = byte_ord(m.get_byte())
    chanid = m.get_int()
    code = None
    payload = None
    ack = None
    if kind == MSG_CHANNEL_EXTENDED_DATA:
        code = m.get_int()
    if kind in (MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA):
        payload = m.get_binary()
    elif kind == MSG_CHANNEL_WINDOW_ADJUST:
        ack = m.get_int()
    return kind, chanid, code, payload, ack


def extended_message(data):
    """Build an inbound MSG_CHANNEL_EXTENDED_DATA(code=1) message."""
    m = Message()
    m.add_int(1)
    m.add_string(data)
    # simulate a packet arriving off the wire (read cursor at position 0)
    m.rewind()
    return m


class ChannelIOProfileTest (unittest.TestCase):

    def make_channel(self, out_window=1000, in_window=1000, reopen_window=0):
        chan = Channel(7)
        transport = RecordingTransport(chan, reopen_window=reopen_window)
        chan._set_transport(transport)
        chan._set_window(in_window, 35000)  # threshold becomes in_window // 10
        chan.remote_chanid = 21
        chan.out_window_size = out_window
        chan.out_max_packet_size = 35000
        chan.active = 1
        chan.settimeout(0.0)
        return chan, transport

    def kinds(self, transport):
        return [parse_message(data)[0] for data in transport.messages]

    def payloads(self, transport, kind=None):
        out = []
        for data in transport.messages:
            parsed = parse_message(data)
            if kind is None or parsed[0] == kind:
                out.append(parsed[3])
        return out

    def acks(self, transport):
        return [
            parse_message(data)[4]
            for data in transport.messages
            if parse_message(data)[0] == MSG_CHANNEL_WINDOW_ADJUST
        ]

    # -- baseline / empty stack ----------------------------------------

    def test_empty_stack_effective_view_is_the_channel_baseline(self):
        chan, transport = self.make_channel()
        self.assertEqual(0, len(chan.io_profile_stack))
        view = chan.get_io_profile()
        self.assertIsInstance(view, EffectiveChannelIOProfile)
        self.assertEqual(STDERR_SEPARATE, view.stderr_merge)
        self.assertIsNone(view.stderr_merge_policy)
        self.assertEqual(WINDOW_THRESHOLD_BATCH, view.window_ack)
        self.assertEqual(OUTBOUND_PARTIAL_OK, view.outbound_delivery)
        self.assertIsNone(view.stream_access)

    def test_send_exit_emits_msg_channel_data(self):
        chan, transport = self.make_channel()
        self.assertEqual(3, chan.send(b'abc'))
        kind, chanid, code, payload, ack = parse_message(
            transport.messages[0])
        self.assertEqual(MSG_CHANNEL_DATA, kind)
        self.assertEqual(21, chanid)
        self.assertIsNone(code)
        self.assertEqual(b'abc', payload)
        self.assertEqual(OUTBOUND_KIND_DATA,
                         chan.io_profile_stack.last_outbound_kind)

    def test_send_stderr_exit_emits_msg_channel_extended_data_code_1(self):
        chan, transport = self.make_channel()
        self.assertEqual(3, chan.send_stderr(b'def'))
        kind, chanid, code, payload, ack = parse_message(
            transport.messages[0])
        self.assertEqual(MSG_CHANNEL_EXTENDED_DATA, kind)
        self.assertEqual(21, chanid)
        self.assertEqual(1, code)
        self.assertEqual(b'def', payload)
        self.assertEqual(OUTBOUND_KIND_EXTENDED_DATA,
                         chan.io_profile_stack.last_outbound_kind)

    def test_baseline_recv_feeds_stay_isolated(self):
        chan, transport = self.make_channel()
        chan._feed(b'out')
        chan._feed_extended(extended_message(b'err'))
        self.assertTrue(chan.recv_ready())
        self.assertTrue(chan.recv_stderr_ready())
        self.assertEqual(b'out', chan.recv(100))
        self.assertEqual(b'err', chan.recv_stderr(100))

    def test_baseline_window_adjust_is_threshold_batched(self):
        # threshold = 100; small reads must be swallowed until the
        # accumulated consumption crosses it, then one batched adjust
        chan, transport = self.make_channel()
        chan._feed(b'x' * 250)
        self.assertEqual(b'x' * 40, chan.recv(40))
        self.assertEqual(b'x' * 40, chan.recv(40))
        self.assertEqual([], self.acks(transport))
        self.assertEqual(b'x' * 40, chan.recv(40))
        self.assertEqual([120], self.acks(transport))

    def test_baseline_set_combine_stderr_flips_routing(self):
        chan, transport = self.make_channel()
        chan._feed_extended(extended_message(b'err'))
        # set_combine_stderr returns the *previous* value
        self.assertEqual(False, chan.set_combine_stderr(True))
        # backlog drained into the primary buffer
        self.assertTrue(chan.recv_ready())
        self.assertFalse(chan.recv_stderr_ready())
        self.assertEqual(b'err', chan.recv(100))
        # and new extended data merges
        chan._feed_extended(extended_message(b'more'))
        self.assertEqual(b'more', chan.recv(100))
        self.assertFalse(chan.recv_stderr_ready())

    # -- window_ack fork -----------------------------------------------

    def test_ack_every_read_emits_one_adjust_per_primary_read(self):
        chan, transport = self.make_channel()
        chan.push_io_profile(window_ack=WINDOW_ACK_EVERY_READ)
        chan._feed(b'x' * 250)
        self.assertEqual(b'x' * 40, chan.recv(40))
        self.assertEqual(b'x' * 40, chan.recv(40))
        self.assertEqual(b'x' * 40, chan.recv(40))
        self.assertEqual([40, 40, 40], self.acks(transport))

    def test_ack_every_read_emits_one_adjust_per_stderr_read(self):
        chan, transport = self.make_channel()
        chan.push_io_profile(window_ack=WINDOW_ACK_EVERY_READ)
        chan._feed_extended(extended_message(b'e' * 250))
        self.assertEqual(b'e' * 40, chan.recv_stderr(40))
        self.assertEqual(b'e' * 40, chan.recv_stderr(40))
        self.assertEqual([40, 40], self.acks(transport))

    def test_suppress_ack_emits_nothing_then_threshold_resumes_after_pop(self):
        chan, transport = self.make_channel()
        chan._feed(b'x' * 250)
        with chan.io_profile(window_ack=WINDOW_SUPPRESS_ACK):
            for _ in range(6):
                chan.recv(40)
            chan.recv(10)
            self.assertEqual([], self.acks(transport))
            self.assertEqual(250, chan.in_window_sofar)
        # frame popped -> batched baseline accounting catches the consumed
        # bytes up on the next read
        chan._feed(b'y' * 100)
        chan.recv(40)
        self.assertEqual([290], self.acks(transport))

    def test_window_ack_modes_fork_on_the_same_reads(self):
        for mode, expected in (
            (WINDOW_THRESHOLD_BATCH, []),
            (WINDOW_ACK_EVERY_READ, [40, 40]),
            (WINDOW_SUPPRESS_ACK, []),
        ):
            chan, transport = self.make_channel()
            chan.push_io_profile(window_ack=mode)
            chan._feed(b'z' * 80)
            # drain the primary buffer in two equal reads; the same 80
            # consumed bytes are accounted differently by each mode
            chan.recv(40)
            chan.recv(40)
            self.assertEqual(
                expected, self.acks(transport),
                'mode %r should produce %r' % (mode, expected))
            # threshold mode swallowed 80 bytes but hasn't crossed 100;
            # every-read observably emitted twice; suppress never emitted
            if mode == WINDOW_ACK_EVERY_READ:
                # the stderr exit must observably fork the same way even
                # though both reads share the window accounting
                chan._feed_extended(extended_message(b'e' * 40))
                chan.recv_stderr(40)
                self.assertEqual([40, 40, 40], self.acks(transport))

    # -- stderr_merge fork ---------------------------------------------

    def test_separate_frame_routes_extended_to_stderr_without_touching_flag(self):
        chan, transport = self.make_channel()
        # baseline channel is already combined via the official switch
        self.assertEqual(False, chan.set_combine_stderr(True))
        self.assertTrue(chan.combine_stderr)
        frame = chan.push_io_profile(stderr_merge=STDERR_SEPARATE)
        try:
            # flag is never mutated by the stack
            self.assertTrue(chan.combine_stderr)
            self.assertEqual(STDERR_SEPARATE,
                             chan.get_io_profile().stderr_merge)
            chan._feed_extended(extended_message(b'X'))
            self.assertTrue(chan.recv_stderr_ready())
            self.assertFalse(chan.recv_ready())
            self.assertEqual(b'X', chan.recv_stderr(10))
        finally:
            chan.pop_io_profile(frame)
        # after pop the combined baseline is observable again
        chan._feed_extended(extended_message(b'Y'))
        self.assertTrue(chan.recv_ready())
        self.assertEqual(b'Y', chan.recv(10))

    def test_combine_frame_drains_backlog_and_routes_new_extended_primary(self):
        chan, transport = self.make_channel()
        chan.in_stderr_buffer.feed(b'old')
        frame = chan.push_io_profile(stderr_merge=STDERR_COMBINE_TO_STDOUT)
        try:
            # the combine_stderr flag is deliberately NOT the mechanism
            self.assertFalse(chan.combine_stderr)
            self.assertEqual(STDERR_COMBINE_TO_STDOUT,
                             chan.get_io_profile().stderr_merge)
            # backlog emptied into the primary buffer
            self.assertTrue(chan.recv_ready())
            self.assertFalse(chan.recv_stderr_ready())
            self.assertEqual(b'old', chan.recv(100))
            # new extended data merges and stderr emits no new data
            chan._feed_extended(extended_message(b'new'))
            self.assertFalse(chan.recv_stderr_ready())
            self.assertEqual(b'new', chan.recv(100))
        finally:
            chan.pop_io_profile(frame)
        # post-pop routing returns to the separate baseline
        chan._feed_extended(extended_message(b'later'))
        self.assertTrue(chan.recv_stderr_ready())
        self.assertEqual(b'later', chan.recv_stderr(100))

    def test_forbid_merge_blocks_opening_combine(self):
        chan, transport = self.make_channel()
        with chan.io_profile(stderr_merge=STDERR_FORBID_MERGE):
            self.assertRaises(
                ChannelProfileError, chan.set_combine_stderr, True)
            self.assertFalse(chan.combine_stderr)
            chan._feed_extended(extended_message(b'keep'))
            self.assertEqual(b'keep', chan.recv_stderr(100))
        # once the frame is gone, combining is permitted again
        self.assertEqual(False, chan.set_combine_stderr(True))
        self.assertTrue(chan.combine_stderr)

    def test_forbid_merge_on_combined_channel_is_read_only(self):
        chan, transport = self.make_channel()
        chan.set_combine_stderr(True)
        with chan.io_profile(stderr_merge=STDERR_FORBID_MERGE):
            self.assertRaises(
                ChannelProfileError, chan.set_combine_stderr, True)
            # extended data keeps merging per the baseline that was already on
            chan._feed_extended(extended_message(b'ro'))
            self.assertEqual(b'ro', chan.recv(100))
            # but outbound writes are refused on the read-only frame
            self.assertRaises(ChannelProfileError, chan.send, b'x')
            self.assertRaises(ChannelProfileError, chan.send_stderr, b'x')

    def test_dual_required_covers_both_streams_and_rejects_merge(self):
        chan, transport = self.make_channel()
        with chan.io_profile(stream_access=STREAM_DUAL_REQUIRED):
            chan._feed(b'O')
            chan._feed_extended(extended_message(b'E'))
            self.assertEqual(b'O', chan.recv(10))
            self.assertEqual(b'E', chan.recv_stderr(10))
            self.assertRaises(
                ChannelProfileError, chan.set_combine_stderr, True)

    def test_dual_required_cannot_be_pushed_on_a_merged_channel(self):
        chan, transport = self.make_channel()
        chan.set_combine_stderr(True)
        before = list(chan.io_profile_stack.frames())
        self.assertRaises(
            ChannelProfileError,
            chan.push_io_profile, stream_access=STREAM_DUAL_REQUIRED)
        # the rejected push left no residue
        self.assertEqual(before, chan.io_profile_stack.frames())
        self.assertEqual(0, len(chan.io_profile_stack))

    def test_dual_required_cannot_sit_above_a_combine_frame(self):
        chan, transport = self.make_channel()
        outer = chan.push_io_profile(stderr_merge=STDERR_COMBINE_TO_STDOUT)
        try:
            self.assertRaises(
                ChannelProfileError,
                chan.push_io_profile, stream_access=STREAM_DUAL_REQUIRED)
        finally:
            chan.pop_io_profile(outer)

    # -- stream_access fork --------------------------------------------

    def test_primary_ok_denies_the_stderr_extended_stream(self):
        chan, transport = self.make_channel()
        with chan.io_profile(stream_access=STREAM_PRIMARY_OK):
            chan._feed(b'o')
            self.assertEqual(b'o', chan.recv(10))
            chan._feed_extended(extended_message(b'e'))
            self.assertRaises(ChannelProfileError, chan.recv_stderr, 10)
            self.assertEqual(1, chan.send(b'p'))
            self.assertRaises(ChannelProfileError, chan.send_stderr, b'e')
            self.assertIsInstance(chan.makefile(), ChannelFile)
            self.assertRaises(ChannelProfileError, chan.makefile_stderr)

    def test_stderr_ok_denies_the_primary_stream(self):
        chan, transport = self.make_channel()
        with chan.io_profile(stream_access=STREAM_STDERR_OK):
            chan._feed_extended(extended_message(b'e'))
            self.assertEqual(b'e', chan.recv_stderr(10))
            chan._feed(b'o')
            self.assertRaises(ChannelProfileError, chan.recv, 10)
            self.assertEqual(1, chan.send_stderr(b'e'))
            self.assertRaises(ChannelProfileError, chan.send, b'p')
            self.assertIsInstance(
                chan.makefile_stderr(), ChannelStderrFile)
            self.assertRaises(ChannelProfileError, chan.makefile)

    # -- outbound_delivery fork ----------------------------------------

    def test_partial_ok_single_send_returns_partial_count(self):
        chan, transport = self.make_channel(out_window=100)
        self.assertEqual(100, chan.send(b'x' * 250))
        self.assertEqual(1, len(transport.messages))
        self.assertEqual([b'x' * 100],
                         self.payloads(transport, MSG_CHANNEL_DATA))

    def test_all_or_fail_send_drains_payload_across_data_messages(self):
        chan, transport = self.make_channel(
            out_window=100, reopen_window=100)
        with chan.io_profile(outbound_delivery=OUTBOUND_ALL_OR_FAIL):
            self.assertEqual(250, chan.send(b'x' * 250))
        self.assertEqual(
            [b'x' * 100, b'x' * 100, b'x' * 50],
            self.payloads(transport, MSG_CHANNEL_DATA))
        self.assertEqual(
            [MSG_CHANNEL_DATA] * 3, self.kinds(transport))

    def test_all_or_fail_send_stderr_drains_payload_extended_messages(self):
        chan, transport = self.make_channel(
            out_window=100, reopen_window=100)
        with chan.io_profile(outbound_delivery=OUTBOUND_ALL_OR_FAIL):
            self.assertEqual(250, chan.send_stderr(b'e' * 250))
        self.assertEqual(
            [b'e' * 100, b'e' * 100, b'e' * 50],
            self.payloads(transport, MSG_CHANNEL_EXTENDED_DATA))
        for data in transport.messages:
            kind, chanid, code, payload, ack = parse_message(data)
            self.assertEqual(MSG_CHANNEL_EXTENDED_DATA, kind)
            self.assertEqual(1, code)

    def test_baseline_sendall_loops_until_drained(self):
        chan, transport = self.make_channel(
            out_window=100, reopen_window=100)
        # no frame: sendall itself is the all-delivery path
        self.assertIsNone(chan.sendall(b'x' * 250))
        self.assertEqual(
            [b'x' * 100, b'x' * 100, b'x' * 50],
            self.payloads(transport, MSG_CHANNEL_DATA))
        transport.messages[:] = []
        self.assertIsNone(chan.sendall_stderr(b'e' * 250))
        self.assertEqual(
            [b'e' * 100, b'e' * 100, b'e' * 50],
            self.payloads(transport, MSG_CHANNEL_EXTENDED_DATA))

    def test_data_vs_extended_keeps_the_two_exits_forked(self):
        # the fake peer reopens the window after each wire message so the
        # second, independently-typed exit can also make progress
        chan, transport = self.make_channel(
            out_window=100, reopen_window=100)
        with chan.io_profile(outbound_delivery=OUTBOUND_DATA_VS_EXTENDED):
            # partial delivery still permitted like partial_ok
            self.assertEqual(100, chan.send(b'd' * 250))
            self.assertEqual(100, chan.send_stderr(b'e' * 250))
        kinds = self.kinds(transport)
        self.assertEqual(
            [MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA], kinds)
        self.assertEqual(
            [b'd' * 100], self.payloads(transport, MSG_CHANNEL_DATA))
        self.assertEqual(
            [b'e' * 100],
            self.payloads(transport, MSG_CHANNEL_EXTENDED_DATA))
        kind, chanid, code, payload, ack = parse_message(
            transport.messages[1])
        self.assertEqual(1, code)
        self.assertEqual(OUTBOUND_KIND_EXTENDED_DATA,
                         chan.io_profile_stack.last_outbound_kind)

    # -- makefile exits stay separate ----------------------------------

    def test_makefile_and_makefile_stderr_are_distinct_exits(self):
        chan, transport = self.make_channel()
        primary = chan.makefile()
        stderr = chan.makefile_stderr()
        # distinct concrete exits (ChannelStderrFile deliberately subclasses
        # ChannelFile, so assert on the concrete type, not isinstance)
        self.assertIs(type(primary), ChannelFile)
        self.assertIs(type(stderr), ChannelStderrFile)
        self.assertIsNot(type(primary), ChannelStderrFile)

        chan._feed(b'OUT')
        chan._feed_extended(extended_message(b'ERR'))
        self.assertEqual(b'OUT', primary.read(3))
        self.assertEqual(b'ERR', stderr.read(3))

    def test_makefile_writes_fork_onto_data_and_extended_messages(self):
        chan, transport = self.make_channel()
        primary = chan.makefile('wb', 0)
        stderr = chan.makefile_stderr('wb', 0)
        primary.write(b'p')
        stderr.write(b'e')
        self.assertEqual(
            [MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA],
            self.kinds(transport))
        self.assertEqual(
            [b'p'], self.payloads(transport, MSG_CHANNEL_DATA))
        self.assertEqual(
            [b'e'], self.payloads(transport, MSG_CHANNEL_EXTENDED_DATA))
        kind, chanid, code, payload, ack = parse_message(
            transport.messages[1])
        self.assertEqual(1, code)

    # -- stack mechanics ------------------------------------------------

    def test_nested_frames_restore_the_outer_profile_on_pop(self):
        chan, transport = self.make_channel()
        outer = chan.push_io_profile(window_ack=WINDOW_ACK_EVERY_READ)
        self.assertEqual(WINDOW_ACK_EVERY_READ,
                         chan.get_io_profile().window_ack)
        inner = chan.push_io_profile(window_ack=WINDOW_SUPPRESS_ACK)
        self.assertEqual(WINDOW_SUPPRESS_ACK,
                         chan.get_io_profile().window_ack)
        # inner frame only tightens window_ack; other axes still inherit
        self.assertEqual(OUTBOUND_PARTIAL_OK,
                         chan.get_io_profile().outbound_delivery)
        chan.pop_io_profile(inner)
        self.assertEqual(WINDOW_ACK_EVERY_READ,
                         chan.get_io_profile().window_ack)
        chan.pop_io_profile(outer)
        view = chan.get_io_profile()
        self.assertEqual(WINDOW_THRESHOLD_BATCH, view.window_ack)
        self.assertEqual(0, len(chan.io_profile_stack))
        self.assertRaises(ChannelProfileError, chan.pop_io_profile)

    def test_context_manager_always_pops_even_on_exception(self):
        chan, transport = self.make_channel()
        try:
            with chan.io_profile(window_ack=WINDOW_SUPPRESS_ACK):
                self.assertEqual(1, len(chan.io_profile_stack))
                raise RuntimeError('boom')
        except RuntimeError:
            pass
        self.assertEqual(0, len(chan.io_profile_stack))
        self.assertEqual(WINDOW_THRESHOLD_BATCH,
                         chan.get_io_profile().window_ack)

        with chan.io_profile(stderr_merge=STDERR_SEPARATE):
            self.assertEqual(1, len(chan.io_profile_stack))
        self.assertEqual(0, len(chan.io_profile_stack))

    def test_invalid_axis_values_are_rejected(self):
        self.assertRaises(
            ChannelProfileError, ChannelIOProfile, stderr_merge='bogus')
        self.assertRaises(
            ChannelProfileError, ChannelIOProfile, window_ack='bogus')
        self.assertRaises(
            ChannelProfileError, ChannelIOProfile,
            outbound_delivery='bogus')
        self.assertRaises(
            ChannelProfileError, ChannelIOProfile, stream_access='bogus')

    def test_shared_mount_isolates_concurrent_channels(self):
        mount = ChannelIOProfileMount()
        chan1 = Channel(1)
        chan2 = Channel(2)
        stack1 = chan1.io_profile_stack
        stack2 = chan2.io_profile_stack
        mount.register(1, stack1)
        mount.register(2, stack2)
        self.assertIs(stack1, mount.get(1))
        self.assertIs(stack2, mount.get(2))
        self.assertEqual(2, len(mount))
        self.assertTrue(1 in mount and 2 in mount)

        mount.push(1, ChannelIOProfile(window_ack=WINDOW_ACK_EVERY_READ))
        mount.push(2, ChannelIOProfile(window_ack=WINDOW_SUPPRESS_ACK))
        # the two stacks never cross
        self.assertEqual(WINDOW_ACK_EVERY_READ,
                         mount.get(1).effective().window_ack)
        self.assertEqual(WINDOW_SUPPRESS_ACK,
                         mount.get(2).effective().window_ack)
        self.assertEqual(1, len(mount.get(1)))
        self.assertEqual(1, len(mount.get(2)))
        mount.pop(1)
        mount.pop(2)
        mount.unregister(1)
        self.assertIsNone(mount.get(1))
        self.assertRaises(ChannelProfileError, mount.pop, 1)

    def test_transport_mount_is_used_by_set_transport(self):
        chan1 = Channel(11)
        chan2 = Channel(12)
        transport1 = RecordingTransport(chan1)
        transport2 = RecordingTransport(chan2)
        chan1._set_transport(transport1)
        chan2._set_transport(transport2)
        self.assertIs(
            chan1.io_profile_stack,
            transport1.channel_io_profiles.get(11))
        self.assertIs(
            chan2.io_profile_stack,
            transport2.channel_io_profiles.get(12))
        # frames pushed through one session's mount never show on the other
        transport1.channel_io_profiles.push(
            11, ChannelIOProfile(stderr_merge=STDERR_COMBINE_TO_STDOUT))
        self.assertEqual(
            STDERR_SEPARATE,
            transport2.channel_io_profiles.get(12).effective().stderr_merge)
        self.assertEqual(
            STDERR_COMBINE_TO_STDOUT,
            transport1.channel_io_profiles.get(11).effective().stderr_merge)

    def test_concurrent_channels_push_without_cross_talk(self):
        chan1, transport1 = self.make_channel()
        chan2, transport2 = self.make_channel()
        errors = []

        def worker(chan, mode):
            try:
                for _ in range(100):
                    frame = chan.push_io_profile(window_ack=mode)
                    if chan.get_io_profile().window_ack != mode:
                        raise AssertionError('cross-talk on %r' % mode)
                    chan.pop_io_profile(frame)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(
            target=worker, args=(chan1, WINDOW_ACK_EVERY_READ))
        t2 = threading.Thread(
            target=worker, args=(chan2, WINDOW_SUPPRESS_ACK))
        t1.start()
        t2.start()
        t1.join(5)
        t2.join(5)
        self.assertFalse(t1.is_alive() or t2.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(0, len(chan1.io_profile_stack))
        self.assertEqual(0, len(chan2.io_profile_stack))
