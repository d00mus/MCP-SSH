"""Text stream primitives: bounded buffer, terminal cleaning, the line-based canvas."""

import random
import threading
import time
import unittest

from mcp_ssh_gateway.stream import (
    Canvas, ChunkBuffer, StreamCleaner, count_virtual_lines, find_line_offset, slice_virtual_lines,
)


class TestChunkBuffer(unittest.TestCase):
    def test_head_is_dropped_past_the_limit_and_offsets_stay_absolute(self):
        buf = ChunkBuffer(max_chars=10)
        buf.append("abcdef")
        dropped = buf.append("ghijkl")
        self.assertEqual(dropped, 2)
        self.assertEqual(buf.text(), "cdefghijkl")
        self.assertEqual(buf.base_offset, 2)

    def test_truncate_tail_removes_only_the_end(self):
        buf = ChunkBuffer()
        buf.append("hello ")
        buf.append("world")
        self.assertEqual(buf.truncate_tail(3), 3)
        self.assertEqual(buf.text(), "hello wo")

    def test_text_reflects_every_mutation(self):
        buf = ChunkBuffer(max_chars=6)
        buf.append("abc")
        self.assertEqual(buf.text(), "abc")
        buf.append("defg")
        self.assertEqual(buf.text(), "bcdefg")
        buf.truncate_tail(2)
        self.assertEqual(buf.text(), "bcde")
        buf.clear()
        self.assertEqual(buf.text(), "")
        self.assertEqual(buf.base_offset, 5)


class TestStreamCleaner(unittest.TestCase):
    def test_escape_split_across_chunks_is_removed(self):
        cleaner = StreamCleaner()
        out = cleaner.feed("a\x1b[3") + cleaner.feed("1mred\x1b[0m")
        self.assertEqual(out, "ared")

    def test_a_lone_escape_does_not_swallow_the_stream(self):
        cleaner = StreamCleaner()
        out = cleaner.feed("x\x1b") + cleaner.feed("\nyz")
        self.assertEqual(out, "x\nyz")

    def test_crlf_split_across_chunks_becomes_one_newline(self):
        cleaner = StreamCleaner()
        out = cleaner.feed("one\r") + cleaner.feed("\ntwo\r\n")
        self.assertEqual(out, "one\ntwo\n")

    def test_finalize_turns_a_pending_cr_into_newline_and_drops_a_partial_escape(self):
        cleaner = StreamCleaner()
        out = cleaner.feed("tail\r") + cleaner.finalize()
        self.assertEqual(out, "tail\n")
        cleaner = StreamCleaner()
        self.assertEqual(cleaner.feed("abc\x1b[") + cleaner.finalize(), "abc")

    def test_bracketed_paste_toggles_and_control_chars_are_removed(self):
        cleaner = StreamCleaner()
        self.assertEqual(cleaner.feed("\x1b[?2004hok\x07\x00\n"), "ok\n")


class TestStreamCleanerKeepingCarriageReturns(unittest.TestCase):
    """A shell session keeps the lone CR of a progress bar; the canvas turns it into an overwrite."""

    def cleaner(self):
        return StreamCleaner(keep_cr=True)

    def test_a_lone_return_stays_and_the_returns_in_front_of_a_newline_go(self):
        # the tty turns "\n" into "\r\n", so a program's own "\r\n" arrives as "\r\r\n"
        out = self.cleaner().feed("10%\r20%\r30%\r\nnext\r\r\nmore\n")
        self.assertEqual(out, "10%\r20%\r30%\nnext\nmore\n")

    def test_a_return_at_the_end_of_a_chunk_is_decided_by_the_next_chunk(self):
        cleaner = self.cleaner()
        self.assertEqual(cleaner.feed("10%\r"), "10%")
        self.assertEqual(cleaner.feed("20%\r"), "\r20%")  # nothing but text followed: a rewind
        self.assertEqual(cleaner.feed("\nnext"), "\nnext")  # a newline followed: the line just ended

    def test_returns_are_still_newlines_unless_asked_to_keep_them(self):
        self.assertEqual(StreamCleaner().feed("10%\r20%\r30%\r\n"), "10%\n20%\n30%\n")


class TestVirtualLines(unittest.TestCase):
    def test_a_long_line_counts_as_several_lines(self):
        text = "x" * 2500 + "\nshort\n"
        self.assertEqual(count_virtual_lines(text), 3 + 1)

    def test_slicing_and_offsets_reassemble_the_original(self):
        text = "a" * 2100 + "\nb\nc\n"
        pieces = []
        offset = 0
        while offset < len(text):
            piece, offset = slice_virtual_lines(text, offset, 2)
            pieces.append(piece)
        self.assertEqual("".join(pieces), text)
        self.assertEqual(find_line_offset(text, 3), 2100 + 1)


def make_canvas(text: str = "", max_chars: int = 0) -> Canvas:
    canvas = Canvas(max_chars=max_chars)
    if text:
        canvas.append(text)
    return canvas


def numbered(n: int) -> str:
    return "".join(f"{i}\n" for i in range(1, n + 1))


class TestCanvasPaging(unittest.TestCase):
    def test_unread_lines_are_delivered_once_in_order(self):
        canvas = make_canvas(numbered(10))
        first = canvas.read_unread(limit_lines=4)
        second = canvas.read_unread(limit_lines=4)
        third = canvas.read_unread(limit_lines=4)
        self.assertEqual(first.text, "1\n2\n3\n4\n")
        self.assertEqual(first.has_more, 6)
        self.assertEqual(second.text, "5\n6\n7\n8\n")
        self.assertEqual(third.text, "9\n10\n")
        self.assertEqual(third.has_more, 0)

    def test_reading_at_the_end_returns_nothing_not_history(self):
        canvas = make_canvas("only\n")
        canvas.read_unread(limit_lines=10)
        again = canvas.read_unread(limit_lines=10)
        self.assertEqual(again.text, "")
        self.assertEqual(again.has_more, 0)

    def test_new_output_after_a_read_is_the_next_unread(self):
        canvas = make_canvas("a\n")
        canvas.read_unread(limit_lines=10)
        canvas.append("b\n")
        self.assertEqual(canvas.read_unread(limit_lines=10).text, "b\n")

    def test_zero_limit_means_everything(self):
        canvas = make_canvas(numbered(500))
        self.assertEqual(canvas.read_unread(limit_lines=0).text, numbered(500))

    def test_a_partial_line_is_delivered_and_completed_later(self):
        canvas = make_canvas("Continue? [y/N] ")
        self.assertEqual(canvas.read_unread(limit_lines=10).text, "Continue? [y/N] ")
        canvas.append("y\n")
        self.assertEqual(canvas.read_unread(limit_lines=10).text, "y\n")

    def test_a_very_long_line_arrives_in_pieces_that_reassemble_exactly(self):
        text = "x" * 3000 + "\ntail\n"
        canvas = make_canvas(text)
        received = ""
        while True:
            window = canvas.read_unread(limit_lines=1)
            received += window.text
            if not window.has_more:
                break
        self.assertEqual(received, text)

    def test_max_chars_is_a_soft_cap_that_still_makes_progress(self):
        canvas = make_canvas("y" * 3000 + "\nz\n")
        window = canvas.read_unread(limit_lines=0, max_chars=10)
        self.assertGreater(len(window.text), 0)
        self.assertTrue(window.truncated)
        self.assertGreater(window.has_more, 0)


class TestCanvasScrollback(unittest.TestCase):
    def test_peek_from_the_start_does_not_move_the_unread_position(self):
        canvas = make_canvas(numbered(10))
        canvas.read_unread(limit_lines=3)
        peek = canvas.peek(offset=0, limit_lines=2)
        self.assertEqual(peek.text, "1\n2\n")
        self.assertEqual(peek.has_more, 7)
        self.assertEqual(canvas.read_unread(limit_lines=2).text, "4\n5\n")

    def test_negative_offset_looks_that_many_lines_above_the_cursor(self):
        canvas = make_canvas(numbered(10))
        canvas.read_unread(limit_lines=6)
        peek = canvas.peek(offset=-2, limit_lines=2)
        self.assertEqual(peek.text, "5\n6\n")
        self.assertEqual(peek.has_more, 4)

    def test_tail_returns_the_last_lines_and_jumps_to_the_end(self):
        canvas = make_canvas(numbered(10))
        window = canvas.tail(3)
        self.assertEqual(window.text, "8\n9\n10\n")
        self.assertEqual(window.has_more, 0)
        self.assertEqual(canvas.read_unread(limit_lines=5).text, "")

    def test_tail_counts_the_unread_lines_it_passes_over_and_loses_none_of_them(self):
        canvas = make_canvas(numbered(10))
        window = canvas.tail(3)
        self.assertEqual(window.skipped, 7)
        self.assertFalse(window.dropped)  # the lines are still in the scrollback
        self.assertEqual(canvas.peek(offset=0, limit_lines=2).text, "1\n2\n")

    def test_tail_does_not_count_the_lines_that_were_already_read(self):
        canvas = make_canvas(numbered(10))
        canvas.read_unread(limit_lines=4)
        self.assertEqual(canvas.tail(3).skipped, 3)  # 5, 6 and 7 were never seen

    def test_tail_over_already_read_lines_skips_nothing(self):
        canvas = make_canvas(numbered(10))
        canvas.read_unread(limit_lines=0)
        window = canvas.tail(3)
        self.assertEqual(window.text, "8\n9\n10\n")
        self.assertEqual(window.skipped, 0)
        self.assertFalse(window.dropped)

    def test_tail_counts_the_unread_lines_that_the_character_cap_cut_off(self):
        canvas = make_canvas(numbered(10))
        window = canvas.tail(10, max_chars=6)
        self.assertEqual(window.text, "9\n10\n")
        self.assertEqual(window.skipped, 8)

    def test_tail_still_reports_output_lost_to_the_buffer_limit(self):
        canvas = Canvas(max_chars=21)
        for number in range(10):
            canvas.append(f"line-{number}\n")  # the buffer keeps the last three of them
        window = canvas.tail(1)
        self.assertEqual(window.text, "line-9\n")
        self.assertTrue(window.dropped)  # line-0 .. line-6 are gone for good
        self.assertEqual(window.skipped, 2)  # line-7 and line-8 are still there
        self.assertFalse(canvas.tail(1).dropped)


class TestCanvasSkipping(unittest.TestCase):
    def test_skip_unread_moves_to_the_end_and_counts_the_lines(self):
        canvas = Canvas()
        canvas.append("a\nb\nc\n")
        canvas.read_unread(limit_lines=1)
        self.assertEqual(canvas.skip_unread(), 2)
        self.assertFalse(canvas.has_unread())
        canvas.append("d\n")
        self.assertEqual(canvas.read_unread().text, "d\n")

    def test_skipped_lines_stay_in_the_scrollback_and_are_not_reported_as_lost(self):
        canvas = Canvas()
        canvas.append("a\nb\n")
        canvas.skip_unread()
        canvas.append("c\n")
        window = canvas.read_unread()
        self.assertFalse(window.dropped)
        self.assertEqual(canvas.peek(0).text, "a\nb\nc\n")

    def test_nothing_to_skip(self):
        self.assertEqual(Canvas().skip_unread(), 0)


class TestCanvasBounds(unittest.TestCase):
    def test_unread_text_trimmed_from_the_head_is_reported_once(self):
        canvas = Canvas(max_chars=20)
        canvas.append("aaaaaaaaaa\n")
        canvas.append("bbbbbbbbbb\n")
        canvas.append("cccccccccc\n")
        first = canvas.read_unread(limit_lines=10)
        self.assertTrue(first.dropped)
        self.assertTrue(first.text.endswith("cccccccccc\n"))
        canvas.append("d\n")
        self.assertFalse(canvas.read_unread(limit_lines=10).dropped)

    def test_the_cursor_stays_absolute_after_a_trim(self):
        canvas = Canvas(max_chars=12)
        canvas.append("one\ntwo\n")
        canvas.read_unread(limit_lines=1)
        canvas.append("three\nfour\n")
        window = canvas.read_unread(limit_lines=10)
        self.assertTrue(window.text.endswith("four\n"))

    def test_history_stays_readable_after_everything_was_consumed(self):
        canvas = make_canvas("a\nb\nc\n")
        canvas.read_unread(limit_lines=0)
        self.assertEqual(canvas.peek(offset=0, limit_lines=3).text, "a\nb\nc\n")


def dropping_lines_one_by_one(text: str, max_chars: int) -> str:
    """What capping the tail means: lines leave from the top until the rest fits; one line always stays."""
    if len(text) <= max_chars:
        return text
    total = count_virtual_lines(text)
    for skip in range(1, total):
        candidate = text[find_line_offset(text, skip):]
        if len(candidate) <= max_chars:
            return candidate
    return text[find_line_offset(text, total - 1):]


class TestCanvasTailCap(unittest.TestCase):
    def test_a_long_tail_is_capped_in_no_time(self):
        canvas = make_canvas(("x" * 799 + "\n") * 5000, max_chars=4_000_000)  # 4 MB of history
        started = time.time()
        window = canvas.tail(5000, max_chars=20_000)
        self.assertLess(time.time() - started, 1.0)
        self.assertEqual(len(window.text), 25 * 800)  # the last 25 whole lines
        self.assertTrue(window.truncated)

    def test_the_cap_keeps_as_many_whole_last_lines_as_fit(self):
        rng = random.Random(7)
        for _ in range(300):
            lines = ["y" * rng.randint(0, 2500) for _ in range(rng.randint(1, 12))]
            text = "\n".join(lines) + rng.choice(["", "\n"])
            cap = rng.randint(1, 3000)
            with self.subTest(lines=[len(line) for line in lines], cap=cap):
                self.assertEqual(make_canvas(text).tail(10_000, max_chars=cap).text,
                                 dropping_lines_one_by_one(text, cap))


class TestCanvasEditing(unittest.TestCase):
    def test_start_new_line_only_when_the_last_line_is_open(self):
        canvas = make_canvas("abc")
        canvas.start_new_line()
        canvas.start_new_line()
        canvas.append("def\n")
        canvas.start_new_line()
        self.assertEqual(canvas.peek(offset=0, limit_lines=0).text, "abc\ndef\n")

    def test_trim_tail_removes_an_unread_suffix(self):
        canvas = make_canvas("out\nKeenetic>")
        self.assertTrue(canvas.trim_tail_if_unread("Keenetic>"))
        self.assertEqual(canvas.read_unread(limit_lines=0).text, "out\n")

    def test_trim_tail_refuses_when_the_text_was_already_delivered(self):
        canvas = make_canvas("out\nKeenetic>")
        canvas.read_unread(limit_lines=0)
        self.assertFalse(canvas.trim_tail_if_unread("Keenetic>"))
        self.assertEqual(canvas.peek(offset=0, limit_lines=0).text, "out\nKeenetic>")


class TestCanvasCarriageReturn(unittest.TestCase):
    """A carriage return sends the writing position back to the start of the line: a progress bar is one line."""

    def test_an_unread_line_is_overwritten(self):
        canvas = Canvas()
        for update in ("10%", "\r20%", "\r30%\n"):
            canvas.append(update)
        self.assertEqual(canvas.read_unread().text, "30%\n")

    def test_a_line_that_was_read_stays_and_the_update_starts_a_new_one(self):
        canvas = Canvas()
        canvas.append("10%")
        self.assertEqual(canvas.read_unread().text, "10%")
        canvas.append("\r20%\n")
        self.assertEqual(canvas.read_unread().text, "20%\n")
        self.assertEqual(canvas.peek(0).text, "10%\n20%\n")

    def test_several_returns_in_one_write(self):
        canvas = make_canvas("head\nabc\rde\nf\rg")
        self.assertEqual(canvas.read_unread().text, "head\nde\ng")

    def test_a_return_that_nothing_overwrites_loses_nothing(self):
        canvas = make_canvas("password:\r")
        canvas.start_new_line()
        canvas.append("next\n")
        self.assertEqual(canvas.read_unread().text, "password:\nnext\n")

    def test_a_return_in_front_of_a_newline_changes_nothing(self):
        canvas = make_canvas("one\r")
        canvas.append("\ntwo\n")
        self.assertEqual(canvas.read_unread().text, "one\ntwo\n")

    def test_only_the_open_line_is_rewritten(self):
        canvas = make_canvas("kept\n\r")
        canvas.append("new\n")
        self.assertEqual(canvas.read_unread().text, "kept\nnew\n")

    def test_a_long_line_read_only_in_part_is_kept_whole(self):
        canvas = make_canvas("x" * 1500)
        first = canvas.read_unread(limit_lines=1)
        canvas.append("\rnew\n")
        self.assertEqual(first.text + canvas.read_unread().text, "x" * 1500 + "\nnew\n")


class TestCanvasWaiting(unittest.TestCase):
    def test_wait_returns_at_once_when_the_condition_already_holds(self):
        canvas = make_canvas("x\n")
        started = time.time()
        self.assertTrue(canvas.wait_until(canvas.has_unread, timeout=5.0))
        self.assertLess(time.time() - started, 0.5)

    def test_wait_wakes_up_when_output_arrives(self):
        canvas = Canvas()
        threading.Timer(0.2, lambda: canvas.append("late\n")).start()
        started = time.time()
        self.assertTrue(canvas.wait_until(canvas.has_unread, timeout=5.0))
        self.assertLess(time.time() - started, 2.0)
        self.assertEqual(canvas.read_unread(limit_lines=5).text, "late\n")

    def test_wait_gives_up_after_the_timeout(self):
        canvas = Canvas()
        started = time.time()
        self.assertFalse(canvas.wait_until(canvas.has_unread, timeout=0.3))
        self.assertGreaterEqual(time.time() - started, 0.25)

    def test_wait_notices_an_outside_state_change_after_wake(self):
        canvas = Canvas()
        flag = threading.Event()
        threading.Timer(0.2, lambda: (flag.set(), canvas.wake())).start()
        started = time.time()
        self.assertTrue(canvas.wait_until(flag.is_set, timeout=5.0))
        self.assertLess(time.time() - started, 2.0)

    def test_a_zero_timeout_only_looks(self):
        canvas = Canvas()
        self.assertFalse(canvas.wait_until(canvas.has_unread, timeout=0))


if __name__ == "__main__":
    unittest.main()
