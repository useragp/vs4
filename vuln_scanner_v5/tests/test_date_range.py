import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnscan.scanner import ScanOptions, Scanner, parse_date_range  # noqa: E402


class DateRangeTests(unittest.TestCase):
    def test_valid_range(self):
        s, e = parse_date_range("2025-01-01", "2025-03-31")
        self.assertEqual((s, e), (dt.date(2025, 1, 1), dt.date(2025, 3, 31)))

    def test_empty_end_is_today(self):
        _, e = parse_date_range("2025-01-01", "")
        self.assertEqual(e, dt.datetime.now(dt.timezone.utc).date())

    def test_future_end_capped(self):
        _, e = parse_date_range("2025-01-01", "2999-01-01")
        self.assertEqual(e, dt.datetime.now(dt.timezone.utc).date())

    def test_errors(self):
        for a, b in (("", ""), ("2025-13-01", ""), ("01.02.2025", ""), ("2025-03-01", "2025-02-01"),
                     ("2999-01-01", "")):
            with self.assertRaises(ValueError):
                parse_date_range(a, b)

    def test_window_whole_days(self):
        sc = Scanner([], ScanOptions(start_date=dt.date(2025, 1, 1), end_date=dt.date(2025, 1, 31)),
                     log=lambda m: None)
        s, e = sc._window()
        self.assertEqual(s, dt.datetime(2025, 1, 1, 0, 0, 0))
        self.assertEqual(e, dt.datetime(2025, 1, 31, 23, 59, 59))

    def test_window_overrides_lookback(self):
        sc = Scanner([], ScanOptions(lookback_days=1, start_date=dt.date(2025, 1, 1)), log=lambda m: None)
        s, e = sc._window()
        self.assertEqual(s, dt.datetime(2025, 1, 1))
        self.assertGreater((e - s).days, 300)

    def test_lookback_still_works(self):
        s, e = Scanner([], ScanOptions(lookback_days=14), log=lambda m: None)._window()
        self.assertEqual(e - s, dt.timedelta(days=14))


if __name__ == "__main__":
    unittest.main()
