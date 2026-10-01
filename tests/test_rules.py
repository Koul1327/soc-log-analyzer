from datetime import datetime, timezone

from soc_analyzer.rules import find_failure_window

def test_detects_exact_threshold():
    first = datetime(2026, 8, 20, 13, 2, 52, tzinfo=timezone.utc)
    second = datetime(2026, 8, 20, 13, 2, 59, tzinfo=timezone.utc)

    result = find_failure_window(
        [first, second],
        threshold=2,
        window_seconds=300,
    )

    assert result == (first,second)

def test_below_threshold_returns_none():
    first = datetime(2026, 8, 20, 13, 2, 52, tzinfo=timezone.utc)
    second = datetime(2026, 8, 20, 13, 2, 59, tzinfo=timezone.utc)

    result = find_failure_window(
        [first, second],
        threshold=3,
        window_seconds=300,
    )

    assert result is None
