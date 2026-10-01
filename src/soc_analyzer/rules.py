def find_failure_window(attempts, threshold=5, window_seconds=300):
    ordered = sorted(attempts)

    for start in range(len(ordered) - threshold + 1):
        end = start + threshold - 1
        duration = ordered[end] - ordered[start]

        if duration.total_seconds() <= window_seconds:
            return ordered[start], ordered[end]

    return None
