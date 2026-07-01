import sys


def progress_bar(done, total, width=40):
    filled = int(width * done / total)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * done / total)
    sys.stdout.write(f"\r  [{bar}] {pct}% ({done}/{total})")
    sys.stdout.flush()
