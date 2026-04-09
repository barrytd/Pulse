# pulse/animations.py
# --------------------
# Terminal animations for Pulse.
#
# Provides a scrolling ECG-style heartbeat monitor that runs in a background
# thread while the main process does work (parsing, scanning, etc.).
#
# USAGE:
#   from pulse.animations import HeartbeatMonitor
#
#   monitor = HeartbeatMonitor()
#   monitor.start("Parsing 12 files...")
#   # ... do work ...
#   monitor.message = "Almost done..."
#   monitor.stop()

import sys
import threading
import time


# ---------------------------------------------------------------------------
# Colour codes
# ---------------------------------------------------------------------------

_GREEN  = "\033[92m"   # bright green  — flatline
_RED    = "\033[91m"   # bright red    — the heart symbol
_DIM    = "\033[2m"    # dim           — status message
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# ECG waveform
# ---------------------------------------------------------------------------
#
# A single heartbeat looks like this scrolling across the screen:
#
#      /\
#  ───/  \─/\───
#
# We build it as a list of characters. Every BEAT_EVERY frames, we inject
# a fresh beat into the right side of the buffer and let it scroll left.

_BEAT_SHAPE = list("──/\\─/\\──")   # QRS complex + T-wave
_FLAT       = "─"
_BEAT_EVERY = 28                    # frames between beats (~1.4s at 50ms/frame)
_WIDTH      = 40                    # characters wide
_FPS        = 0.05                  # seconds per frame (20 fps)


class HeartbeatMonitor:
    """
    A scrolling ECG heartbeat animation that runs in a background thread.

    Example:
        monitor = HeartbeatMonitor()
        monitor.start("Parsing files...")
        do_slow_thing()
        monitor.message = "Almost done..."
        monitor.stop()
    """

    def __init__(self):
        self._stop_event  = threading.Event()
        self._thread      = None
        self.message      = ""         # update this at any time to change the status text

    def start(self, message=""):
        """Start the animation with an optional status message."""
        self.message     = message
        self._stop_event = threading.Event()
        self._thread     = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the animation and clear the line."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1)
        # Clear the animation line completely
        sys.stdout.write(f"\r{' ' * (_WIDTH + 60)}\r")
        sys.stdout.flush()

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    def _run(self):
        buf              = [_FLAT] * _WIDTH   # the scrolling line buffer
        beat_shape       = list(_BEAT_SHAPE)
        beat_len         = len(beat_shape)
        beat_cursor      = beat_len            # past end = not mid-beat
        frames_since_beat = 0

        while not self._stop_event.is_set():
            # --- Advance the buffer ---
            buf.pop(0)

            # Trigger a new beat on schedule
            if frames_since_beat >= _BEAT_EVERY:
                frames_since_beat = 0
                beat_cursor = 0

            # Append next character: beat shape or flat line
            if beat_cursor < beat_len:
                buf.append(beat_shape[beat_cursor])
                beat_cursor += 1
            else:
                buf.append(_FLAT)

            frames_since_beat += 1

            # --- Render ---
            line = "".join(buf)
            sys.stdout.write(
                f"\r  {_GREEN}{line}{_RESET}  "
                f"{_RED}♥{_RESET}  "
                f"{_DIM}{self.message}{_RESET}"
                f"          "   # padding to overwrite any leftover text
            )
            sys.stdout.flush()

            time.sleep(_FPS)
