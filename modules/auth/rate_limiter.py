"""
SCOUT Brute-Force Rate Limiter
Sliding-window failure tracker protecting authentication endpoints from credential-stuffing.
"""

import time
import threading
from typing import Dict, List, Tuple


class LoginRateLimiter:
    """
    Thread-safe rate limiter tracking failed login attempts.
    Blocks key after max_attempts within window_seconds.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 900, lockout_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        self._attempts: Dict[str, List[float]] = {}
        self._lockouts: Dict[str, float] = {}

    def _cleanup_unlocked(self, key: str, now: float) -> None:
        """Removes expired attempt timestamps outside the sliding window."""
        if key in self._attempts:
            self._attempts[key] = [t for t in self._attempts[key] if now - t < self.window_seconds]
            if not self._attempts[key]:
                del self._attempts[key]
        if key in self._lockouts and now >= self._lockouts[key]:
            del self._lockouts[key]

    def is_locked(self, key: str) -> Tuple[bool, int]:
        """
        Returns (is_locked, seconds_remaining).
        """
        now = time.time()
        with self._lock:
            self._cleanup_unlocked(key, now)
            if key in self._lockouts:
                remaining = int(self._lockouts[key] - now)
                if remaining > 0:
                    return True, remaining
                del self._lockouts[key]
            return False, 0

    def record_failure(self, key: str) -> Tuple[bool, int]:
        """
        Records a failed attempt.
        If threshold reached, locks the key and returns (True, lockout_seconds).
        Otherwise returns (False, 0).
        """
        now = time.time()
        with self._lock:
            self._cleanup_unlocked(key, now)
            if key not in self._attempts:
                self._attempts[key] = []
            self._attempts[key].append(now)

            if len(self._attempts[key]) >= self.max_attempts:
                self._lockouts[key] = now + self.lockout_seconds
                self._attempts.pop(key, None)
                return True, self.lockout_seconds
            return False, 0

    def reset(self, key: str) -> None:
        """Clears failures on successful login."""
        with self._lock:
            self._attempts.pop(key, None)
            self._lockouts.pop(key, None)


login_rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=900, lockout_seconds=900)
