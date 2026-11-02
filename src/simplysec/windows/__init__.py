"""The only layer that touches the operating system.

Everything here is a thin adapter that can be replaced by a fake in tests. Core logic
never imports subprocess, winreg, COM or psutil directly.
"""
