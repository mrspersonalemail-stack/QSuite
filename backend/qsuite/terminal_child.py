"""Executed only after subprocess has dropped to the isolated terminal identity."""

import fcntl
import os
import resource
import termios


def main():
    if os.geteuid() == 0:
        raise SystemExit("terminal refuses root")
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    os.execve("/bin/bash", ["bash", "--noprofile", "--norc"], dict(os.environ))  # noqa: S606 -- explicit unprivileged PTY shell


if __name__ == "__main__":
    main()
