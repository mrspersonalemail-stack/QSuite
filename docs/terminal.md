# Terminal isolation

WebSocket transport attaches to a real PTY. It requires explicit terminal
permission, live session, exact origin, fresh authentication and a one-use
30-second ticket. The ticket is the first frame, never an access-log URL.
Cookie-only cross-site connections are rejected.

The broker starts a child with native UID/GID drop, no supplementary groups,
minimal environment and a separate session. The child refuses root, acquires
the controlling PTY and limits processes/descriptors before Bash without rc
files. The terminal identity must not belong to sudo, adm or the helper group.
SCM_RIGHTS passes only the PTY master to the API.

Five-minute idle and one-hour lifetime limits apply. Session validity is
rechecked. Disconnect/expiry/shutdown close the descriptor and kill the spawned
process group. The broker independently reaps expired children if the API dies.
Creation/termination are audited without keystroke capture.

Root terminal is unavailable. Use existing SSH/sudo for root administration.
This is identity isolation, not a full container sandbox: ordinary readable
host files and allowed networks remain accessible. Stronger confinement needs
a separate reviewed design and deployment test.
