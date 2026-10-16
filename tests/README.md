# Tests

## Host tests

`tests/unit-tests.c` covers the daemon's logic with the host compiler:

- option parsing: devices, DNS servers, limits, detach and invalid input
- automatic DNS selection: a device's own ULA, else its bridge's, and which
  addresses are ULAs
- the exact log line for each verdict, kind and reason

`tests/init-tests.sh` covers `files/l2dns6rw.init` with procd, UCI and logger
stubs: the required device, DNS servers and verbose passed to the daemon,
validation errors, and the `detach` command.

```sh
sh tools/host-test.sh               # quiet, log in build/host-test.log
sh tests/run-tests.sh               # direct
SANITIZERS=1 sh tests/run-tests.sh  # AddressSanitizer and UBSan
COVERAGE=1 sh tests/run-tests.sh    # gcov line and branch coverage
```

## BPF packet tests

`tests/bpf/cases.py` builds 55 frames and the outcome each must have;
`tests/bpf/runner.c` runs the program on them in a kernel with
`BPF_PROG_TEST_RUN`, which needs root, and `cases.py check` verifies every
rewrite option by option (the DNS list, removed and kept options, lengths,
the checksum state).

The cases cover RA and DHCPv6 rewrites with one, two and eight servers,
compliant messages, duplicate DNS options, protected (SEND, Authentication,
AH) messages, bad and zero checksums, malformed options and headers, DNS
options of a bad length, extension headers (within and beyond the limit),
routing headers with and without segments left, fragments, jumbograms,
truncation, the size and option limits, a device without DNS, and traffic
that is not a target.

```sh
sh tests/bpf/run.sh                   # native build, run with sudo (CI)
sh tests/bpf/run.sh root@192.168.56.2 # on a test VM, x86 SDK build
```

## VM test

`tools/vm-test/run.sh` installs the x86 package on an OpenWrt VM and sends an
RA, a DHCPv6 Reply and a SEND-signed RA through a test bridge, checking what
reaches the other side: configured servers, a daemon restart (link reuse),
the daemon stopped (the pinned program keeps working), automatic mode, a
recreated port, a missing and then added ULA, detach, idle wakeups, and the
verbose log.

```sh
sh tools/sdk-build.sh x86
sh tools/vm-test/run.sh root@192.168.56.2
```
