## wice

The WICE daemon

```
wice [flags]
```

### Options

```
  -b, --backend strings                    backend types / URLs (default )
  -c, --config string                      Path of configuration file
  -h, --help                               help for wice
      --ice-candidate-type strings         usable candidate types (**, one of "host", "srflx", "prflx", "relay")
      --ice-check-interval duration        interval at which the agent performs candidate checks in the connecting phase (default 200ms)
      --ice-disconnected-timout duration   time till an Agent transitions disconnected (default 5s)
      --ice-failed-timeout duration        time until an Agent transitions to failed after disconnected (default 25s)
  -k, --ice-insecure-skip-verify           skip verification of TLS certificates for secure STUN/TURN servers
      --ice-interface-filter string        regex for filtering local interfaces for ICE candidate gathering (e.g. "eth[0-9]+") (default ".*")
      --ice-keepalive-interval duration    interval netween STUN keepalives (default 2s)
  -l, --ice-lite                           lite agents do not perform connectivity check and only provide host candidates
      --ice-max-binding-requests uint16    maximum number of binding request before considering a pair failed (default 7)
  -m, --ice-mdns                           enable local Multicast DNS discovery
      --ice-nat-1to1-ip strings            list of IP addresses which will be added as local server reflexive candidates (**)
      --ice-network-type strings           usable network types (**, select from "udp4", "udp6", "tcp4", "tcp6")
  -P, --ice-pass string                    password for STUN/TURN credentials
      --ice-port-max uint16                maximum port for allocation policy (range: 0-65535)
      --ice-port-min uint16                minimum port for allocation policy (range: 0-65535)
      --ice-restart-interval duration      time to wait before ICE restart (default 5s)
  -U, --ice-user string                    username for STUN/TURN credentials
  -f, --interface-filter string            regex for filtering Wireguard interfaces (e.g. "wg-.*") (default ".*")
  -d, --log-level string                   log level (one of "panic", "fatal", "error", "warn", "info", "debug", "trace") (default "info")
  -p, --proxy string                       proxy type to use (default "auto")
      --socket string                      Unix control and monitoring socket (default "/var/run/wice.sock")
      --socket-wait                        wait until first client connected to control socket before continuing start
  -a, --url strings                        STUN and/or TURN server address  (**)
  -i, --watch-interval duration            interval at which we are polling the kernel for updates on the Wireguard interfaces (default 1s)
  -w, --wg-config-path string              base path to search for Wireguard configuration files (default "/etc/wireguard")
  -s, --wg-config-sync                     sync Wireguard interface with configuration file (see "wg synconf"
  -u, --wg-user                            start userspace Wireguard daemon
```

### SEE ALSO

* [wice completion](wice_completion.md)	 - Generate the autocompletion script for the specified shell
* [wice docs](wice_docs.md)	 - Generate documentation for the wice commands

###### Auto generated by spf13/cobra on 6-Jan-2022