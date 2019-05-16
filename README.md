A test tool for 802.11 monitor mode frame injection
===================================================

Wperf is an iperf-like test tool for injecting 802.11 frames using the
mac80211 monitor wireless stack in Linux.

## Command line options

```
  Usage: wperf [options]
         wperf [-h|--help]

    Options:
        -p, --port     <port> server UDP port to listen on/connect to
        -m, --mtu      <mtu>  set the MTU size, default 1500
        -b, --bandwidh <bps>  set the bandwidth in [G|M|k]bit/s
        -M, --monitor  <if>   use a monitor interface for send/receive
        -D, --dhost    <mac>  dest MAC address (monitor only)
        -S, --shost    <mac>  source MAC address (monitor only)
        -B, --bssid    <mac>  AP BSSID MAC address (monitor only)
        -q, --tid      <tid>  set TID, -1 for non-QoS (monitor only)
        -t, --sta             run as STA instead of AP (monitor only)
        -i, --interval <sec>  set the printout interval (default 1s)
        -r, --radom           random payload
        -v, --verbose         increase verbosity
        -h, --help            display this help and exit

```

## Examples

```
sudo ./wperf -M mon0  --dhost 00:00:aa:00:00:00 --shost aa:ff:aa:ff:ff:ff  --bssid ff:aa:ff:dd:ff:ff --mtu 1400 --random
```


## Cross-compiling for openwrt mips example

```
$ export STAGING_DIR=/home/san/Downloads/openwrt/staging_dir
$ export PATH=$PATH:$STAGING_DIR/toolchain-mips_24kc_gcc-7.3.0_musl/bin/
$ make CC=mips-openwrt-linux-gcc CFLAGS="-I$STAGING_DIR/target-mips_24kc_musl/usr/include" LDFLAGS="-L$STAGING_DIR/target-mips_24kc_musl/usr/lib"
```
