# Network monitoring with eBPF

The first working version of this project was developed in this repo: https://github.com/FedeParola/network-monitoring-ebpf.

The current version of the code, instead, contains some enhancements starting from that code for monitoring L3 and L4 traffic.

Initial program for the network monitoring with eBPF lab of the software networking course

## Building

Install pre-requirements:
```sh
sudo apt update
sudo apt install -y clang libelf-dev zlib1g-dev gcc-multilib
```

Init libbpf and bpftool submodules:
```sh
git submodule update --init --recursive
```

Build and install libbpf:
```sh
cd ./libbpf/src
make
sudo make install
# Make sure the loader knows where to find libbpf
sudo ldconfig /usr/lib64
```

Build and install bpftool:
```sh
cd ./bpftool/src
make
sudo make install
```

Build and run the network monitor:
```sh
make
sudo ./network_monitor <ifname>
```
