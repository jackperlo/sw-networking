## This project is a simple packet sniffer written in C using LibPcap.

### To compile the project
``` gcc -o packet_sniffer main.c -lpcap ```

### To execute the project:
``` ./packet_sniffer ```

### (MacOS - updating the priviledge to obtain access to NICs)
``` cd dev ```
``` sudo chown <user>:admin bp* ```
