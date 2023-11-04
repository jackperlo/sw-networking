## This project is a simple packet sniffer written in C using LibPcap.

### To compile the project
``` gcc -o http_capturing main.c -lpcap ```

### To execute the project:
``` ./http_capturing ```

### (MacOS - updating the priviledge to obtain access to NICs)
``` cd dev ```
``` sudo chown <user>:admin bp* ```
