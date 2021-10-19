# owfuzz usage:
#	-i [interface]
#	   Interface to use.
#	-m [ap/sta/mitm]
#	   Set the mode of fuzzer, default is ap.
#	-c [channel]
#	   Set the working channel of fuzzer, default is 1.
#	-t [mac]
#	   Target's MAC address.
#	-S [SSID]
#	   AP's SSID.
#	-A [auth type]
#	   Target's auth type: OPEN_NONE, OPEN_WEP, SHARE_WEP, WPA_PSK_TKIP, WPA_PSK_AES, WPA_PSK_TKIP_AES, WPA2_PSK_TKIP, WPA2_PSK_AES, WPA2_PSK_TKIP_AES WPA3
#	-I [IP address]
#	   Target's IP address
#	-s [mac]
#	   Fuzzing source Mac address.
#	-T [test type]
#	   Test type, default 1, 0: PoC test, 1: interactive test, 2: frames test
#	-l [log level]
#	   Log level, 8:DEBUG, 7:INFO, 6:NOTICE, 5:WARN, 4:ERR, 3:CRIT, 2:ALERT, 1:EMERG, 0:STDERR
#	-f [log file]
#	   Log file path
#	-h
#	   Help.


# ap mode
#./src/owfuzz -i wlx8416f9157eb6 -m ap -c 11 -t 9C:C0:12:13:D5:1B -b 09:D9:F5:26:FF:80 -s 09:D9:F5:26:FF:80 -T 2 -A WPA2_PSK_TKIP_AES -I 192.168.50.102

# sta mode
#./src/owfuzz -i wlx00c0caaf559c -m sta -c 11 -t AE:B6:D0:15:73:05 -b AE:B6:D0:15:73:05 -s F8:0F:F9:CF:51:0C -T 2 -A WPA2_PSK_AES -S owfuzz

# mitm mode testing uses config file: owfuzz.cfg