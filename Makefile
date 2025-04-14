# Example makefile for CPE464 Trace program
#
# Just links in pcap library

CC = gcc
LIBS = -lpcap
CFLAGS = -g -Wall -pedantic -std=gnu99
#CGLAGS = 
TESTS = arp ping small http udp mix tcpbad ipbad largeMix largeMix2 

all:  trace

trace: trace.c checksum.c
	$(CC) $(CFLAGS) -o $@ trace.c checksum.c $(LIBS)

clean:
	rm -f trace output.txt

arp: trace
	./trace traceFiles/ArpTest.pcap > output.txt
	diff output.txt traceFiles/ArpTest.out

http: trace
	./trace traceFiles/Http.pcap > output.txt
	diff output.txt traceFiles/Http.out

ipbad: trace
	./trace traceFiles/IP_bad_checksum.pcap > output.txt
	diff output.txt traceFiles/IP_bad_checksum.out

largeMix: trace
	./trace traceFiles/largeMix.pcap > output.txt
	diff output.txt traceFiles/largeMix.out

largeMix2: trace
	./trace traceFiles/largeMix2.pcap > output.txt
	diff output.txt traceFiles/largeMix2.out

mix: trace
	./trace traceFiles/mix_withIPoptions.pcap > output.txt
	diff output.txt traceFiles/mix_withIPoptions.out

ping: trace
	./trace traceFiles/PingTest.pcap > output.txt
	diff output.txt traceFiles/PingTest.out

small: trace
	./trace traceFiles/smallTCP.pcap > output.txt
	diff output.txt traceFiles/smallTCP.out

tcpbad: trace
	./trace traceFiles/TCP_bad_checksum.pcap > output.txt
	diff output.txt traceFiles/TCP_bad_checksum.out

udp: trace
	./trace traceFiles/UDPfile.pcap > output.txt
	diff output.txt traceFiles/UDPfile.out

test: trace $(TESTS)