arp_spoof: main.cpp
	gcc -o arp_spoof main.cpp -lpcap -pthread -show

clean:
	rm arp_spoof
