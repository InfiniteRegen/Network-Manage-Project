main:		main.o callback.o shell_color.o statisticsHandler.o checkIPAddress.o
	gcc -o main main.o callback.o shell_color.o statisticsHandler.o checkIPAddress.o -lpcap

main.o: main.c
		gcc -c main.c

callback.o: callback.c
		gcc -c callback.c

shell_color.o: shell_color.c
		gcc -c shell_color.c

statisticsHandler.o: statisticsHandler.c
		gcc -c statisticsHandler.c

checkIPAddress.o: checkIPAddress.c
		gcc -c checkIPAddress.c

clean:
	rm -rf *.o main *.pkt

clear:
	rm -rf *.o main *.pkt
