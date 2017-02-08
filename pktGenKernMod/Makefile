############################################################################
#  Filename: Makefile
#
#  Description: This file is used to compile the packet generator 
#              
############################################################################

obj-m += pktGen.o
pktGen-objs := pkt_main.o pkt_util.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
