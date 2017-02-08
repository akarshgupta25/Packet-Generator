/********************************************************************
*
* Filename: pkt_hdrs.h
*
* Description: This file includes the standard linux header files
*              that are included in the packet generator
*
*******************************************************************/

#ifndef __PKT_HDRS_H__
#define __PKT_HDRS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>


#include "pkt_defn.h"

#endif /* __PKT_HDRS_H__ */
