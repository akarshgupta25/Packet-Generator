/********************************************************************
*
* Filename: pkt_defn.h
*
* Description: This file contains the macros, structures and enums
*              used in the packet generator
*
*******************************************************************/

#ifndef __PKT_DEFN_H__
#define __PKT_DEFN_H__

#define MOD_AUTHOR "SDN Flow Classification in OpenFlow Client Kernel Module"
#define MOD_DESC "This module implements OpenFlow protocol in linux kernel"

#define NETLINK_USER 31

#define PKT_SUCCESS 0
#define PKT_FAILURE 1

#define PKT_TRUE  1
#define PKT_FALSE 0

#define PKT_CMD_LINE_ARG_NUM 5
#define PKT_MTU_SIZE 1498
#define PKT_MIN_SIZE 64
#define PKT_CRC_LEN  4

#define PKT_MAC_ADDR_BUF_LEN 18

#define PKT_IP_ADDR_LEN     4

typedef struct
{
    char *pIfName;
    int  numPkts;
    int  pktInterval;
    char *pFileName;
    int  isFileInput;
} tCmdLineArg;

void DumpPacket (char *au1Packet, int len);
int SendDataFromInterface (tCmdLineArg cmdLineArg, char *pktData, 
                           int pktLen);
int ConvertCharToByte (char *pValue);
struct net_device *getNetDevByName (char *pIfName);

#endif /* __PKT_DEFN_H__ */
