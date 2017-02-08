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
#define PKT_MAC_ADDR_LEN 6
#define PKT_DMAC_OFFSET 0
#define PKT_SMAC_OFFSET (PKT_DMAC_OFFSET + PKT_MAC_ADDR_LEN)

#define PKT_MIN_VLAN_PRI 0
#define PKT_MAX_VLAN_PRI 7
#define PKT_MIN_VLAN_ID  1
#define PKT_MAX_VLAN_ID  4095

#define PKT_MIN_ETHTYPE 0x1
#define PKT_MAX_ETHTYPE 0xFFFF

#define PKT_VLAN_TPID       0x8100
#define PKT_ARP_ETHTYPE     0x0806
#define PKT_IPV4_ETHTYPE    0x0800
#define PKT_ARP_HW_TYPE     0x0001
#define PKT_ARP_PROT_SIZE   0x04
#define PKT_ARP_REQ_OPCODE  0x0001
#define PKT_ARP_REP_OPCODE  0x0002
#define PKT_TCP_PROT_NUM    0x6
#define PKT_UDP_PROT_NUM    0x11

#define PKT_MIN_L3_DATAGRAM_LEN 20
#define PKT_MAX_L3_DATAGRAM_LEN 65535
#define PKT_MIN_DSCP            0
#define PKT_MAX_DSCP            63
#define PKT_MIN_IP_TTL          1
#define PKT_MAX_IP_TTL          255
#define PKT_MIN_IP_FRAG_OFF     0
#define PKT_MAX_IP_FRAG_OFF     8191
#define PKT_MIN_IP_PROT         1
#define PKT_MAX_IP_PROT         255

#define PKT_DSCP_OFFSET         1
#define PKT_TOT_LEN_OFFSET      2
#define PKT_IP_ID_OFFSET        4
#define PKT_IP_FLAGS_OFFSET     6
#define PKT_IP_TTL_OFFSET       8
#define PKT_IP_PROTOCOL_OFFSET  9
#define PKT_IP_CHECKSUM_OFFSET  10
#define PKT_IP_SRC_IP_OFFSET    12
#define PKT_IP_DST_IP_OFFSET    16

#define PKT_IP_ADDR_LEN     4
#define PKT_IPADDR_BUF_LEN  17

#define PKT_MIN_TCP_HDR_LEN     20
#define PKT_MIN_UDP_HDR_LEN     8
#define PKT_MIN_L4_PORT_NUM     1
#define PKT_MAX_L4_PORT_NUM     65535
#define PKT_MIN_TCP_SEQ_NUM     1
#define PKT_MAX_TCP_SEQ_NUM     4294967295
#define PKT_MIN_TCP_ACK_NUM     0
#define PKT_MAX_TCP_ACK_NUM     4294967295
#define PKT_TCP_FLAG_BITS       6
#define PKT_TCP_MIN_WIN_SIZE    0
#define PKT_TCP_MAX_WIN_SIZE    65535
#define PKT_TCP_MIN_URG_PTR     0
#define PKT_TCP_MAX_URG_PTR     65535
#define PKT_TCP_PSEUDO_HDR_LEN  12

#define PKT_L4_DST_PORT_OFFSET  2
#define PKT_TCP_SEQ_NUM_OFFSET  4
#define PKT_TCP_ACK_NUM_OFFSET  8
#define PKT_TCP_DATA_OFFSET     12
#define PKT_TCP_FLAGS_OFFSET    13
#define PKT_TCP_WIN_SIZE_OFFSET 14
#define PKT_TCP_CHECKSUM_OFFSET 16
#define PKT_TCP_URG_PTR_OFFSET  18

#define PKT_UDP_LEN_OFFSET      4
#define PKT_UDP_CHECKSUM_OFFSET 6

#define CRCPOLY2 0xEDB88320UL  /* left-right reversal */

enum
{
    PKT_ARP_PACKET = 1,
    PKT_L2_PACKET,
    PKT_IP_PACKET,
    PKT_TCP_PACKET,
    PKT_UDP_PACKET
};

typedef struct
{
    char *pIfName;
    int  numPkts;
    int  pktInterval;
    char *pFileName;
    int  isFileInput;
} tCmdLineArg;

int ValidateCmdLineArg (char *argv[], int argc, tCmdLineArg *pCmdLineArg);
void CleanupPktGen (tCmdLineArg *pCmdLineArg);
int ReadPktDataFromFile (char *pFileName, char *pktData, int *pPktLen);
void DumpPacket (char *au1Packet, int len);
int SendDataToKernel (tCmdLineArg cmdLineArg, char *pktData, int pktLen);
int ReadPktDataFromUser (char *pktData, int *pPktLen);
void DisplaySpecificPktTypes (void);
int ConvertCharToByte (char *pValue);
int GetL2HdrLen (char *pktData, int *pL2HdrLen);
int ConstructL2Header (char *pktData, int *pPktLen, int isL3Pkt);
int ConstructL3Header (char *pktData, int *pPktLen, uint8_t ipProtNum);
int ConstructArpPacket (char *pktData, int *pPktLen);
int ValidateMacAddressFormat (char *macAddr);
int GetDestMacAddr (char *pktData, int *pPktLen);
int GetSrcMacAddr (char *pktData, int *pPktLen);
int GetVlanTag (char *pktData, int *pPktLen);
int GetEtherType (char *pktData, int *pPktLen);
int GetPktLength (char *pktData, int *pPktLen);
int GetSrcIpAddr (char *pktData, int *pPktLen);
int GetDestIpAddr (char *pktData, int *pPktLen);
void SetPktFcs (char *pktData, int *pPktLen);
unsigned long crc2(int n, unsigned char c[]);
int GetL3Dscp (char *pktData, int l2HdrLen);
int GetIpFlags (char *pktData, int l2HdrLen);
int GetIpFragOffset (char *pktData, int l2HdrLen);
int GetIpTtl (char *pktData, int l2HdrLen);
int GetIpProtocol (char *pktData, int l2HdrLen);
int GetL3DatagramLength (char *pktData, int *pPktLen);
uint16_t ip_checksum (const void *buf, size_t hdr_len);
int ConstructTcpHeader (char *pktData, int *pPktLen);
int GetL4SrcPort (char *pktData, int l4HdrOffset);
int GetL4DstPort (char *pktData, int l4HdrOffset);
int GetTcpSeqNum (char *pktData, int l4HdrOffset);
int GetTcpAckNum (char *pktData, int l4HdrOffset);
int GetTcpFlags (char *pktData, int l4HdrOffset);
int GetTcpWindowSize (char *pktData, int l4HdrOffset);
int GetTcpUrgPtr (char *pktData, int l4HdrOffset, int pktLen);
void CalculateL4Checksum (char *pktData, int l4HdrOffset, int ipProtNum);
int ConstructUdpHeader (char *pktData, int *pPktLen);

#endif /* __PKT_DEFN_H__ */
