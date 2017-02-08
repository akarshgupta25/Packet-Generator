/********************************************************************
*
* Filename: pkt_util.c
*
* Description: This file contains the utility functions used by
*              packet generator
*
*******************************************************************/

#include "pkt_hdrs.h"

void DumpPacket (char *au1Packet, int len)
{
    unsigned int u4ByteCount = 0;
    unsigned int u4Length = len;
    char         tempDataLow = 0;
    char         tempDataHigh = 0;

    for (u4ByteCount = 0; u4ByteCount < u4Length; u4ByteCount++)
    {
        if ((u4ByteCount % 16) == 0)
        {
            printf ("\n");
        }
        
        tempDataLow = (au1Packet[u4ByteCount] >> 4) & 0xF;
        tempDataHigh = au1Packet[u4ByteCount] & 0xF;
        if ((tempDataLow >= 0) && (tempDataLow <= 0x9))
        {
            tempDataLow += 48;
        }
        else if ((tempDataLow >= 0xA) && (tempDataLow <= 0xF))
        {
            tempDataLow += 87;
        }
        if ((tempDataHigh >= 0) && (tempDataHigh <= 0x9))
        {
            tempDataHigh += 48;
        }
        else if ((tempDataHigh >= 0xA) && (tempDataHigh <= 0xF))
        {
            tempDataHigh += 87;
        }
        
        printf ("%c%c ", tempDataLow, tempDataHigh);
    }
    printf ("\n");
   
    return;
}

void DisplaySpecificPktTypes (void)
{
    printf ("\n1. ARP Packet\r\n2. L2 Packet\r\n"
            "3. IP Packet\r\n4. TCP Packet\r\n"
            "5. UDP Packet\r\n\n");
    printf ("Enter Packet Header Type: ");
    return;
}

int ConstructL2Header (char *pktData, int *pPktLen, int isL3Pkt)
{
    unsigned short ipEthType = PKT_IPV4_ETHTYPE;
    int            retVal = PKT_SUCCESS;

    do
    {
        retVal = GetDestMacAddr (pktData, pPktLen);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetSrcMacAddr (pktData, pPktLen);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetVlanTag (pktData, pPktLen);

    } while (retVal != PKT_SUCCESS);

    if (isL3Pkt == PKT_TRUE)
    {
        ipEthType = htons (ipEthType);
        memcpy (pktData + *pPktLen, &ipEthType, sizeof (ipEthType));
        *pPktLen += sizeof (ipEthType);
        return PKT_SUCCESS;
    }

    do
    {
        retVal = GetEtherType (pktData, pPktLen);

    } while (retVal != PKT_SUCCESS);

    return PKT_SUCCESS;
}

int ConstructArpPacket (char *pktData, int *pPktLen)
{
    int    pktLen = 0;
    int    arpOpCode = 0;
    int    retVal = PKT_SUCCESS;
    short  twoByteField = 0;

    while (1)
    {
        printf ("1.ARP Request 2.ARP Reply [1/2]: ");
        scanf ("%d", &arpOpCode);
        switch (arpOpCode)
        {
            case PKT_ARP_REQ_OPCODE:
                pktData[pktLen++] = 0xFF;
                pktData[pktLen++] = 0xFF;
                pktData[pktLen++] = 0xFF;
                pktData[pktLen++] = 0xFF;
                pktData[pktLen++] = 0xFF;
                pktData[pktLen++] = 0xFF;
                break;

            case PKT_ARP_REP_OPCODE:
                do
                {
                    retVal = GetDestMacAddr (pktData, &pktLen);

                } while (retVal != PKT_SUCCESS);
                break;

            default:
                continue;
        }
        break;
    }

    do
    {
        retVal = GetSrcMacAddr (pktData, &pktLen);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetVlanTag (pktData, &pktLen);

    } while (retVal != PKT_SUCCESS);

    twoByteField = htons (PKT_ARP_ETHTYPE);
    memcpy (pktData + pktLen, &twoByteField, sizeof(twoByteField));
    pktLen += sizeof(twoByteField);
    
    twoByteField = htons (PKT_ARP_HW_TYPE);
    memcpy (pktData + pktLen, &twoByteField, sizeof(twoByteField));
    pktLen += sizeof(twoByteField);

    twoByteField = htons (PKT_IPV4_ETHTYPE);
    memcpy (pktData + pktLen, &twoByteField, sizeof(twoByteField));
    pktLen += sizeof(twoByteField);

    pktData[pktLen++] = PKT_MAC_ADDR_LEN;
    pktData[pktLen++] = PKT_ARP_PROT_SIZE;

    switch (arpOpCode)
    {
        case PKT_ARP_REQ_OPCODE:
            twoByteField = htons (PKT_ARP_REQ_OPCODE);
            break;

        case PKT_ARP_REP_OPCODE:
            twoByteField = htons (PKT_ARP_REP_OPCODE);
            break;

        default:
            return PKT_FAILURE;
    }
    memcpy (pktData + pktLen, &twoByteField, sizeof(twoByteField));
    pktLen += sizeof(twoByteField);

    memcpy (pktData + pktLen, pktData + PKT_SMAC_OFFSET,
            PKT_MAC_ADDR_LEN);
    pktLen += PKT_MAC_ADDR_LEN;

    do
    {
        retVal = GetSrcIpAddr (pktData, &pktLen);

    } while (retVal != PKT_SUCCESS);

    if (arpOpCode == PKT_ARP_REP_OPCODE)
    {
        memcpy (pktData + pktLen, pktData + PKT_DMAC_OFFSET,
                PKT_MAC_ADDR_LEN);
    }
    pktLen += PKT_MAC_ADDR_LEN;

    do
    {
        retVal = GetDestIpAddr (pktData, &pktLen);

    } while (retVal != PKT_SUCCESS);

    pktLen += (PKT_MIN_SIZE - pktLen - PKT_CRC_LEN);
    SetPktFcs (pktData, &pktLen);

    *pPktLen = pktLen;
    return PKT_SUCCESS;
}

int ConstructL3Header (char *pktData, int *pPktLen, uint8_t ipProtNum)
{
    unsigned int    l2HdrLen = *pPktLen;
    int             tempPktLen = 0;
    int             retVal = PKT_SUCCESS;
    unsigned short  IpId = 0;
    unsigned short  ipChecksum = 0;
    size_t          ipHdrLen = 0;

    pktData[l2HdrLen] = 0x45;

    printf ("\n");
    do
    {
        retVal = GetL3Dscp (pktData, l2HdrLen);

    } while (retVal != PKT_SUCCESS);

    /* generate random IP Identification field */
    srand (time (NULL));
    IpId = (unsigned short) rand();
    IpId = htons (IpId);
    memcpy (pktData + l2HdrLen + PKT_IP_ID_OFFSET, &IpId, sizeof (IpId));

    do
    {
        retVal = GetIpFlags (pktData, l2HdrLen);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetIpFragOffset (pktData, l2HdrLen);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetIpTtl (pktData, l2HdrLen);

    } while (retVal != PKT_SUCCESS);

    if (ipProtNum == 0)
    {
        do
        {
            retVal = GetIpProtocol (pktData, l2HdrLen);

        } while (retVal != PKT_SUCCESS);
    }
    else
    {
        pktData[l2HdrLen + PKT_IP_PROTOCOL_OFFSET] = ipProtNum;
    }

    tempPktLen = l2HdrLen + PKT_IP_SRC_IP_OFFSET;
    do
    {
        retVal = GetSrcIpAddr (pktData, &tempPktLen);

    } while (retVal != PKT_SUCCESS);

    tempPktLen = l2HdrLen + PKT_IP_DST_IP_OFFSET;
    do
    {
        retVal = GetDestIpAddr (pktData, &tempPktLen);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetL3DatagramLength (pktData, pPktLen);

    } while (retVal != PKT_SUCCESS);

    ipHdrLen = (pktData[l2HdrLen] & 0xF) * 4;
    ipChecksum = ip_checksum (pktData + l2HdrLen, ipHdrLen);
    memcpy (pktData + l2HdrLen + PKT_IP_CHECKSUM_OFFSET,
            &ipChecksum, sizeof (ipChecksum));

    return PKT_SUCCESS;
}

int ConstructTcpHeader (char *pktData, int *pPktLen)
{
    int   l2HdrLen = 0;
    int   l3HdrLen = 0;
    int   l4HdrOffset = 0;
    int   retVal = PKT_SUCCESS;

    if (GetL2HdrLen (pktData, &l2HdrLen) != PKT_SUCCESS)
    {
        printf ("Failed to get L2 header length (Unknown Error)!!\r\n");
        return PKT_FAILURE;
    }

    l3HdrLen = (pktData[l2HdrLen] & 0xF) * 4;
    l4HdrOffset = l2HdrLen + l3HdrLen;

    printf ("\n");
    do
    {
        retVal = GetL4SrcPort (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetL4DstPort (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetTcpSeqNum (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetTcpAckNum (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    /* Set data offset to TCP header length */
    pktData[l4HdrOffset + PKT_TCP_DATA_OFFSET] |= 
        ((PKT_MIN_TCP_HDR_LEN / 4) << 4) & 0xF0;

    do
    {
        retVal = GetTcpFlags (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetTcpWindowSize (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    /* Set urgent pointer only if urgent bit is set */
    if (pktData[l4HdrOffset + PKT_TCP_FLAGS_OFFSET] & (0x1 << 5))
    {
        do
        {
            retVal = GetTcpUrgPtr (pktData, l4HdrOffset, *pPktLen);

        } while (retVal != PKT_SUCCESS);
    }

    CalculateL4Checksum (pktData, l4HdrOffset, PKT_TCP_PROT_NUM);

    return PKT_SUCCESS;
}

int ConstructUdpHeader (char *pktData, int *pPktLen)
{
    int       l2HdrLen = 0;
    int       l3HdrLen = 0;
    int       l4HdrOffset = 0;
    int       retVal = PKT_SUCCESS;
    uint16_t  l4SegmentLen = 0;

    if (GetL2HdrLen (pktData, &l2HdrLen) != PKT_SUCCESS)
    {
        printf ("Failed to get L2 header length (Unknown Error)!!\r\n");
        return PKT_FAILURE;
    }

    l3HdrLen = (pktData[l2HdrLen] & 0xF) * 4;
    l4HdrOffset = l2HdrLen + l3HdrLen;

    printf ("\n");
    do
    {
        retVal = GetL4SrcPort (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    do
    {
        retVal = GetL4DstPort (pktData, l4HdrOffset);

    } while (retVal != PKT_SUCCESS);

    memcpy (&l4SegmentLen, pktData + l2HdrLen + PKT_TOT_LEN_OFFSET,
            sizeof (l4SegmentLen));
    l4SegmentLen -= htons (l3HdrLen);
    memcpy (pktData + l4HdrOffset + PKT_UDP_LEN_OFFSET,
            &l4SegmentLen, sizeof (l4SegmentLen));

    CalculateL4Checksum (pktData, l4HdrOffset, PKT_UDP_PROT_NUM);

    return PKT_SUCCESS;
}

int ConvertCharToByte (char *pValue)
{
    char data = *pValue;

    if ((data >= '0') && (data <= '9'))
    {
        *pValue -= 48;
    }
    else if ((data >= 'A') && (data <= 'F'))
    {
        *pValue -= 55;
    }
    else if ((data >= 'a') && (data <= 'f'))
    {
        *pValue -= 87;
    }
    else
    {
        return PKT_FAILURE;
    }
 
    return PKT_SUCCESS;
}

int ConvertToOneBytePktData (char dataToConvert, char *pData)
{
    char tempData = 0;

    tempData = (dataToConvert >> 4) & 0xF;
    if (ConvertCharToByte (&tempData) != PKT_SUCCESS)
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }
    *pData = (tempData << 4) & 0xF0;

    tempData = dataToConvert & 0xF;
    if (ConvertCharToByte (&tempData) != PKT_SUCCESS)
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }
    *pData |= (tempData & 0xF);

    return PKT_SUCCESS;
}

int ValidateMacAddressFormat (char *macAddr)
{
    int i = 0;
    int bitCount = 0;
    int colonCount = 0;

    for (i = 0; i < PKT_MAC_ADDR_BUF_LEN; i++)
    {
        if (macAddr[i] == '\0')
        {
            continue;
        }
        if (macAddr[i] == ':')
        {
            colonCount++;
            if (bitCount != 2)
            {
                printf ("Invalid value entered!!\r\n");
                return PKT_FAILURE;
            }
            bitCount = 0;
            continue;
        }
        bitCount++;
    }

    if (colonCount == 5)
    {
        return PKT_SUCCESS;
    }

    printf ("Invalid value entered!!\r\n");
    return PKT_FAILURE;
}

int GetDestMacAddr (char *pktData, int *pPktLen)
{
    char macAddr[PKT_MAC_ADDR_BUF_LEN];
    char tempData = 0;
    int  i = 0;
    int  pktLen = 0;
    int  bitCount = 0;

    memset (macAddr, 0, sizeof(macAddr));
    printf ("Enter Destination MAC Address (xx:xx:xx:xx:xx:xx): ");
    scanf ("%s", macAddr);
    if (ValidateMacAddressFormat (macAddr) != PKT_SUCCESS)
    {   
        return PKT_FAILURE;
    }

    pktLen = *pPktLen;
    for (i = 0; i < PKT_MAC_ADDR_BUF_LEN; i++)
    {   
        tempData = macAddr[i];
        if ((tempData == ':') || (tempData == '\0'))
        {   
            continue;
        }
        if (ConvertCharToByte (&tempData) != PKT_SUCCESS)
        {   
            printf ("Invalid value entered!!\r\n");
            return PKT_FAILURE;
        }
        
        bitCount++;
        if (bitCount == 1)
        {   
            pktData[pktLen] = (tempData << 4) & 0xF0;
        }
        else
        {   
            pktData[pktLen] |= (tempData & 0xF);
            bitCount = 0;
            pktLen++;
        }
    }
    if (pktLen < PKT_DMAC_OFFSET + PKT_MAC_ADDR_LEN)
    {   
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    *pPktLen = pktLen;
    return PKT_SUCCESS;
}

int GetSrcMacAddr (char *pktData, int *pPktLen)
{
    char macAddr[PKT_MAC_ADDR_BUF_LEN];
    char tempData = 0;
    int  i = 0;
    int  pktLen = 0;
    int  bitCount = 0;

    memset (macAddr, 0, sizeof(macAddr));
    printf ("Enter Source MAC Address (xx:xx:xx:xx:xx:xx): ");
    scanf ("%s", macAddr);
    if (ValidateMacAddressFormat (macAddr) != PKT_SUCCESS)
    {
        return PKT_FAILURE;
    }

    pktLen = *pPktLen;
    for (i = 0; i < PKT_MAC_ADDR_BUF_LEN; i++)
    {
        tempData = macAddr[i];
        if ((tempData == ':') || (tempData == '\0'))
        {
            continue;
        }
        if (ConvertCharToByte (&tempData) != PKT_SUCCESS)
        {
            printf ("Invalid value entered!!\r\n");
            return PKT_FAILURE;
        }

        bitCount++;
        if (bitCount == 1)
        {
            pktData[pktLen] = (tempData << 4) & 0xF0;
        }
        else
        {
            pktData[pktLen] |= (tempData & 0xF);
            bitCount = 0;
            pktLen++;
        }
    }
    if (pktLen < PKT_SMAC_OFFSET + PKT_MAC_ADDR_LEN)
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    *pPktLen = pktLen;
    return PKT_SUCCESS;
}

int GetVlanTag (char *pktData, int *pPktLen)
{
    int  pktLen = 0;
    int  vlanPri = 0;
    int  vlanId = 0;
    char isInsertVlanHdr[2] = "n";

    while (1)
    {
        printf ("Insert VLAN Header? [y/n]: ");
        scanf ("%s", isInsertVlanHdr);
        switch (*isInsertVlanHdr)
        {
            case 'y':
            case 'Y':
                break;

            case 'n':
            case 'N':
                return PKT_SUCCESS;

            default:
                continue;
        }
        break;
    }

    printf ("Enter VLAN priority (%d-%d): ", 
            PKT_MIN_VLAN_PRI, PKT_MAX_VLAN_PRI);
    scanf ("%d", &vlanPri);
    if ((vlanPri < PKT_MIN_VLAN_PRI) || 
        (vlanPri > PKT_MAX_VLAN_PRI))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    printf ("Enter VLAN tag (%d-%d): ", 
            PKT_MIN_VLAN_ID, PKT_MAX_VLAN_ID);
    scanf ("%d", &vlanId);
    if ((vlanId < PKT_MIN_VLAN_ID) ||
        (vlanId > PKT_MAX_VLAN_ID))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    pktLen = *pPktLen;
    pktData[pktLen++] = 0x81;
    pktData[pktLen++] = 0x00;
    pktData[pktLen] = (vlanPri << 5) & 0xE0;
    pktData[pktLen++] |= ((vlanId >> 8) & 0xF);
    pktData[pktLen++] = vlanId & 0xFF;

    *pPktLen = pktLen;
    return PKT_SUCCESS;   
}

int GetEtherType (char *pktData, int *pPktLen)
{
    int    etherType = 0;
    int    pktLen = 0;

    printf ("Enter EtherType (0x%x-0x%x): ", PKT_MIN_ETHTYPE, 
            PKT_MAX_ETHTYPE);
    scanf ("%x", (int *) &etherType);
    if ((etherType < PKT_MIN_ETHTYPE) ||
        (etherType > PKT_MAX_ETHTYPE))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    pktLen = *pPktLen;
    etherType = htons (etherType);
    memcpy (pktData + pktLen, &etherType, 2);
    pktLen += 2;
    *pPktLen = pktLen;

    return PKT_SUCCESS;
}

int GetPktLength (char *pktData, int *pPktLen)
{   
    int    totalPktLen = 0;
    int    pktLen = *pPktLen;
    int    i = 0;

    printf ("Enter Packet Length for padding (%d <= packet length <= %d): ", 
            PKT_MIN_SIZE, PKT_MTU_SIZE);
    scanf ("%d", &totalPktLen);
    if ((totalPktLen < PKT_MIN_SIZE) || (totalPktLen > PKT_MTU_SIZE) ||
        (totalPktLen < pktLen))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    for (i = 0; i < totalPktLen - *pPktLen - PKT_CRC_LEN; i++)
    {
        pktData[pktLen++] = 0x00;
    }

    SetPktFcs (pktData, &pktLen);

    *pPktLen = pktLen;
    return PKT_SUCCESS;
}

int GetL3DatagramLength (char *pktData, int *pPktLen)
{
    int       datagramLen = 0;
    int       l2HdrLen = *pPktLen;
    uint8_t   ipProtNum = 0;

    printf ("Enter IP Datagram length (%d <= Datagram Length <= %d): ",
            PKT_MIN_L3_DATAGRAM_LEN, PKT_MTU_SIZE);
    scanf ("%d", &datagramLen);

    if ((datagramLen < PKT_MIN_L3_DATAGRAM_LEN) || 
        (datagramLen > PKT_MTU_SIZE))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    ipProtNum = pktData[l2HdrLen + PKT_IP_PROTOCOL_OFFSET];
    switch (ipProtNum)
    {
        case PKT_TCP_PROT_NUM:
            if (datagramLen < (PKT_MIN_L3_DATAGRAM_LEN + PKT_MIN_TCP_HDR_LEN))
            {
                printf ("Minimum IP datagram length for TCP packet is %d!!\r\n",
                        PKT_MIN_L3_DATAGRAM_LEN + PKT_MIN_TCP_HDR_LEN);
                return PKT_FAILURE;
            }
            break;

        case PKT_UDP_PROT_NUM:
            if (datagramLen < (PKT_MIN_L3_DATAGRAM_LEN + PKT_MIN_UDP_HDR_LEN))
            {
                printf ("Minimum IP datagram length for UDP packet is %d!!\r\n",
                        PKT_MIN_L3_DATAGRAM_LEN + PKT_MIN_UDP_HDR_LEN);
                return PKT_FAILURE;
            }
            break;

        default:
            break;
    }

    datagramLen = htons (datagramLen);
    memcpy (pktData + l2HdrLen + PKT_TOT_LEN_OFFSET, &datagramLen, 2);

    datagramLen = ntohs (datagramLen);
    *pPktLen = l2HdrLen + datagramLen;
    return PKT_SUCCESS;
}

int GetSrcIpAddr (char *pktData, int *pPktLen)
{
    char ipAddr[PKT_IPADDR_BUF_LEN];
    int  srcIpAddr = 0;
    int  pktLen = *pPktLen;

    memset (ipAddr, 0, sizeof(PKT_IPADDR_BUF_LEN));
    printf ("Enter Source IP Address (in dotted notation): ");
    scanf ("%s", ipAddr);

    srcIpAddr = inet_addr (ipAddr);
    if (srcIpAddr == INADDR_NONE)
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }
    
    memcpy (pktData + pktLen, &srcIpAddr, sizeof(srcIpAddr));
    pktLen += sizeof(srcIpAddr);

    *pPktLen = pktLen;
    return PKT_SUCCESS;
}

int GetDestIpAddr (char *pktData, int *pPktLen)
{
    char ipAddr[PKT_IPADDR_BUF_LEN];
    int  destIpAddr = 0;
    int  pktLen = *pPktLen;
    
    memset (ipAddr, 0, sizeof(PKT_IPADDR_BUF_LEN));
    printf ("Enter Destination IP Address (in dotted notation): ");
    scanf ("%s", ipAddr);

    destIpAddr = inet_addr (ipAddr);
    if (destIpAddr == INADDR_NONE)
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }
    
    memcpy (pktData + pktLen, &destIpAddr, sizeof(destIpAddr));
    pktLen += sizeof(destIpAddr);

    *pPktLen = pktLen;
    return PKT_SUCCESS;
}

void SetPktFcs (char *pktData, int *pPktLen)
{
    unsigned long crc = 0;

    crc = crc2 (*pPktLen, (unsigned char *) pktData);
    memcpy (pktData + *pPktLen, &crc, PKT_CRC_LEN);
    *pPktLen += PKT_CRC_LEN;

    return;
}

/* Code borrowed from: 
 * https://ttssh2.osdn.jp/manual/en/macro/command/crc32.html */
unsigned long crc2(int n, unsigned char c[])
{
	int i, j;
	unsigned long r;

	r = 0xFFFFFFFFUL;
	for (i = 0; i < n; i++) {
		r ^= c[i];
		for (j = 0; j < 8; j++)
			if (r & 1) r = (r >> 1) ^ CRCPOLY2;
			else       r >>= 1;
	}
	return r ^ 0xFFFFFFFFUL;
}

int GetL3Dscp (char *pktData, int l2HdrLen)
{
    int   dscp = 0;

    printf ("Enter IP DSCP (%d-%d): ", PKT_MIN_DSCP, PKT_MAX_DSCP);
    scanf ("%d", &dscp);
    if ((dscp < PKT_MIN_DSCP) || (dscp > PKT_MAX_DSCP))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    pktData[l2HdrLen + PKT_DSCP_OFFSET] |= ((dscp << 2) & 0xFC);
    return PKT_SUCCESS;
}

int GetIpFlags (char *pktData, int l2HdrLen)
{
    char   isSetIpFlags[2] = "n";
    char   isSetDfFlag[2] = "n";
    char   isSetMfFlag[2] = "n";
    
    while (1)
    {
        printf ("Set IP Flags (DF/MF)? [y/n]: ");
        scanf ("%s", isSetIpFlags);
        switch (*isSetIpFlags)
        {
            case 'y':
            case 'Y':
                while (1)
                {
                    printf ("Set DF Flag? [y/n]: ");
                    scanf ("%s", isSetDfFlag);
                    switch (*isSetDfFlag)
                    {
                        case 'y':
                        case 'Y':
                            pktData[l2HdrLen + PKT_IP_FLAGS_OFFSET] 
                                |= (0x1 << 6);
                        /* Intentional fall through */
                        case 'n':
                        case 'N':
                            break;

                        default:
                            continue;
                    }
                    break;
                }

                while (1)
                {
                    printf ("Set MF Flag? [y/n]: ");
                    scanf ("%s", isSetMfFlag);
                    switch (*isSetMfFlag)
                    {
                        case 'y':
                        case 'Y':
                            pktData[l2HdrLen + PKT_IP_FLAGS_OFFSET] 
                                |= 0x1 << 5;
                        /* Intentional fall through */
                        case 'n':
                        case 'N':
                            break;

                        default:
                            continue;
                    }
                    break;
                }

                break;

            case 'n':
            case 'N':
                return PKT_SUCCESS;

            default:
                continue;
        }

        break;
    }

    return PKT_SUCCESS;
}

int GetIpFragOffset (char *pktData, int l2HdrLen)
{
    int    ipFragOffset = 0;

    printf ("Enter IP Fragment Offset (%d-%d): ",
             PKT_MIN_IP_FRAG_OFF, PKT_MAX_IP_FRAG_OFF);
    scanf ("%d", &ipFragOffset);

    if ((ipFragOffset < PKT_MIN_IP_FRAG_OFF) || 
        (ipFragOffset > PKT_MAX_IP_FRAG_OFF))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }
    
    pktData[l2HdrLen + PKT_IP_FLAGS_OFFSET + 1] = ipFragOffset & 0xFF;
    pktData[l2HdrLen + PKT_IP_FLAGS_OFFSET] |= ((ipFragOffset >> 8) & 0x1F);

    return PKT_SUCCESS;
}

int GetIpTtl (char *pktData, int l2HdrLen)
{
    int   ipTtl = 0;

    printf ("Enter IP TTL (%d-%d): ", PKT_MIN_IP_TTL, PKT_MAX_IP_TTL);
    scanf ("%d", &ipTtl);

    if ((ipTtl < PKT_MIN_IP_TTL) || (ipTtl > PKT_MAX_IP_TTL))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    pktData[l2HdrLen + PKT_IP_TTL_OFFSET] = ipTtl;
    return PKT_SUCCESS;
}

int GetIpProtocol (char *pktData, int l2HdrLen)
{
    int ipProtNum = 0;

    printf ("Enter IP Protocol: (%d-%d): ",
            PKT_MIN_IP_PROT, PKT_MAX_IP_PROT);
    scanf ("%d", &ipProtNum);

    if ((ipProtNum < PKT_MIN_IP_PROT) || (ipProtNum > PKT_MAX_IP_PROT))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    pktData[l2HdrLen + PKT_IP_PROTOCOL_OFFSET] = ipProtNum;
    return PKT_SUCCESS;
}

/* Code borrowed from http://minirighi.sourceforge.net/html/ip_8c.html#a2 */
uint16_t ip_checksum (const void *buf, size_t hdr_len)
{
    unsigned long sum = 0;
    const uint16_t *ip1;

    ip1 = buf;
    while (hdr_len > 1)
    {
            sum += *ip1++;
            if (sum & 0x80000000)
                    sum = (sum & 0xFFFF) + (sum >> 16);
            hdr_len -= 2;
    }

    while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

    return(~sum);
}

int GetL2HdrLen (char *pktData, int *pL2HdrLen)
{
    uint16_t  vlanTpid = 0;

    vlanTpid = htons (PKT_VLAN_TPID);
    if (memcmp (pktData + PKT_SMAC_OFFSET + PKT_MAC_ADDR_LEN, &vlanTpid,
                sizeof (vlanTpid)))
    {
        /* No vlan header */
        *pL2HdrLen = PKT_SMAC_OFFSET + PKT_MAC_ADDR_LEN + sizeof (vlanTpid);
        return PKT_SUCCESS;
    }

    /* Vlan header present */
    *pL2HdrLen = PKT_MAC_ADDR_BUF_LEN;
    return PKT_SUCCESS;
}

int GetL4SrcPort (char *pktData, int l4HdrOffset)
{
    int       srcPortNum = 0;
    uint16_t  portNum = 0;

    printf ("Enter Source Port Number (%d-%d): ",
             PKT_MIN_L4_PORT_NUM, PKT_MAX_L4_PORT_NUM);
    scanf ("%d", &srcPortNum);

    if ((srcPortNum < PKT_MIN_L4_PORT_NUM) || 
        (srcPortNum > PKT_MAX_L4_PORT_NUM))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    portNum = htons (srcPortNum);
    memcpy (pktData + l4HdrOffset, &portNum, sizeof (portNum));

    return PKT_SUCCESS;
}

int GetL4DstPort (char *pktData, int l4HdrOffset)
{
    int       dstPortNum = 0;
    uint16_t  portNum = 0;

    printf ("Enter Destination Port Number (%d-%d): ",
             PKT_MIN_L4_PORT_NUM, PKT_MAX_L4_PORT_NUM);
    scanf ("%d", &dstPortNum);

    if ((dstPortNum < PKT_MIN_L4_PORT_NUM) || 
        (dstPortNum > PKT_MAX_L4_PORT_NUM))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    portNum = htons (dstPortNum);
    memcpy (pktData + l4HdrOffset + PKT_L4_DST_PORT_OFFSET, 
            &portNum, sizeof (portNum));

    return PKT_SUCCESS;
}

int GetTcpSeqNum (char *pktData, int l4HdrOffset)
{
    long long int  userInput = 0;
    uint32_t       seqNum = 0;

    printf ("Enter TCP Sequence Number (%d-%ld): ",
             PKT_MIN_TCP_SEQ_NUM, PKT_MAX_TCP_SEQ_NUM);
    scanf ("%lld", &userInput);

    if ((userInput < PKT_MIN_TCP_SEQ_NUM) || 
        (userInput > PKT_MAX_TCP_SEQ_NUM))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    seqNum = htonl (userInput);
    memcpy (pktData + l4HdrOffset + PKT_TCP_SEQ_NUM_OFFSET,
            &seqNum, sizeof (seqNum));

    return PKT_SUCCESS;
}

int GetTcpAckNum (char *pktData, int l4HdrOffset)
{
    long long int  userInput = 0;
    uint32_t       ackNum = 0;

    printf ("Enter TCP Acknowledgement Number (%d-%ld): ",
             PKT_MIN_TCP_ACK_NUM, PKT_MAX_TCP_ACK_NUM);
    scanf ("%lld", &userInput);

    if ((userInput < PKT_MIN_TCP_ACK_NUM) || 
        (userInput > PKT_MAX_TCP_ACK_NUM))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    ackNum = htonl (userInput);
    memcpy (pktData + l4HdrOffset + PKT_TCP_ACK_NUM_OFFSET,
            &ackNum, sizeof (ackNum));

    return PKT_SUCCESS;
}

int GetTcpFlags (char *pktData, int l4HdrOffset)
{
    char      flags[PKT_TCP_FLAG_BITS + 1];
    int       flagIndex = 0;
    uint8_t   flagBits = 0;

    memset (flags, 0, sizeof (flags));
    printf ("Enter TCP Flags (URG [U], ACK [A], PSH [P], RST [R], " 
            "SYN [S], FIN [F]): ");
    scanf ("%s", flags);

    for (flagIndex = 0; flagIndex < PKT_TCP_FLAG_BITS; flagIndex++)
    {
        switch (flags[flagIndex])
        {
            case 'U':
            case 'u':
                flagBits |= 0x1 << 5;
                break;

            case 'A':
            case 'a':
                flagBits |= 0x1 << 4;
                break;

            case 'P':
            case 'p':
                flagBits |= 0x1 << 3;
                break;

            case 'R':
            case 'r':
                flagBits |= 0x1 << 2;
                break;

            case 'S':
            case 's':
                flagBits |= 0x1 << 1;
                break;

            case 'F':
            case 'f':
                flagBits |= 0x1;
                break;

            default:
                continue;
        }
    }

    pktData[l4HdrOffset + PKT_TCP_FLAGS_OFFSET] |= (flagBits & 0x3F);
    return PKT_SUCCESS;
}

int GetTcpWindowSize (char *pktData, int l4HdrOffset)
{
    int        userInputWinSize = 0;
    uint16_t   windowSize = 0;

    printf ("Enter TCP Window Size (%d-%d): ", 
            PKT_TCP_MIN_WIN_SIZE, PKT_TCP_MAX_WIN_SIZE);
    scanf ("%d", &userInputWinSize);

    if ((userInputWinSize < PKT_TCP_MIN_WIN_SIZE) || 
        (userInputWinSize > PKT_TCP_MAX_WIN_SIZE))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }

    windowSize = htons (userInputWinSize);
    memcpy (pktData + l4HdrOffset + PKT_TCP_WIN_SIZE_OFFSET,
            &windowSize, sizeof (windowSize));

    return PKT_SUCCESS;
}

int GetTcpUrgPtr (char *pktData, int l4HdrOffset, int pktLen)
{
    uint16_t   urgPtr = 0;
    int        userInput = 0;
    int        l2HdrLen = 0;
    int        l3HdrLen = 0;
    int        l4HdrLen = 0;

    printf ("Enter Urgent Pointer (%d-%d): ", 
            PKT_TCP_MIN_URG_PTR, PKT_TCP_MAX_URG_PTR);
    scanf ("%d", &userInput);

    if ((userInput < PKT_TCP_MIN_URG_PTR) ||
        (userInput > PKT_TCP_MAX_URG_PTR))
    {
        printf ("Invalid value entered!!\r\n");
        return PKT_FAILURE;
    }
    
    if (GetL2HdrLen (pktData, &l2HdrLen) != PKT_SUCCESS)
    {
        printf ("Unexpected error occurred!!\r\n");
        return PKT_FAILURE;
    }
    l3HdrLen = (pktData[l2HdrLen] & 0xF) * 4;
    l4HdrLen = ((pktData[l4HdrOffset + PKT_TCP_DATA_OFFSET] >> 4) & 0xF) * 4;

    if ((l2HdrLen + l3HdrLen + l4HdrLen + userInput) > pktLen)
    {
        printf ("Urgent pointer > Total packet length!!\r\n");
        return PKT_FAILURE;
    }

    urgPtr = htons (userInput);
    memcpy (pktData + l4HdrLen + PKT_TCP_URG_PTR_OFFSET,
            &urgPtr, sizeof (urgPtr));

    return PKT_SUCCESS;
}

void CalculateL4Checksum (char *pktData, int l4HdrOffset, int ipProtNum)
{
    char        *pseudoTcpHdr = NULL;
    int         pseudoHdrOffset = 0;
    int         l2HdrLen = 0;
    int         l3HdrLen = 0;
    int         l4ChecksumOffset = 0;
    uint16_t    l4SegmentLen = 0;
    uint16_t    checksum = 0;

    if (GetL2HdrLen (pktData, &l2HdrLen) != PKT_SUCCESS)
    {
        return;
    }
    l3HdrLen = (pktData[l2HdrLen] & 0xF) * 4;
    memcpy (&l4SegmentLen, pktData + l2HdrLen + PKT_TOT_LEN_OFFSET,
            sizeof (l4SegmentLen));
    l4SegmentLen = ntohs (l4SegmentLen);
    l4SegmentLen -= l3HdrLen;

    pseudoTcpHdr = (char *) malloc (PKT_TCP_PSEUDO_HDR_LEN + l4SegmentLen);
    if (pseudoTcpHdr == NULL)
    {
        printf ("Unknown error occurred (Malloc failed)!!\r\n");
        return;
    }
    memset (pseudoTcpHdr, 0, PKT_TCP_PSEUDO_HDR_LEN + l4SegmentLen);

    /* Copy source and destination IP addresses */
    memcpy (pseudoTcpHdr, pktData + l2HdrLen + PKT_IP_SRC_IP_OFFSET,
            2 * PKT_IP_ADDR_LEN);
    pseudoHdrOffset += 2 * PKT_IP_ADDR_LEN; 
    /* skipping empty field */
    pseudoHdrOffset++;
    /* Adding IP protocol field */
    pseudoTcpHdr[pseudoHdrOffset++] = ipProtNum;

    /* Adding L4 segment length */
    l4SegmentLen = htons (l4SegmentLen);
    memcpy (pseudoTcpHdr + pseudoHdrOffset, &l4SegmentLen, 
            sizeof (l4SegmentLen));
    l4SegmentLen = ntohs (l4SegmentLen);
    pseudoHdrOffset += sizeof (l4SegmentLen);

    /* Copying L4 segment */
    memcpy (pseudoTcpHdr + pseudoHdrOffset, pktData + l4HdrOffset, 
            l4SegmentLen);

    checksum = ip_checksum (pseudoTcpHdr,  
                            PKT_TCP_PSEUDO_HDR_LEN + l4SegmentLen);
    free (pseudoTcpHdr);

    switch (ipProtNum)
    {
        case PKT_TCP_PROT_NUM:
            l4ChecksumOffset = PKT_TCP_CHECKSUM_OFFSET;
            break;

        case PKT_UDP_PROT_NUM:
            l4ChecksumOffset = PKT_UDP_CHECKSUM_OFFSET;
            break;

        default:
            return;
    }

    memcpy (pktData + l4HdrOffset + l4ChecksumOffset, &checksum, 
            sizeof (checksum));
    return;
}
