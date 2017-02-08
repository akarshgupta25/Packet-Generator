/********************************************************************
*
* Filename: pkt_util.c
*
* Description: This file contains the utility functions used by
*              packet generator
*
*******************************************************************/

#include "pkt_hdrs.h"

extern struct net init_net;

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
            printk (KERN_INFO "\n");
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
        
        printk (KERN_INFO "%c%c ", tempDataLow, tempDataHigh);
    }
    printk (KERN_INFO "\n");
   
    return;
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
        return PKT_FAILURE;
    }
    *pData = (tempData << 4) & 0xF0;

    tempData = dataToConvert & 0xF;
    if (ConvertCharToByte (&tempData) != PKT_SUCCESS)
    {
        return PKT_FAILURE;
    }
    *pData |= (tempData & 0xF);

    return PKT_SUCCESS;
}

struct net_device *getNetDevByName (char *pIfName)
{
    struct net_device *pTempDev = NULL;

    pTempDev = first_net_device (&init_net);
    while (pTempDev)
    {
        if (!strcmp (pTempDev->name, pIfName))
        {
            return pTempDev;
        }
        pTempDev = next_net_device (pTempDev);
    }

    return NULL;
}
