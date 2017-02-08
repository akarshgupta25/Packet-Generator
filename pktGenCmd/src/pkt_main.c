/********************************************************************
*
* Filename: pkt_main.c
*
* Description: This file contains the packet generator code
*
*******************************************************************/

#include "pkt_hdrs.h"

int main (int argc, char *argv[])
{
    tCmdLineArg cmdLineArg;
    char        pktData[PKT_MTU_SIZE + PKT_MAC_ADDR_BUF_LEN];
    int         pktLen = 0;

    if (ValidateCmdLineArg (argv, argc, &cmdLineArg) != PKT_SUCCESS)
    {
        return PKT_FAILURE;
    }

    memset (pktData, 0, sizeof(pktData));
    if (cmdLineArg.isFileInput == PKT_TRUE)
    {
        if (ReadPktDataFromFile (cmdLineArg.pFileName, pktData, &pktLen)
            != PKT_SUCCESS)
        {
            CleanupPktGen (&cmdLineArg);
            return PKT_FAILURE;
        }
    }
    else
    {
        if (ReadPktDataFromUser (pktData, &pktLen) != PKT_SUCCESS)
        {
            CleanupPktGen (&cmdLineArg);
            return PKT_FAILURE;
        }
    }

    if (SendDataToKernel (cmdLineArg, pktData, pktLen)
        != PKT_SUCCESS)
    {
        CleanupPktGen (&cmdLineArg);
        return PKT_FAILURE;
    }

    CleanupPktGen (&cmdLineArg);
    return PKT_SUCCESS;
}

int ValidateCmdLineArg (char *argv[], int argc, tCmdLineArg *pCmdLineArg)
{
    char *pIfName = NULL;
    char *pFileName = NULL;

    /* Validate number of command line arguments */
    if ((argc != PKT_CMD_LINE_ARG_NUM) &&
        (argc != (PKT_CMD_LINE_ARG_NUM - 1)))
    {
        printf ("Usage: pktGen <interface> <num_of_pkts> " 
                "<inter-packet interval> <input_file>\r\n\n");
        return PKT_FAILURE;
    }

    memset (pCmdLineArg, 0, sizeof (tCmdLineArg));
    /* Validate and store each command line argument */
    pIfName = (char *) malloc (strlen (argv[1]) + 1);
    if (pIfName == NULL)
    {
        printf ("Failed to allocate memory to interface name!!\r\n");
        return PKT_FAILURE;
    }
    memset (pIfName, 0, strlen(argv[1]) + 1);
    strcpy (pIfName, argv[1]);
    pCmdLineArg->pIfName = pIfName;

    if ((pCmdLineArg->numPkts = strtol (argv[2], NULL, 10)) == 0)
    {
        printf ("Invalid number of packets entered!!\r\n");
        free (pCmdLineArg->pIfName);
        pCmdLineArg->pIfName = NULL;
        return PKT_FAILURE;
    }

    if ((pCmdLineArg->pktInterval = strtol (argv[3], NULL, 10)) == 0)
    {
        printf ("Invalid inter-packet interval entered!!\r\n");
        free (pCmdLineArg->pIfName);
        pCmdLineArg->pIfName = NULL;
        return PKT_FAILURE;
    }

    if (argc == (PKT_CMD_LINE_ARG_NUM - 1))
    {
        pCmdLineArg->isFileInput = PKT_FALSE;
        return PKT_SUCCESS;
    }

    pFileName = (char *) malloc (strlen (argv[4] + 1));
    if (pFileName == NULL)
    {
        printf ("Failed to allocate memory to file name!!\r\n");
        free (pCmdLineArg->pIfName);
        pCmdLineArg->pIfName = NULL;
        return PKT_FAILURE;
    }
    memset (pFileName, 0, strlen(argv[4]) + 1);
    strcpy (pFileName, argv[4]);
    pCmdLineArg->pFileName = pFileName;
    pCmdLineArg->isFileInput = PKT_TRUE;

    return PKT_SUCCESS;
}

void CleanupPktGen (tCmdLineArg *pCmdLineArg)
{
    free (pCmdLineArg->pIfName);
    pCmdLineArg->pIfName = NULL;

    if (pCmdLineArg->isFileInput == PKT_TRUE)
    {
        free (pCmdLineArg->pFileName);
    }
    pCmdLineArg->pFileName = NULL;

    return;
}

int ReadPktDataFromFile (char *pFileName, char *pktData, int *pPktLen)
{
    FILE *pFile = NULL;
    char fileData = 0;
    int  bitCount = 0;
    int  i = 0;

    pFile = fopen (pFileName, "r");
    if (pFile == NULL)
    {
        printf ("Invalid filename!!\r\n");
        return PKT_FAILURE;
    }

    while ((fileData = fgetc (pFile)) != EOF)
    {
        if (ConvertCharToByte (&fileData) != PKT_SUCCESS)
        {
            continue;
        }

        bitCount++;
        if (bitCount == 1)
        {
            pktData[i] = (fileData << 4) & 0xF0;
        }
        else
        {
            pktData[i] |= (fileData & 0xF);
            bitCount = 0;
            i++;
        }
    }

    *pPktLen = i;

    fclose (pFile);
    return PKT_SUCCESS;
}

int SendDataToKernel (tCmdLineArg cmdLineArg, char *pktData,
                      int pktLen)
{
    struct sockaddr_nl srcAddr;
    struct sockaddr_nl kernelAddr;
    struct nlmsghdr    *nlMsg = NULL;
    struct nlmsghdr    *nlMsgParser = NULL;
    struct msghdr      msg;
    struct iovec       iov;
    int                socketFd = 0;
    int                msgLen = 0;
    int                nlMsgLen = 0;

    socketFd = socket (PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (socketFd < 0)
    {
        printf ("Failed to create netlink socket!!\r\n");
        return PKT_FAILURE;
    }

    memset (&srcAddr, 0, sizeof (srcAddr));
    srcAddr.nl_family = AF_NETLINK;
    srcAddr.nl_pid = getpid();
    if (bind (socketFd, (struct sockaddr *) &srcAddr, 
        sizeof (srcAddr)) < 0)
    {
        printf ("Failed to bind netlink socket!!\r\n");
        close (socketFd);
        return PKT_FAILURE;
    }

    memset (&kernelAddr, 0, sizeof (kernelAddr));
    kernelAddr.nl_family = AF_NETLINK;
    kernelAddr.nl_pid = 0;
    kernelAddr.nl_groups = 0;

    nlMsgLen = NLMSG_SPACE (pktLen) + 
               NLMSG_SPACE (strlen (cmdLineArg.pIfName) + 1) +
               NLMSG_SPACE (sizeof (cmdLineArg.numPkts)) +
               NLMSG_SPACE (sizeof (cmdLineArg.pktInterval));
    nlMsg = (struct nlmsghdr *) malloc (nlMsgLen);
    if (nlMsg == NULL)
    {
        printf ("Failed to allocate memory to kernel netlink message\r\n");
        close (socketFd);
        return PKT_FAILURE;
    }
    memset (nlMsg, 0, nlMsgLen);

    nlMsgParser = nlMsg;
    nlMsgParser->nlmsg_len = NLMSG_SPACE (pktLen);
    nlMsgParser->nlmsg_pid = getpid();
    nlMsgParser->nlmsg_flags = NLM_F_MULTI;
    memcpy (NLMSG_DATA (nlMsgParser), pktData, pktLen);

    nlMsgParser = (struct nlmsghdr *) (void *)
                  (((char *) nlMsgParser) + NLMSG_SPACE (pktLen));
    nlMsgParser->nlmsg_len = NLMSG_SPACE (strlen (cmdLineArg.pIfName) + 1);
    nlMsgParser->nlmsg_pid = getpid();
    nlMsgParser->nlmsg_flags = NLM_F_MULTI;
    strcpy (NLMSG_DATA (nlMsgParser), cmdLineArg.pIfName);

    nlMsgParser = (struct nlmsghdr *) (void *)
                  (((char *) nlMsgParser) + 
                   NLMSG_SPACE (strlen (cmdLineArg.pIfName) + 1));
    nlMsgParser->nlmsg_len = NLMSG_SPACE (sizeof (cmdLineArg.numPkts));
    nlMsgParser->nlmsg_pid = getpid();
    nlMsgParser->nlmsg_flags = NLM_F_MULTI;
    memcpy (NLMSG_DATA (nlMsgParser), &cmdLineArg.numPkts, 
            sizeof (cmdLineArg.numPkts));

    nlMsgParser = (struct nlmsghdr *) (void *)
                  (((char *) nlMsgParser) +
                   NLMSG_SPACE (sizeof (cmdLineArg.numPkts)));
    nlMsgParser->nlmsg_len = NLMSG_SPACE (sizeof (cmdLineArg.pktInterval));
    nlMsgParser->nlmsg_pid = getpid();
    nlMsgParser->nlmsg_flags = NLMSG_DONE;
    memcpy (NLMSG_DATA (nlMsgParser), &cmdLineArg.pktInterval,
            sizeof (cmdLineArg.pktInterval));

    printf ("\nThe following packet shall be transmitted:");
    DumpPacket (pktData, pktLen);
    printf ("Packet Length:%u\r\n", pktLen);

    memset (&msg, 0, sizeof(msg));
    memset (&iov, 0, sizeof(iov));
    iov.iov_base = (void *) nlMsg;
    iov.iov_len = nlMsgLen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = (void *) &kernelAddr;
    msg.msg_namelen = sizeof (kernelAddr);
    msgLen = sendmsg (socketFd, &msg, 0);
    if (msgLen == 0)
    {
        printf ("Failed to send message to kernel!!\n");
        free (nlMsg);
        close (socketFd);
        return PKT_FAILURE;
    }

    recvmsg (socketFd, &msg, 0);
    printf("\n%s\n\n", (char *) NLMSG_DATA (nlMsg));

    free (nlMsg);
    close (socketFd);
    return PKT_SUCCESS;
}

int ReadPktDataFromUser (char *pktData, int *pPktLen)
{
    int pktType = 0;
    int pktLen = 0;
    int retVal = PKT_SUCCESS;

    DisplaySpecificPktTypes();
    scanf ("%d", &pktType);

    switch (pktType)
    {
        case PKT_ARP_PACKET:
            retVal = ConstructArpPacket (pktData, &pktLen);
            break;

        case PKT_L2_PACKET:
            retVal = ConstructL2Header (pktData, &pktLen, PKT_FALSE);
            if (retVal == PKT_SUCCESS)
            {
                do
                {
                    retVal = GetPktLength (pktData, &pktLen);

                } while (retVal != PKT_SUCCESS);
            }

            break;

        case PKT_IP_PACKET:
            retVal = ConstructL2Header (pktData, &pktLen, PKT_TRUE);
            if (retVal == PKT_SUCCESS)
            {
                retVal = ConstructL3Header (pktData, &pktLen, 0);
            }

            break;

        case PKT_TCP_PACKET:
            retVal = ConstructL2Header (pktData, &pktLen, PKT_TRUE);
            if (retVal == PKT_SUCCESS)
            {
                retVal = ConstructL3Header (pktData, &pktLen, 
                                            PKT_TCP_PROT_NUM);
                if (retVal != PKT_SUCCESS)
                {
                    break;
                }
                retVal = ConstructTcpHeader (pktData, &pktLen);
            }

            break;

        case PKT_UDP_PACKET:
            retVal = ConstructL2Header (pktData, &pktLen, PKT_TRUE);
            if (retVal == PKT_SUCCESS)
            {
                retVal = ConstructL3Header (pktData, &pktLen,
                                            PKT_UDP_PROT_NUM);
                if (retVal != PKT_SUCCESS)
                {
                    break;
                }
                retVal = ConstructUdpHeader (pktData, &pktLen);
            }
            break;

        default:
            printf ("Invalid Option!!\r\n");
            return PKT_FAILURE;
    }

    *pPktLen = pktLen;

    return retVal;
}
