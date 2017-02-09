/********************************************************************
*
* Filename: pkt_main.c
*
* Description: This file contains the packet generator code
*
*******************************************************************/

#include "pkt_hdrs.h"

struct sock *sock = NULL;
extern struct net init_net;
char *pErrStr = NULL;

static void userMsgRx (struct sk_buff *skb) 
{
    struct nlmsghdr *nlMsg = NULL;
    struct nlmsghdr *nlMsgParser = NULL;
    struct sk_buff  *skbTx = NULL;
    tCmdLineArg     cmdLineArg;
    __u8            *pktData = NULL;
    int             pktLen = 0;
    int             userPid = 0;
    int             msgSize = 5;
    int             nlMsgLen = 0;

    memset (&cmdLineArg, 0, sizeof (cmdLineArg));
    if (skb == NULL)
    {
        printk (KERN_CRIT "Received empty message from user!!\n");
        pErrStr = "NetLink Message Receive Error!!";
        goto error;
    }

    nlMsgLen = skb->len;
    nlMsg = (struct nlmsghdr *) skb->data;
    if (nlMsg == NULL)
    {
        printk (KERN_CRIT "Received empty data from user!!\n");
        pErrStr = "NetLink Message Data Error!!";
        goto error;
    }
    userPid = nlMsg->nlmsg_pid;

    nlMsgParser = nlMsg;
    pktData = (char *) NLMSG_DATA (nlMsgParser);
    pktLen = nlMsgParser->nlmsg_len - NLMSG_HDRLEN;
    if (nlMsgParser->nlmsg_flags != NLM_F_MULTI)
    {
        printk (KERN_CRIT "NLM_F_MULTI flag not set!!\n");
        pErrStr = "NetLink Message Format Error!!";
        goto error;
    }

    nlMsgParser = NLMSG_NEXT (nlMsgParser, nlMsgLen);
    cmdLineArg.pIfName = (char *) NLMSG_DATA (nlMsgParser);
    if (nlMsgParser->nlmsg_flags != NLM_F_MULTI)
    {
        printk (KERN_CRIT "NLM_F_MULTI flag not set!!\n");
        pErrStr = "NetLink Message Format Error!!";
        goto error;
    }
    
    nlMsgParser = NLMSG_NEXT (nlMsgParser, nlMsgLen);
    cmdLineArg.numPkts = *((int *) NLMSG_DATA (nlMsgParser));
    if (nlMsgParser->nlmsg_flags != NLM_F_MULTI)
    {
        printk (KERN_CRIT "NLM_F_MULTI flag not set!!\n");
        pErrStr = "NetLink Message Format Error!!";
        goto error;
    }

    nlMsgParser = NLMSG_NEXT (nlMsgParser, nlMsgLen);
    cmdLineArg.pktInterval = *((int *) NLMSG_DATA (nlMsgParser));
    if (nlMsgParser->nlmsg_flags != NLMSG_DONE)
    {
        printk (KERN_CRIT "NLMSG_DONE flag not set!!\n");
        pErrStr = "NetLink Message Format Error!!";
        goto error;
    }

    if (SendDataFromInterface (cmdLineArg, pktData, pktLen) != PKT_SUCCESS)
    {
        printk (KERN_CRIT "Failed to send packet!!\n");
        goto error;
    }

    pErrStr = "Packet successfully transmitted!!";

error:
    msgSize = strlen (pErrStr) + 1;
    skbTx = nlmsg_new (msgSize, 0);
    if (skbTx == NULL)
    {
        printk (KERN_CRIT "Failed to allocate memory to user message!!\n");
        return;
    }

    nlMsg = nlmsg_put (skbTx, 0, 0, NLMSG_DONE, msgSize,0);
    NETLINK_CB (skbTx).dst_group = 0;
    strncpy (nlmsg_data (nlMsg), pErrStr, msgSize);
    if (nlmsg_unicast (sock, skbTx, userPid) < 0)
    {
        printk (KERN_CRIT "Failed to send message to user!!\n");
    }

    return;    
}

static int __init PktGenInit (void)
{
    struct netlink_kernel_cfg cfg = { .input = userMsgRx };

    sock = netlink_kernel_create (&init_net, NETLINK_USER, &cfg);
    if(sock == NULL)
    {
        printk (KERN_CRIT "Failed to create Netlink socket!!\n");
        return PKT_FAILURE;
    }

    printk (KERN_INFO "PktGen kernel module inserted successfully!!\n");
    return PKT_SUCCESS;
}

static void __exit PktGenDeInit (void)
{
    netlink_kernel_release (sock);
    printk (KERN_INFO "Removing PktGen Kernel Module!!\n");
    return;
}

int SendDataFromInterface (tCmdLineArg cmdLineArg, char *pktData,
                           int pktLen)
{
    struct net_device    *dev = NULL;
    struct sockaddr_ll   socketBindAddr;
    struct socket        *socket = NULL;
    struct msghdr        msg;
    struct iovec         iov;
    mm_segment_t         old_fs;
    __u32                msgLen = 0;
    int                  numPktsSent = 0;

    if ((sock_create (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL),
         &socket)) < 0)
    {
        printk (KERN_CRIT "Failed to open data socket!!\r\n");
        pErrStr = "Failed to open raw socket!!";
        return PKT_FAILURE;
    }

    dev = getNetDevByName (cmdLineArg.pIfName);
    if (dev == NULL)
    {
        printk (KERN_CRIT "Device not found!!\r\n");
        pErrStr = "Invalid Interface Name!!";
        socket->ops->release (socket);
        return PKT_FAILURE;
    }

    memset (&socketBindAddr, 0, sizeof(socketBindAddr));
    socketBindAddr.sll_family = AF_PACKET;
    socketBindAddr.sll_protocol = htons(ETH_P_ALL);
    socketBindAddr.sll_ifindex = dev->ifindex;

    if (socket->ops->bind (socket, (struct sockaddr *) &socketBindAddr,
                           sizeof(socketBindAddr)) < 0)
    {   
        printk (KERN_CRIT "Failed to bind data socket!!\r\n");
        pErrStr = "Failed to bind raw socket!!";
        socket->ops->release (socket);
        return PKT_FAILURE;
    }

    for (numPktsSent = 0; numPktsSent < cmdLineArg.numPkts; 
         numPktsSent++)
    {
        memset (&msg, 0, sizeof(msg));
        memset (&iov, 0, sizeof(iov));
#ifdef KERN_VER_3
        iov.iov_base = pktData;
        iov.iov_len = pktLen;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
#endif /* KERN_VER_3 */
#ifdef KERN_VER_4
        iov.iov_base = pktData;
        iov.iov_len = pktLen;
        msg.msg_iter.type = ITER_IOVEC;
        msg.msg_iter.iov = &iov;
        msg.msg_iter.count = pktLen;
#endif /* KERN_VER_4 */
        old_fs = get_fs();
        set_fs(KERNEL_DS);
#ifdef KERN_VER_3
        msgLen = sock_sendmsg (socket, &msg, pktLen);
#endif /* KERN_VER_3 */
#ifdef KERN_VER_4
        msgLen = sock_sendmsg (socket, &msg);
#endif /* KERN_VER_4 */
        set_fs(old_fs);
        if (msgLen == 0)
        {
            printk (KERN_CRIT "Failed to send message from data "
                              "socket!!\r\n");
            pErrStr = "Failed to send message";
        }
        msleep (1000 * cmdLineArg.pktInterval);
    }

    /* Close socket */
    socket->ops->release (socket);
    return PKT_SUCCESS;
}

module_init (PktGenInit);
module_exit (PktGenDeInit);

MODULE_LICENSE ("Proprietary");
MODULE_AUTHOR (MOD_AUTHOR);
MODULE_DESCRIPTION (MOD_DESC);

