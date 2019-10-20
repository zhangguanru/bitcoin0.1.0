// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include <winsock2.h>

// 这三个函数 和其他节点建立连接 并且处理消息的传递
void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);
void ThreadOpenConnections2(void* parg);






//
// Global state variables
// 全局状态变量
bool fClient = false;
uint64 nLocalServices = (fClient ? 0 : NODE_NETWORK);
CAddress addrLocalHost(0, DEFAULT_PORT, nLocalServices);
CNode nodeLocalHost(INVALID_SOCKET, CAddress("127.0.0.1", nLocalServices));
CNode* pnodeLocalHost = &nodeLocalHost;
bool fShutdown = false;
array<bool, 10> vfThreadRunning;
vector<CNode*> vNodes;
CCriticalSection cs_vNodes;
map<vector<unsigned char>, CAddress> mapAddresses;
CCriticalSection cs_mapAddresses;
map<CInv, CDataStream> mapRelay;
deque<pair<int64, CInv> > vRelayExpiration;
CCriticalSection cs_mapRelay;
map<CInv, int64> mapAlreadyAskedFor;



CAddress addrProxy;

// 连接Socket
bool ConnectSocket(const CAddress& addrConnect, SOCKET& hSocketRet)
{
    hSocketRet = INVALID_SOCKET;

    SOCKET hSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (hSocket == INVALID_SOCKET)
        return false;

    bool fRoutable = !(addrConnect.GetByte(3) == 10 || (addrConnect.GetByte(3) == 192 && addrConnect.GetByte(2) == 168));
    bool fProxy = (addrProxy.ip && fRoutable);
    struct sockaddr_in sockaddr = (fProxy ? addrProxy.GetSockAddr() : addrConnect.GetSockAddr());

    if (connect(hSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        closesocket(hSocket);
        return false;
    }

    if (fProxy)
    {
        printf("Proxy connecting to %s\n", addrConnect.ToString().c_str());
        char pszSocks4IP[] = "\4\1\0\0\0\0\0\0user";
        memcpy(pszSocks4IP + 2, &addrConnect.port, 2);
        memcpy(pszSocks4IP + 4, &addrConnect.ip, 4);
        char* pszSocks4 = pszSocks4IP;
        int nSize = sizeof(pszSocks4IP);

        int ret = send(hSocket, pszSocks4, nSize, 0);
        if (ret != nSize)
        {
            closesocket(hSocket);
            return error("Error sending to proxy\n");
        }
        char pchRet[8];
        if (recv(hSocket, pchRet, 8, 0) != 8)
        {
            closesocket(hSocket);
            return error("Error reading proxy response\n");
        }
        if (pchRet[1] != 0x5a)
        {
            closesocket(hSocket);
            return error("Proxy returned error %d\n", pchRet[1]);
        }
        printf("Proxy connection established %s\n", addrConnect.ToString().c_str());
    }

    hSocketRet = hSocket;
    return true;
}

// 得到默认的外部IP
bool GetMyExternalIP(unsigned int& ipRet)
{
    CAddress addrConnect("72.233.89.199:80"); // whatismyip.com 198-200

    SOCKET hSocket;
    if (!ConnectSocket(addrConnect, hSocket))
        return error("GetMyExternalIP() : connection to %s failed\n", addrConnect.ToString().c_str());

    char* pszGet =
        "GET /automation/n09230945.asp HTTP/1.1\r\n"
        "Host: www.whatismyip.com\r\n"
        "User-Agent: Bitcoin/0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    send(hSocket, pszGet, strlen(pszGet), 0);

    string strLine;
    while (RecvLine(hSocket, strLine))
    {
        if (strLine.empty())
        {
            if (!RecvLine(hSocket, strLine))
            {
                closesocket(hSocket);
                return false;
            }
            closesocket(hSocket);
            CAddress addr(strLine.c_str());
            printf("GetMyExternalIP() received [%s] %s\n", strLine.c_str(), addr.ToString().c_str());
            if (addr.ip == 0)
                return false;
            ipRet = addr.ip;
            return true;
        }
    }
    closesocket(hSocket);
    return error("GetMyExternalIP() : connection closed\n");
}





// 添加其他服务的地址
bool AddAddress(CAddrDB& addrdb, const CAddress& addr)
{
    if (!addr.IsRoutable())
        return false;
    // 过滤调自己的IP地址
    if (addr.ip == addrLocalHost.ip)
        return false;
    CRITICAL_BLOCK(cs_mapAddresses)
    {
        map<vector<unsigned char>, CAddress>::iterator it = mapAddresses.find(addr.GetKey());
        if (it == mapAddresses.end())
        {
            // New address
            mapAddresses.insert(make_pair(addr.GetKey(), addr));
            addrdb.WriteAddress(addr);
            return true;
        }
        else
        {
            CAddress& addrFound = (*it).second;
            if ((addrFound.nServices | addr.nServices) != addrFound.nServices)
            {
                // Services have been added
                // 服务已添加
                addrFound.nServices |= addr.nServices;
                addrdb.WriteAddress(addrFound);
                return true;
            }
        }
    }
    return false;
}





void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1)
{
    // If the dialog might get closed before the reply comes back,
    // call this in the destructor so it doesn't get called after it's deleted.
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
        {
            CRITICAL_BLOCK(pnode->cs_mapRequests)
            {
                for (map<uint256, CRequestTracker>::iterator mi = pnode->mapRequests.begin(); mi != pnode->mapRequests.end();)
                {
                    CRequestTracker& tracker = (*mi).second;
                    if (tracker.fn == fn && tracker.param1 == param1)
                        pnode->mapRequests.erase(mi++);
                    else
                        mi++;
                }
            }
        }
    }
}







//
// Subscription methods for the broadcast and subscription system.
// Channel numbers are message numbers, i.e. MSG_TABLE and MSG_PRODUCT.
//
// The subscription system uses a meet-in-the-middle strategy.
// With 100,000 nodes, if senders broadcast to 1000 random nodes and receivers
// subscribe to 1000 random nodes, 99.995% (1 - 0.99^1000) of messages will get through.
// 广播和订阅系统的订阅方法。
// 通道号是消息号，即MSG_TABLE和MSG_PRODUCT。
// 订阅系统使用中间会议策略。
// 如果发送者广播到1000个随机节点和接收者，则具有100,000个节点
// 订阅1000个随机节点，则99.995％（1-0.99 ^ 1000）的消息将通过。

bool AnySubscribed(unsigned int nChannel)
{
    if (pnodeLocalHost->IsSubscribed(nChannel))
        return true;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->IsSubscribed(nChannel))
                return true;
    return false;
}

bool CNode::IsSubscribed(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return false;
    return vfSubscribe[nChannel];
}

void CNode::Subscribe(unsigned int nChannel, unsigned int nHops)
{
    if (nChannel >= vfSubscribe.size())
        return;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscribe
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("subscribe", nChannel, nHops);
    }

    vfSubscribe[nChannel] = true;
}

void CNode::CancelSubscribe(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return;

    // Prevent from relaying cancel if wasn't subscribed
    if (!vfSubscribe[nChannel])
        return;
    vfSubscribe[nChannel] = false;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscription cancel
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("sub-cancel", nChannel);

        // Clear memory, no longer subscribed
        if (nChannel == MSG_PRODUCT)
            CRITICAL_BLOCK(cs_mapProducts)
                mapProducts.clear();
    }
}









CNode* FindNode(unsigned int ip)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr.ip == ip)
                return (pnode);
    }
    return NULL;
}

CNode* FindNode(CAddress addr)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr == addr)
                return (pnode);
    }
    return NULL;
}

// 连接节点
CNode* ConnectNode(CAddress addrConnect, int64 nTimeout)
{
    if (addrConnect.ip == addrLocalHost.ip)
        return NULL;

    // Look for an existing connection
    // 查找现有连接
    CNode* pnode = FindNode(addrConnect.ip);
    if (pnode)
    {
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        return pnode;
    }

    /// debug print
    printf("trying %s\n", addrConnect.ToString().c_str());

    // Connect
    SOCKET hSocket;
    if (ConnectSocket(addrConnect, hSocket))
    {
        /// debug print
        printf("connected %s\n", addrConnect.ToString().c_str());

        // Add node
        // 添加节点
        CNode* pnode = new CNode(hSocket, addrConnect, false);
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(pnode);

        CRITICAL_BLOCK(cs_mapAddresses)
            mapAddresses[addrConnect.GetKey()].nLastFailed = 0;
        return pnode;
    }
    else
    {
        CRITICAL_BLOCK(cs_mapAddresses)
            mapAddresses[addrConnect.GetKey()].nLastFailed = GetTime();
        return NULL;
    }
}

// 断开连接
void CNode::Disconnect()
{
    printf("disconnecting node %s\n", addr.ToString().c_str());

    closesocket(hSocket);

    // All of a nodes broadcasts and subscriptions are automatically torn down
    // when it goes down, so a node has to stay up to keep its broadcast going.

    CRITICAL_BLOCK(cs_mapProducts)
        for (map<uint256, CProduct>::iterator mi = mapProducts.begin(); mi != mapProducts.end();)
            AdvertRemoveSource(this, MSG_PRODUCT, 0, (*(mi++)).second);

    // Cancel subscriptions
    for (unsigned int nChannel = 0; nChannel < vfSubscribe.size(); nChannel++)
        if (vfSubscribe[nChannel])
            CancelSubscribe(nChannel);
}












// 处理Socket线程
void ThreadSocketHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadSocketHandler(parg));

    loop
    {
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        try
        {
            ThreadSocketHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadSocketHandler()")
        vfThreadRunning[0] = false;
        Sleep(5000);
    }
}

// 和其他节点建立连接 接收和发送数据
void ThreadSocketHandler2(void* parg)
{
    printf("ThreadSocketHandler started\n");
    SOCKET hListenSocket = *(SOCKET*)parg;
    list<CNode*> vNodesDisconnected;
    int nPrevNodeCount = 0;

    loop
    {
        //
        // Disconnect nodes
        // 断开节点
        CRITICAL_BLOCK(cs_vNodes)
        {
            // Disconnect duplicate connections
            // 断开重复的连接
            map<unsigned int, CNode*> mapFirst;
            foreach(CNode* pnode, vNodes)
            {
                if (pnode->fDisconnect)
                    continue;
                unsigned int ip = pnode->addr.ip;
                if (mapFirst.count(ip) && addrLocalHost.ip < ip)
                {
                    // In case two nodes connect to each other at once,
                    // the lower ip disconnects its outbound connection
                    // 如果两个节点一次相互连接，高度较低的IP断开其出站连接
                    CNode* pnodeExtra = mapFirst[ip];

                    if (pnodeExtra->GetRefCount() > (pnodeExtra->fNetworkNode ? 1 : 0))
                        swap(pnodeExtra, pnode);

                    if (pnodeExtra->GetRefCount() <= (pnodeExtra->fNetworkNode ? 1 : 0))
                    {
                        printf("(%d nodes) disconnecting duplicate: %s\n", vNodes.size(), pnodeExtra->addr.ToString().c_str());
                        if (pnodeExtra->fNetworkNode && !pnode->fNetworkNode)
                        {
                            pnode->AddRef();
                            swap(pnodeExtra->fNetworkNode, pnode->fNetworkNode);
                            pnodeExtra->Release();
                        }
                        pnodeExtra->fDisconnect = true;
                    }
                }
                mapFirst[ip] = pnode;
            }

            // Disconnect unused nodes
            // 断开未使用的节点
            vector<CNode*> vNodesCopy = vNodes;
            foreach(CNode* pnode, vNodesCopy)
            {
                if (pnode->ReadyToDisconnect() && pnode->vRecv.empty() && pnode->vSend.empty())
                {
                    // remove from vNodes
                    // 从vNode删除
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());
                    pnode->Disconnect();

                    // hold in disconnected pool until all refs are released
                    // 保持在断开连接的池中，直到释放所有引用
                    pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 5 * 60);
                    if (pnode->fNetworkNode)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }

            // Delete disconnected nodes
            // 删除断开连接的节点
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            foreach(CNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                // 等到线程使用完毕
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                     TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                      TRY_CRITICAL_BLOCK(pnode->cs_mapRequests)
                       TRY_CRITICAL_BLOCK(pnode->cs_inventory)
                        fDelete = true;
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            }
        }
        if (vNodes.size() != nPrevNodeCount)
        {
            nPrevNodeCount = vNodes.size();
            MainFrameRepaint();
        }


        //
        // Find which sockets have data to receive
        // 查找哪些套接字有数据要接收
        struct timeval timeout;
        timeout.tv_sec  = 0;
        // 轮询pnode-> vSend的频率
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        struct fd_set fdsetRecv;
        struct fd_set fdsetSend;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        SOCKET hSocketMax = 0;
        FD_SET(hListenSocket, &fdsetRecv);
        hSocketMax = max(hSocketMax, hListenSocket);
        CRITICAL_BLOCK(cs_vNodes)
        {
            foreach(CNode* pnode, vNodes)
            {
                FD_SET(pnode->hSocket, &fdsetRecv);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                    if (!pnode->vSend.empty())
                        FD_SET(pnode->hSocket, &fdsetSend);
            }
        }

        vfThreadRunning[0] = false;
        int nSelect = select(hSocketMax + 1, &fdsetRecv, &fdsetSend, NULL, &timeout);
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        if (nSelect == SOCKET_ERROR)
        {
            int nErr = WSAGetLastError();
            printf("select failed: %d\n", nErr);
            for (int i = 0; i <= hSocketMax; i++)
            {
                FD_SET(i, &fdsetRecv);
                FD_SET(i, &fdsetSend);
            }
            Sleep(timeout.tv_usec/1000);
        }
        RandAddSeed();

        //// debug print
        //foreach(CNode* pnode, vNodes)
        //{
        //    printf("vRecv = %-5d ", pnode->vRecv.size());
        //    printf("vSend = %-5d    ", pnode->vSend.size());
        //}
        //printf("\n");


        //
        // Accept new connections
        // 接受新的连接
        if (FD_ISSET(hListenSocket, &fdsetRecv))
        {
            struct sockaddr_in sockaddr;
            int len = sizeof(sockaddr);
            SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
            CAddress addr(sockaddr);
            if (hSocket == INVALID_SOCKET)
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK)
                    printf("ERROR ThreadSocketHandler accept failed: %d\n", WSAGetLastError());
            }
            else
            {
                printf("accepted connection from %s\n", addr.ToString().c_str());
                CNode* pnode = new CNode(hSocket, addr, true);
                pnode->AddRef();
                CRITICAL_BLOCK(cs_vNodes)
                    vNodes.push_back(pnode);
            }
        }


        //
        // Service each socket
        // 维修每个Socket
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            CheckForShutdown(0);
            SOCKET hSocket = pnode->hSocket;

            //
            // Receive   接收
            //
            if (FD_ISSET(hSocket, &fdsetRecv))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                {
                    CDataStream& vRecv = pnode->vRecv;
                    unsigned int nPos = vRecv.size();

                    // typical socket buffer is 8K-64K
                    // 典型的套接字缓冲区是8K-64K
                    const unsigned int nBufSize = 0x10000;
                    vRecv.resize(nPos + nBufSize);
                    int nBytes = recv(hSocket, &vRecv[nPos], nBufSize, 0);
                    vRecv.resize(nPos + max(nBytes, 0));
                    if (nBytes == 0)
                    {
                        // socket closed gracefully
                        // Socket正常关闭
                        if (!pnode->fDisconnect)
                            printf("recv: socket closed\n");
                        pnode->fDisconnect = true;
                    }
                    else if (nBytes < 0)
                    {
                        // socket error
                        int nErr = WSAGetLastError();
                        if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                        {
                            if (!pnode->fDisconnect)
                                printf("recv failed: %d\n", nErr);
                            pnode->fDisconnect = true;
                        }
                    }
                }
            }

            //
            // Send   发送
            //
            if (FD_ISSET(hSocket, &fdsetSend))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                {
                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(hSocket, &vSend[0], vSend.size(), 0);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                        }
                        else if (nBytes == 0)
                        {
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                        else
                        {
                            printf("send error %d\n", nBytes);
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                    }
                }
            }
        }


        Sleep(10);
    }
}









// 处理打开的连接
void ThreadOpenConnections(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadOpenConnections(parg));

    loop
    {
        vfThreadRunning[1] = true;
        CheckForShutdown(1);
        try
        {
            ThreadOpenConnections2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadOpenConnections()")
        vfThreadRunning[1] = false;
        Sleep(5000);
    }
}

void ThreadOpenConnections2(void* parg)
{
    printf("ThreadOpenConnections started\n");

    // Initiate network connections
    // 启动网络连接
    // 最大15个连接
    const int nMaxConnections = 15;
    loop
    {
        // Wait
        vfThreadRunning[1] = false;
        Sleep(500);
        while (vNodes.size() >= nMaxConnections || vNodes.size() >= mapAddresses.size())
        {
            CheckForShutdown(1);
            Sleep(2000);
        }
        vfThreadRunning[1] = true;
        CheckForShutdown(1);


        // Make a list of unique class C's
        // 列出唯一的C类IP
        unsigned char pchIPCMask[4] = { 0xff, 0xff, 0xff, 0x00 };
        unsigned int nIPCMask = *(unsigned int*)pchIPCMask;
        vector<unsigned int> vIPC;
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            vIPC.reserve(mapAddresses.size());
            unsigned int nPrev = 0;
            foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                const CAddress& addr = item.second;
                // IPv4
                if (!addr.IsIPv4())
                    continue;

                // Taking advantage of mapAddresses being in sorted order,
                // with IPs of the same class C grouped together.
                // 利用mapAddresses的排序顺序，将相同C类的IP分组在一起。
                unsigned int ipC = addr.ip & nIPCMask;
                if (ipC != nPrev)
                    vIPC.push_back(nPrev = ipC);
            }
        }

        //
        // The IP selection process is designed to limit vulnerability to address flooding.
        // Any class C (a.b.c.?) has an equal chance of being chosen, then an IP is
        // chosen within the class C.  An attacker may be able to allocate many IPs, but
        // they would normally be concentrated in blocks of class C's.  They can hog the
        // attention within their class C, but not the whole IP address space overall.
        // A lone node in a class C will get as much attention as someone holding all 255
        // IPs in another class C.
        // IP选择过程旨在限制漏洞来解决泛洪。 任何C类（a.b.c.？）都有相等的机会被选中，然后在C类中选择一个IP。
        // 攻击者可能能够分配许多IP，但通常它们会集中在C类的块中。
        // 他们可以将注意力集中在C类中，而不是整个IP地址空间。
        // 类C中的一个孤独节点将像持有另一个类C中的所有255个IP的人一样受到关注。
        bool fSuccess = false;
        int nLimit = vIPC.size();
        while (!fSuccess && nLimit-- > 0)
        {
            // Choose a random class C
            // 选择一个随机的C类IP
            unsigned int ipC = vIPC[GetRand(vIPC.size())];

            // Organize all addresses in the class C by IP
            // 通过IP组织C类中的所有地址
            map<unsigned int, vector<CAddress> > mapIP;
            CRITICAL_BLOCK(cs_mapAddresses)
            {
                unsigned int nDelay = ((30 * 60) << vNodes.size());
                if (nDelay > 8 * 60 * 60)
                    nDelay = 8 * 60 * 60;
                for (map<vector<unsigned char>, CAddress>::iterator mi = mapAddresses.lower_bound(CAddress(ipC, 0).GetKey());
                     mi != mapAddresses.upper_bound(CAddress(ipC | ~nIPCMask, 0xffff).GetKey());
                     ++mi)
                {
                    const CAddress& addr = (*mi).second;
                    unsigned int nRandomizer = (addr.nLastFailed * addr.ip * 7777U) % 20000;
                    if (GetTime() - addr.nLastFailed > nDelay * nRandomizer / 10000)
                        mapIP[addr.ip].push_back(addr);
                }
            }
            if (mapIP.empty())
                break;

            // Choose a random IP in the class C
            // 在C类中选择一个随机IP
            map<unsigned int, vector<CAddress> >::iterator mi = mapIP.begin();
            advance(mi, GetRand(mapIP.size()));

            // Once we've chosen an IP, we'll try every given port before moving on
            // 一旦选择了IP，我们将尝试每个给定的端口，然后继续操作
            foreach(const CAddress& addrConnect, (*mi).second)
            {
                // 过滤本机
                if (addrConnect.ip == addrLocalHost.ip || !addrConnect.IsIPv4() || FindNode(addrConnect.ip))
                    continue;

                CNode* pnode = ConnectNode(addrConnect);
                if (!pnode)
                    continue;
                pnode->fNetworkNode = true;

                if (addrLocalHost.IsRoutable())
                {
                    // Advertise our address
                    // 刊登我们的地址 把本机的地址发送给其他节点
                    vector<CAddress> vAddrToSend;
                    vAddrToSend.push_back(addrLocalHost);
                    pnode->PushMessage("addr", vAddrToSend);
                }

                // Get as many addresses as we can
                // 获得尽可能多的地址
                pnode->PushMessage("getaddr");

                ////// should the one on the receiving end do this too?
                // Subscribe our local subscription list
                // 订阅我们的本地订阅列表
                const unsigned int nHops = 0;
                for (unsigned int nChannel = 0; nChannel < pnodeLocalHost->vfSubscribe.size(); nChannel++)
                    if (pnodeLocalHost->vfSubscribe[nChannel])
                        pnode->PushMessage("subscribe", nChannel, nHops);

                fSuccess = true;
                break;
            }
        }
    }
}







// 处理信息
void ThreadMessageHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadMessageHandler(parg));

    loop
    {
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
        try
        {
            ThreadMessageHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadMessageHandler()")
        vfThreadRunning[2] = false;
        Sleep(5000);
    }
}

void ThreadMessageHandler2(void* parg)
{
    printf("ThreadMessageHandler started\n");
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    loop
    {
        // Poll the connected nodes for messages
        // Poll the connected nodes for messages
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            pnode->AddRef();

            // Receive messages
            // 接收消息
            TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                ProcessMessages(pnode);

            // Send messages
            // 发送消息
            TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                SendMessages(pnode);

            pnode->Release();
        }

        // Wait and allow messages to bunch up
        // 等待并允许消息堆积
        vfThreadRunning[2] = false;
        Sleep(100);
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
    }
}









//// todo: start one thread per processor, use getenv("NUMBER_OF_PROCESSORS")
// 每个处理器启动一个线程，使用getenv（“ NUMBER_OF_PROCESSORS”）
// 启动挖矿
void ThreadBitcoinMiner(void* parg)
{
    vfThreadRunning[3] = true;
    CheckForShutdown(3);
    try
    {
        bool fRet = BitcoinMiner();
        printf("BitcoinMiner returned %s\n\n\n", fRet ? "true" : "false");
    }
    CATCH_PRINT_EXCEPTION("BitcoinMiner()")
    vfThreadRunning[3] = false;
}










// todo 开始节点 和其他节点建立连接 并传递消息
bool StartNode(string& strError)
{
    strError = "";

    // Sockets startup
    // 开始Socket
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        strError = strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get local host ip
    // 获取本地主机IP
    char pszHostName[255];
    if (gethostname(pszHostName, 255) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    // 获取本机IP地址
    struct hostent* pHostEnt = gethostbyname(pszHostName);
    if (!pHostEnt)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostbyname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    addrLocalHost = CAddress(*(long*)(pHostEnt->h_addr_list[0]),
                             DEFAULT_PORT,
                             nLocalServices);
    printf("addrLocalHost = %s\n", addrLocalHost.ToString().c_str());

    // Create socket for listening for incoming connections
    // 创建套接字以监听传入的连接
    SOCKET hListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Set to nonblocking, incoming connections will also inherit this
    // 设置为非阻塞，传入的连接也将继承此
    u_long nOne = 1;
    if (ioctlsocket(hListenSocket, FIONBIO, &nOne) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (ioctlsocket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound
    // sockaddr_in结构指定要绑定的套接字的地址族，IP地址和端口
    int nRetryLimit = 15;
    struct sockaddr_in sockaddr = addrLocalHost.GetSockAddr();
    if (bind(hListenSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf("Error: Unable to bind to port %s on this computer. The program is probably already running.", addrLocalHost.ToString().c_str());
        else
            strError = strprintf("Error: Unable to bind to port %s on this computer (bind returned error %d)", addrLocalHost.ToString().c_str(), nErr);
        printf("%s\n", strError.c_str());
        return false;
    }
    printf("bound to addrLocalHost = %s\n\n", addrLocalHost.ToString().c_str());

    // Listen for incoming connections
    // 监听传入的连接
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get our external IP address for incoming connections
    // 获取我们用于传入连接的外部IP地址
    if (addrIncoming.ip)
        addrLocalHost.ip = addrIncoming.ip;

    if (GetMyExternalIP(addrLocalHost.ip))
    {
        addrIncoming = addrLocalHost;
        CWalletDB().WriteSetting("addrIncoming", addrIncoming);
    }

    // Get addresses from IRC and advertise ours
    // 从IRC获取地址
    if (_beginthread(ThreadIRCSeed, 0, NULL) == -1)
        printf("Error: _beginthread(ThreadIRCSeed) failed\n");

    //
    // Start threads
    // 开始线程  下面三个函数 和其他节点建立连接 并传递消息
    //
    if (_beginthread(ThreadSocketHandler, 0, new SOCKET(hListenSocket)) == -1)
    {
        strError = "Error: _beginthread(ThreadSocketHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadOpenConnections, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadOpenConnections) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadMessageHandler, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadMessageHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    return true;
}

// 停止节点
bool StopNode()
{
    printf("StopNode()\n");
    fShutdown = true;
    nTransactionsUpdated++;
    while (count(vfThreadRunning.begin(), vfThreadRunning.end(), true))
        Sleep(10);
    Sleep(50);

    // Sockets shutdown
    // 关闭Socket
    WSACleanup();
    return true;
}

void CheckForShutdown(int n)
{
    if (fShutdown)
    {
        if (n != -1)
            vfThreadRunning[n] = false;
        _endthread();
    }
}
