// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "sha.h"





//
// Global state
//

CCriticalSection cs_main;

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex*> mapBlockIndex;
const uint256 hashGenesisBlock("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CDataStream*> mapOrphanTransactions;
multimap<uint256, CDataStream*> mapOrphanTransactionsByPrev;

map<uint256, CWalletTx> mapWallet;
vector<pair<uint256, bool> > vWalletUpdated;
CCriticalSection cs_mapWallet;

map<vector<unsigned char>, CPrivKey> mapKeys;
map<uint160, vector<unsigned char> > mapPubKeys;
CCriticalSection cs_mapKeys;
CKey keyUser;

string strSetDataDir;
int nDropMessagesTest = 0;

// Settings
int fGenerateBitcoins;
int64 nTransactionFee = 0;
CAddress addrIncoming;








//////////////////////////////////////////////////////////////////////////////
//
// mapKeys
//
// 保存key pubKey:privKey   address:pubKey
bool AddKey(const CKey& key)
{
    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys[key.GetPubKey()] = key.GetPrivKey();
        mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
    }
    return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey());
}

vector<unsigned char> GenerateNewKey()
{
    CKey key;
    key.MakeNewKey();
    if (!AddKey(key))
        throw runtime_error("GenerateNewKey() : AddKey failed\n");
    return key.GetPubKey();
}




//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//
// 将未花费添加到钱包
bool AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Inserts only if not already there, returns tx inserted or tx found
        // 不存在则插入，返回插入的tx或找到的tx
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
            wtx.nTimeReceived = GetAdjustedTime();

        //// debug print
        printf("AddToWallet %s  %s\n", wtxIn.GetHash().ToString().substr(0,6).c_str(), fInsertedNew ? "new" : "update");

        if (!fInsertedNew)
        {
            // Merge
            bool fUpdated = false;
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            if (wtxIn.fSpent && wtxIn.fSpent != wtx.fSpent)
            {
                wtx.fSpent = wtxIn.fSpent;
                fUpdated = true;
            }
            if (!fUpdated)
                return true;
        }

        // Write to disk
        if (!wtx.WriteToDisk())
            return false;

        // Notify UI
        // 通知
        vWalletUpdated.push_back(make_pair(hash, fInsertedNew));
    }

    // Refresh UI
    // 刷新桌面显示
    MainFrameRepaint();
    return true;
}

// 将coinbase交易添加到钱包
bool AddToWalletIfMine(const CTransaction& tx, const CBlock* pblock)
{
    if (tx.IsMine() || mapWallet.count(tx.GetHash()))
    {
        CWalletTx wtx(tx);
        // Get merkle branch if transaction was found in a block
        if (pblock)
            wtx.SetMerkleBranch(pblock);
        return AddToWallet(wtx);
    }
    return true;
}

// 从钱包移除
bool EraseFromWallet(uint256 hash)
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        if (mapWallet.erase(hash))
            CWalletDB().EraseTx(hash);
    }
    return true;
}









//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
// 添加孤儿交易

void AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return;
    CDataStream* pvMsg = mapOrphanTransactions[hash] = new CDataStream(vMsg);
    foreach(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
}

// 移除孤儿交易
void EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    foreach(const CTxIn& txin, tx.vin)
    {
        for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(txin.prevout.hash);
             mi != mapOrphanTransactionsByPrev.upper_bound(txin.prevout.hash);)
        {
            if ((*mi).second == pvMsg)
                mapOrphanTransactionsByPrev.erase(mi++);
            else
                mi++;
        }
    }
    delete pvMsg;
    mapOrphanTransactions.erase(hash);
}








//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTxIn::IsMine() const
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                if (prev.vout[prevout.n].IsMine())
                    return true;
        }
    }
    return false;
}

int64 CTxIn::GetDebit() const
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                if (prev.vout[prevout.n].IsMine())
                    return prev.vout[prevout.n].nValue;
        }
    }
    return 0;
}

int64 CWalletTx::GetTxTime() const
{
    if (!fTimeReceivedIsTxTime && hashBlock != 0)
    {
        // If we did not receive the transaction directly, we rely on the block's
        // time to figure out when it happened.  We use the median over a range
        // of blocks to try to filter out inaccurate block times.
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (pindex)
                return pindex->GetMedianTime();
        }
    }
    return nTimeReceived;
}






int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
                return 0;
            if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, true))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}



void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        foreach(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        // This critsect is OK because txdb is already open
        CRITICAL_BLOCK(cs_mapWallet)
        {
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                if (mapWallet.count(hash))
                {
                    tx = mapWallet[hash];
                    foreach(const CMerkleTx& txWalletPrev, mapWallet[hash].vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (!fClient && txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                    foreach(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}










// 接收交易
bool CTransaction::AcceptTransaction(CTxDB& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    // Coinbase is only valid in a block, not as a loose transaction
    // Coinbase在接收区块的时候校验
    if (IsCoinBase())
        return error("AcceptTransaction() : coinbase as individual tx");

    if (!CheckTransaction())
        return error("AcceptTransaction() : CheckTransaction failed");

    // Do we already have it?
    // 是否已经处理过这笔交易
    uint256 hash = GetHash();
    CRITICAL_BLOCK(cs_mapTransactions)
        if (mapTransactions.count(hash))
            return false;
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Check for conflicts with in-memory transactions
    // 检查与内存中事务的冲突
    CTransaction* ptxOld = NULL;
    for (int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Allow replacing with a newer version of the same transaction
            // 允许替换为同一交易的较新版本
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (!IsNewerThan(*ptxOld))
                return false;
            for (int i = 0; i < vin.size(); i++)
            {
                COutPoint outpoint = vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    // Check against previous transactions
    // 再次检查交易输入
    map<uint256, CTxIndex> mapUnused;
    int64 nFees = 0;
    if (fCheckInputs && !ConnectInputs(txdb, mapUnused, CDiskTxPos(1,1,1), 0, nFees, false, false))
    {
        if (pfMissingInputs)
            *pfMissingInputs = true;
        return error("AcceptTransaction() : ConnectInputs failed %s", hash.ToString().substr(0,6).c_str());
    }

    // Store transaction in memory
    // 将交易存储在内存池中
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (ptxOld)
        {
            printf("mapTransaction.erase(%s) replacing with new version\n", ptxOld->GetHash().ToString().c_str());
            mapTransactions.erase(ptxOld->GetHash());
        }
        AddToMemoryPool();
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    // 如果已更新，请从钱包中删除旧的TX
    if (ptxOld)
        EraseFromWallet(ptxOld->GetHash());

    printf("AcceptTransaction(): accepted %s\n", hash.ToString().substr(0,6).c_str());
    return true;
}

// 将交易添加到内存池 不做任何检查
bool CTransaction::AddToMemoryPool()
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call AcceptTransaction to properly check the transaction first.
    // 添加到内存池而不检查任何内容。 不要直接调用此方法，请先调用AcceptTransaction以正确检查事务。
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint256 hash = GetHash();
        mapTransactions[hash] = *this;
        for (int i = 0; i < vin.size(); i++)
            mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}

// 从内存池中删除事务
bool CTransaction::RemoveFromMemoryPool()
{
    // Remove transaction from memory pool
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        foreach(const CTxIn& txin, vin)
            mapNextTx.erase(txin.prevout);
        mapTransactions.erase(GetHash());
        nTransactionsUpdated++;
    }
    return true;
}





// 得到MerkleTree深度
int CMerkleTx::GetDepthInMainChain() const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    // 确保merkle分支连接到此块
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    return pindexBest->nHeight - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return max(0, (COINBASE_MATURITY+20) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptTransaction(CTxDB& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptTransaction(txdb, false);
    }
    else
    {
        return CTransaction::AcceptTransaction(txdb, fCheckInputs);
    }
}


// 是否接受交易
bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        foreach(CMerkleTx& tx, vtxPrev)
        {
            if (!tx.IsCoinBase())
            {
                uint256 hash = tx.GetHash();
                if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptTransaction(txdb, fCheckInputs);
            }
        }
        if (!IsCoinBase())
            return AcceptTransaction(txdb, fCheckInputs);
    }
    return true;
}

//  将尚未存在的钱包交易添加到mapTransactions
void ReacceptWalletTransactions()
{
    // Reaccept any txes of ours that aren't already in a block
    // 接受我们尚未存在的任何TX
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet)
    {
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (!wtx.IsCoinBase() && !txdb.ContainsTx(wtx.GetHash()))
                wtx.AcceptWalletTransaction(txdb, false);
        }
    }
}

// 广播钱包里的交易
void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    foreach(const CMerkleTx& tx, vtxPrev)
    {
        if (!tx.IsCoinBase())
        {
            // 非coinbase交易 并且每包含在txdb中
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx);
        }
    }
    if (!IsCoinBase())
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            printf("Relaying wtx %s\n", hash.ToString().substr(0,6).c_str());
            RelayMessage(CInv(MSG_TX, hash), (CTransaction)*this);
        }
    }
}

// 广播钱包交易
void RelayWalletTransactions()
{
    static int64 nLastTime;
    // 1小时进行一次
    if (GetTime() - nLastTime < 10 * 60)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    // 转播尚未在区块中出现的tx
    printf("RelayWalletTransactions()\n");
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Sort them in chronological order
        // 按时间顺序对它们进行排序
        multimap<unsigned int, CWalletTx*> mapSorted;
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        foreach(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            wtx.RelayWalletTransaction(txdb);
        }
    }
}










//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CBlock::ReadFromDisk(const CBlockIndex* pblockindex, bool fReadTransactions)
{
    return ReadFromDisk(pblockindex->nFile, pblockindex->nBlockPos, fReadTransactions);
}

uint256 GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// coinbase交易的收益 挖矿奖励+手续费
int64 CBlock::GetBlockValue(int64 nFees) const
{
    int64 nSubsidy = 50 * COIN;

    // Subsidy is cut in half every 4 years
    // 挖矿奖励 每4年减半
    nSubsidy >>= (nBestHeight / 210000);

    return nSubsidy + nFees;
}

// 得到挖矿难度 调整挖矿难度值
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast)
{
    // 每两周调整一次挖矿难度
    const unsigned int nTargetTimespan = 14 * 24 * 60 * 60; // two weeks
    // 10min一个区块
    const unsigned int nTargetSpacing = 10 * 60;
    // 2016个区块
    const unsigned int nInterval = nTargetTimespan / nTargetSpacing;

    // Genesis block
    // 创世区块 难度值规定为一个默认值
    if (pindexLast == NULL)
        return bnProofOfWorkLimit.GetCompact();

    // Only change once per interval
    // 判断下一个区块高度是否为2016的整数倍 如果不是 则还是采用上一个区块的难度值
    if ((pindexLast->nHeight+1) % nInterval != 0)
        return pindexLast->nBits;

    // Go back by what we want to be 14 days worth of blocks
    // 往前回退2016个区块
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nInterval-1; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    // 生成最近的2016个区块所用的时间
    unsigned int nActualTimespan = pindexLast->nTime - pindexFirst->nTime;
    printf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
    // 重新规划接下去2016个区块的时间  在1/4～4倍时间范围内 避免过大或过小
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;

    // Retarget
    // 新的难度值= 前一个难度值*接下去2016个块的时间/2周
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    // 如果难度值超纲 则采用系统规定的最大值
    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    /// debug print
    printf("\n\n\nGetNextWorkRequired RETARGET *****\n");
    printf("nTargetTimespan = %d    nActualTimespan = %d\n", nTargetTimespan, nActualTimespan);
    printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
    printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

    return bnNew.GetCompact();
}








// 断开输入
bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    // 放弃先前交易的已用指针
    if (!IsCoinBase())
    {
        foreach(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            txdb.UpdateTxIndex(prevout.hash, txindex);
        }
    }

    // Remove transaction from index
    if (!txdb.EraseTxIndex(*this))
        return error("DisconnectInputs() : EraseTxPos failed");

    return true;
}


/**
 * 检查交易的输入
 *
 * @param txdb
 * @param mapTestPool
 * @param posThisTx
 * @param nHeight 0
 * @param nFees 区块中所有的交易的手续费
 * @param fBlock  false
 * @param fMiner  true 是否为矿工
 * @param nMinFee  单笔交易的手续费
 * @return
 */
bool CTransaction::ConnectInputs(CTxDB& txdb, map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx, int nHeight, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee)
{
    // Take over previous transactions' spent pointers
    // 检查交易输入 coinbase没有交易输入
    if (!IsCoinBase())
    {
        int64 nValueIn = 0; // 交易的输入总和
        // 遍历交易输入
        for (int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            // Read txindex
            CTxIndex txindex;
            bool fFound = true;

            // 获取交易输入的交易索引
            // 如果是矿工 则从mapTestPool获取；否则从库中查询
            if (fMiner && mapTestPool.count(prevout.hash))
            {
                // Get txindex from current proposed changes
                txindex = mapTestPool[prevout.hash];
            }
            else
            {
                // Read txindex from txdb
                fFound = txdb.ReadTxIndex(prevout.hash, txindex);
            }
            if (!fFound && (fBlock || fMiner))
                return fMiner ? false : error("ConnectInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());

            // Read txPrev
            CTransaction txPrev;
            if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
            {
                // Get prev tx from single transactions in memory
                // 从内存中查询交易输入txid对应的交易
                CRITICAL_BLOCK(cs_mapTransactions)
                {
                    if (!mapTransactions.count(prevout.hash))
                        return error("ConnectInputs() : %s mapTransactions prev not found %s", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());
                    txPrev = mapTransactions[prevout.hash];
                }
                if (!fFound)
                    txindex.vSpent.resize(txPrev.vout.size());
            }
            else
            {
                // Get prev tx from disk
                // 从磁盘中查询交易输入txid 对应的交易
                if (!txPrev.ReadFromDisk(txindex.pos))
                    return error("ConnectInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());
            }

            // 检查交易输入 txid + n ，n是否在范围内
            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return error("ConnectInputs() : %s prevout.n out of range %d %d %d", GetHash().ToString().substr(0,6).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size());

            // If prev is coinbase, check that it's matured
            // 如果prev是coinbase，请检查它是否已成熟 是否已经可花费 coinbase交易要等100个确认后才可再花费 120？
            if (txPrev.IsCoinBase())
                for (CBlockIndex* pindex = pindexBest; pindex && nBestHeight - pindex->nHeight < COINBASE_MATURITY-1; pindex = pindex->pprev)
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
                        return error("ConnectInputs() : tried to spend coinbase at depth %d", nBestHeight - pindex->nHeight);

            // Verify signature
            // 验证交易的签名
            if (!VerifySignature(txPrev, *this, i))
                return error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,6).c_str());

            // Check for conflicts
            // 检查交易输入是否已经被花费
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,6).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

            // Mark outpoints as spent
            // 将交易输入标记为已花费
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock)
                txdb.UpdateTxIndex(prevout.hash, txindex);
            else if (fMiner)
                mapTestPool[prevout.hash] = txindex;

            // 累加交易的输入
            nValueIn += txPrev.vout[prevout.n].nValue;
        }

        // Tally transaction fees
        // 交易手续费 交易输入-交易输出
        int64 nTxFee = nValueIn - GetValueOut();
        // 交易输出大于交易输入 不合法
        if (nTxFee < 0)
            return error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,6).c_str());
        // 交易输入 不够
        if (nTxFee < nMinFee)
            return false;
        // 累加所有的交易手续费
        nFees += nTxFee;
    }

    if (fBlock)
    {
        // Add transaction to disk index
        // 如果是Block，将交易信息写进库中
        if (!txdb.AddTxIndex(*this, posThisTx, nHeight))
            return error("ConnectInputs() : AddTxPos failed");
    }
    else if (fMiner)
    {
        // Add transaction to test pool
        // 如果是矿工 将交易信息写进mapTestPool
        mapTestPool[GetHash()] = CTxIndex(CDiskTxPos(1,1,1), vout.size());
    }

    return true;
}


bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    // 接管交易输入的指针
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            // 从内存中的单个事务获取上交易输入
            COutPoint prevout = vin[i].prevout;
            if (!mapTransactions.count(prevout.hash))
                return false;
            CTransaction& txPrev = mapTransactions[prevout.hash];

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return error("ConnectInputs() : VerifySignature failed");

            ///// this is redundant with the mapNextTx stuff, not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.n].nValue;
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}




bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    // 以相反的顺序断开
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    // 更新磁盘上的块索引，而不在内存中进行更改。
    // 提交数据库后，将更改内存索引结构。
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        txdb.WriteBlockIndex(blockindexPrev);
    }

    return true;
}

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    //// issue here: it doesn't know the version
    unsigned int nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK) - 1 + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapUnused;
    int64 nFees = 0;
    foreach(CTransaction& tx, vtx)
    {
        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        if (!tx.ConnectInputs(txdb, mapUnused, posThisTx, pindex->nHeight, nFees, true, false))
            return false;
    }

    if (vtx[0].GetValueOut() > GetBlockValue(nFees))
        return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        txdb.WriteBlockIndex(blockindexPrev);
    }

    // Watch for transactions paying to me
    // 监控支付给我的交易
    foreach(CTransaction& tx, vtx)
        AddToWalletIfMine(tx, this);

    return true;
}


// 重组
bool Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
{
    printf("*** REORGANIZE ***\n");

    // Find the fork
    // 查找分叉
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
    }

    // List of what to disconnect
    // 断开连接的列表
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    //连接的列表
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    // Disconnect shorter branch
    // 断开较短的分支
    vector<CTransaction> vResurrect;
    foreach(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock failed");

        // Queue memory transactions to resurrect
        // 轮询需要恢复的交易
        foreach(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    // 连接最长的分支
    vector<CTransaction> vDelete;
    for (int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
            return error("Reorganize() : ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, pindex))
        {
            // Invalid block, delete the rest of this branch
            // 无效的块，删除该分支的其余部分
            txdb.TxnAbort();
            for (int j = i; j < vConnect.size(); j++)
            {
                CBlockIndex* pindex = vConnect[j];
                pindex->EraseBlockFromDisk();
                txdb.EraseBlockIndex(pindex->GetBlockHash());
                mapBlockIndex.erase(pindex->GetBlockHash());
                delete pindex;
            }
            return error("Reorganize() : ConnectBlock failed");
        }

        // Queue memory transactions to delete
        // 轮询需要删除的交易
        foreach(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Commit now because resurrecting could take some time
    // 立即提交，因为恢复可能需要一些时间
    txdb.TxnCommit();

    // Disconnect shorter branch
    // 断开短的分支
    foreach(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    // 连接长的分支
    foreach(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    // 恢复断开连接分支中的内存交易
    foreach(CTransaction& tx, vResurrect)
        tx.AcceptTransaction(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    // 删除连接分支中的冗余内存交易
    foreach(CTransaction& tx, vDelete)
        tx.RemoveFromMemoryPool();

    return true;
}

// 将新的区块信息写进BlockIndex
bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    // 检查是否重复
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,14).c_str());

    // Construct new block index object
    // 构造新的块索引对象
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    CTxDB txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));

    // New best
    // 新的区块
    if (pindexNew->nHeight > nBestHeight)
    {
        if (pindexGenesisBlock == NULL && hash == hashGenesisBlock)
        {
            pindexGenesisBlock = pindexNew;
            txdb.WriteHashBestChain(hash);
        }
        else if (hashPrevBlock == hashBestChain)
        {
            // Adding to current best branch
            // 添加到当前的最佳分支
            if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
            {
                txdb.TxnAbort();
                pindexNew->EraseBlockFromDisk();
                mapBlockIndex.erase(pindexNew->GetBlockHash());
                delete pindexNew;
                return error("AddToBlockIndex() : ConnectBlock failed");
            }
            txdb.TxnCommit();
            pindexNew->pprev->pnext = pindexNew;

            // Delete redundant memory transactions
            // 删除冗余内存交易
            foreach(CTransaction& tx, vtx)
                tx.RemoveFromMemoryPool();
        }
        else
        {
            // New best branch
            if (!Reorganize(txdb, pindexNew))
            {
                txdb.TxnAbort();
                return error("AddToBlockIndex() : Reorganize failed");
            }
        }

        // New best link
        hashBestChain = hash;
        pindexBest = pindexNew;
        nBestHeight = pindexBest->nHeight;
        nTransactionsUpdated++;
        printf("AddToBlockIndex: new best=%s  height=%d\n", hashBestChain.ToString().substr(0,14).c_str(), nBestHeight);
    }

    txdb.TxnCommit();
    txdb.Close();

    // Relay wallet transactions that haven't gotten in yet
    // 广播本地钱包尚未包含在区块中的交易
    if (pindexNew == pindexBest)
        RelayWalletTransactions();

    MainFrameRepaint();
    return true;
}



// 检查区块
bool CBlock::CheckBlock() const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.
    // 这些检查与上下文无关
    // 可以在保存孤立块之前进行验证。

    // Size limits
    // 区块大小限制 0x02000000
    if (vtx.empty() || vtx.size() > MAX_SIZE || ::GetSerializeSize(*this, SER_DISK) > MAX_SIZE)
        return error("CheckBlock() : size limits failed");

    // Check timestamp
    // 检查时间戳  区块时间戳太远 超多当前两个小时
    if (nTime > GetAdjustedTime() + 2 * 60 * 60)
        return error("CheckBlock() : block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    // 第一笔交易必须是coinbase，其余的一定不能为coinbase交易
    // 第一笔交易必须为coinbase交易
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return error("CheckBlock() : first tx is not coinbase");
    for (int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return error("CheckBlock() : more than one coinbase");

    // Check transactions
    // 遍历交易 检查每笔交易
    foreach(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction())
            return error("CheckBlock() : CheckTransaction failed");

    // Check proof of work matches claimed amount
    // 检查工作量证明是否符合要求
    if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
        return error("CheckBlock() : nBits below minimum work");
    if (GetHash() > CBigNum().SetCompact(nBits).getuint256())
        return error("CheckBlock() : hash doesn't match nBits");

    // Check merkleroot
    // 检查merkleroot 再次重构一遍MerkleTree
    if (hashMerkleRoot != BuildMerkleTree())
        return error("CheckBlock() : hashMerkleRoot mismatch");

    return true;
}

// 接收区块
bool CBlock::AcceptBlock()
{
    // Check for duplicate
    // 检查重复
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    // 得到前一个区块的index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return error("AcceptBlock() : prev block not found");
    CBlockIndex* pindexPrev = (*mi).second;

    // Check timestamp against prev
    // 检查时间戳 当前区块时间戳小于前一个区块的时间戳 不合法
    if (nTime <= pindexPrev->GetMedianTimePast())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check proof of work
    // 根据前一个区块得到当前区块的难度值 进行对比 判断是否一致 检查工作量证明
    if (nBits != GetNextWorkRequired(pindexPrev))
        return error("AcceptBlock() : incorrect proof of work");

    // Write block to history file
    // 将块写入历史文件
    unsigned int nFile;
    unsigned int nBlockPos;
    if (!WriteToDisk(!fClient, nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // 如果当前区块为最新区块  放入列表以提供给其他节点
    if (hashBestChain == hash)
        RelayInventory(CInv(MSG_BLOCK, hash));

    // // Add atoms to user reviews for coins created
    // vector<unsigned char> vchPubKey;
    // if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
    // {
    //     unsigned short nAtom = GetRand(USHRT_MAX - 100) + 100;
    //     vector<unsigned short> vAtoms(1, nAtom);
    //     AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms, true);
    // }

    return true;
}

// 处理区块
bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    // Check for duplicate
    // 检查重复 是否已经处理过
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,14).c_str());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,14).c_str());

    // Preliminary checks
    // 初步检查
    if (!pblock->CheckBlock())
    {
        delete pblock;
        return error("ProcessBlock() : CheckBlock FAILED");
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    // 如果还没有之前的方块，请将其分流到等待区域，直到我们得到为止
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,14).c_str());
        mapOrphanBlocks.insert(make_pair(hash, pblock));
        mapOrphanBlocksByPrev.insert(make_pair(pblock->hashPrevBlock, pblock));

        // Ask this guy to fill in what we're missing
        // 要求这个人填写我们缺少的内容
        if (pfrom)
            pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), GetOrphanRoot(pblock));
        return true;
    }

    // Store to disk
    // 存储到磁盘
    if (!pblock->AcceptBlock())
    {
        delete pblock;
        return error("ProcessBlock() : AcceptBlock FAILED");
    }
    delete pblock;

    // Recursively process any orphan blocks that depended on this one
    // 递归处理任何依赖于此的孤立块
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED\n");
    return true;
}








template<typename Stream>
bool ScanMessageStart(Stream& s)
{
    // Scan ahead to the next pchMessageStart, which should normally be immediately
    // at the file pointer.  Leaves file pointer at end of pchMessageStart.
    s.clear(0);
    short prevmask = s.exceptions(0);
    const char* p = BEGIN(pchMessageStart);
    try
    {
        loop
        {
            char c;
            s.read(&c, 1);
            if (s.fail())
            {
                s.clear(0);
                s.exceptions(prevmask);
                return false;
            }
            if (*p != c)
                p = BEGIN(pchMessageStart);
            if (*p == c)
            {
                if (++p == END(pchMessageStart))
                {
                    s.clear(0);
                    s.exceptions(prevmask);
                    return true;
                }
            }
        }
    }
    catch (...)
    {
        s.clear(0);
        s.exceptions(prevmask);
        return false;
    }
}

string GetAppDir()
{
    string strDir;
    if (!strSetDataDir.empty())
    {
        strDir = strSetDataDir;
    }
    else if (getenv("APPDATA"))
    {
        strDir = strprintf("%s\\Bitcoin", getenv("APPDATA"));
    }
    else if (getenv("USERPROFILE"))
    {
        string strAppData = strprintf("%s\\Application Data", getenv("USERPROFILE"));
        static bool fMkdirDone;
        if (!fMkdirDone)
        {
            fMkdirDone = true;
            _mkdir(strAppData.c_str());
        }
        strDir = strprintf("%s\\Bitcoin", strAppData.c_str());
    }
    else
    {
        return ".";
    }
    static bool fMkdirDone;
    if (!fMkdirDone)
    {
        fMkdirDone = true;
        _mkdir(strDir.c_str());
    }
    return strDir;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if (nFile == -1)
        return NULL;
    FILE* file = fopen(strprintf("%s\\blk%04d.dat", GetAppDir().c_str(), nFile).c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        // FAT32文件大小最大为4GB，fseek和ftell最大为2GB，因此我们必须保持在2GB以下
        if (ftell(file) < 0x7F000000 - MAX_SIZE)
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

// 加载区块索引
bool LoadBlockIndex(bool fAllowNew)
{
    //
    // Load block index
    //
    CTxDB txdb("cr");
    if (!txdb.LoadBlockIndex())
        return false;
    txdb.Close();

    //
    // Init with genesis block
    // 用创始块进行初始化
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;


        // Genesis Block:
        // GetHash()      = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        // hashMerkleRoot = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
        // txNew.vin[0].scriptSig     = 486604799 4 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854
        // txNew.vout[0].nValue       = 5000000000
        // txNew.vout[0].scriptPubKey = 0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704 OP_CHECKSIG
        // block.nVersion = 1
        // block.nTime    = 1231006505
        // block.nBits    = 0x1d00ffff
        // block.nNonce   = 2083236893
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e

        // Genesis block
        char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig     = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((unsigned char*)pszTimestamp, (unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue       = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << CBigNum("0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704") << OP_CHECKSIG;
        CBlock block;
        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nTime    = 1231006505;
        block.nBits    = 0x1d00ffff;
        block.nNonce   = 2083236893;

            //// debug print, delete this later
            printf("%s\n", block.GetHash().ToString().c_str());
            printf("%s\n", block.hashMerkleRoot.ToString().c_str());
            printf("%s\n", hashGenesisBlock.ToString().c_str());
            txNew.vout[0].scriptPubKey.print();
            block.print();
            assert(block.hashMerkleRoot == uint256("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        assert(block.GetHash() == hashGenesisBlock);

        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(!fClient, nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(nFile, nBlockPos))
            return error("LoadBlockIndex() : genesis block not accepted");
    }

    return true;
}


// 打印区块树
void PrintBlockTree()
{
    // precompute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex, true);
        printf("%d (%u,%u) %s  %s  tx %d",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().substr(0,14).c_str(),
            DateTimeStr(block.nTime).c_str(),
            block.vtx.size());

        CRITICAL_BLOCK(cs_mapWallet)
        {
            if (mapWallet.count(block.vtx[0].GetHash()))
            {
                CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
                printf("    mine:  %d  %d  %d", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
            }
        }
        printf("\n");


        // put the main timechain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}










//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:        return mapTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
    case MSG_BLOCK:     return mapBlockIndex.count(inv.hash) || mapOrphanBlocks.count(inv.hash);
    case MSG_REVIEW:    return true;
    case MSG_PRODUCT:   return mapProducts.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}






// 处理从节点传来的消息
bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;
    printf("ProcessMessages(%d bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (x) data
    //

    loop
    {
        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        if (vRecv.end() - pstart < sizeof(CMessageHeader))
        {
            if (vRecv.size() > sizeof(CMessageHeader))
            {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - sizeof(CMessageHeader));
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        CMessageHeader hdr;
        vRecv >> hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            // 倒带并等待消息的其余部分
            ///// need a mechanism to give up waiting for overlong message size error
            printf("MESSAGE-BREAK 2\n");
            vRecv.insert(vRecv.begin(), BEGIN(hdr), END(hdr));
            Sleep(100);
            break;
        }

        // Copy message to its own buffer
        // 将消息复制到其自己的缓冲区
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try
        {
            CheckForShutdown(2);
            CRITICAL_BLOCK(cs_main)
            // 调用函数处理消息
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            CheckForShutdown(2);
        }
        CATCH_PRINT_EXCEPTION("ProcessMessage()")
        if (!fRet)
            printf("ProcessMessage(%s, %d bytes) from %s to %s FAILED\n", strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), addrLocalHost.ToString().c_str());
    }

    vRecv.Compact();
    return true;
}



// 处理收到的信息
bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static map<unsigned int, vector<unsigned char> > mapReuseKey;
    printf("received: %-12s (%d bytes)  ", strCommand.c_str(), vRecv.size());
    for (int i = 0; i < min(vRecv.size(), (unsigned int)25); i++)
        printf("%02x ", vRecv[i] & 0xff);
    printf("\n");
    if (nDropMessagesTest > 0 && GetRand(nDropMessagesTest) == 0)
    {
        printf("dropmessages DROPPING RECV MESSAGE\n");
        return true;
    }


    // version 命令
    if (strCommand == "version")
    {
        // Can only do this once
        if (pfrom->nVersion != 0)
            return false;

        int64 nTime;
        CAddress addrMe;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion == 0)
            return false;

        pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);
        if (pfrom->fClient)
        {
            pfrom->vSend.nType |= SER_BLOCKHEADERONLY;
            pfrom->vRecv.nType |= SER_BLOCKHEADERONLY;
        }

        AddTimeData(pfrom->addr.ip, nTime);

        // Ask the first connected node for block updates
        // 向第一个连接的节点询问块更新
        static bool fAskedForBlocks;
        if (!fAskedForBlocks && !pfrom->fClient)
        {
            fAskedForBlocks = true;
            pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), uint256(0));
        }

        printf("version addrMe = %s\n", addrMe.ToString().c_str());
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        // 必须先有版本消息
        return false;
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Store the new addresses
        // 存储新地址
        CAddrDB addrdb;
        foreach(const CAddress& addr, vAddr)
        {
            if (fShutdown)
                return true;
            if (AddAddress(addrdb, addr))
            {
                // Put on lists to send to other nodes
                // 放入列表以发送到其他节点
                pfrom->setAddrKnown.insert(addr);
                CRITICAL_BLOCK(cs_vNodes)
                    foreach(CNode* pnode, vNodes)
                        if (!pnode->setAddrKnown.count(addr))
                            pnode->vAddrToSend.push_back(addr);
            }
        }
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        CTxDB txdb("r");
        foreach(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave)
                pfrom->AskFor(inv);
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash))
                pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), GetOrphanRoot(mapOrphanBlocks[inv.hash]));
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        foreach(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            printf("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                // 从磁盘发送块
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    //// could optimize this to send header straight from blockindex for client
                    CBlock block;
                    block.ReadFromDisk((*mi).second, !pfrom->fClient);
                    pfrom->PushMessage("block", block);
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                CRITICAL_BLOCK(cs_mapRelay)
                {
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end())
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                }
            }
        }
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the first block the caller has in the main chain
        // 查找调用者在主链中拥有的第一个区块
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        printf("getblocks %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,14).c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,14).c_str());
                break;
            }

            // Bypass setInventoryKnown in case an inventory message got lost
            CRITICAL_BLOCK(pfrom->cs_inventory)
            {
                CInv inv(MSG_BLOCK, pindex->GetBlockHash());
                // returns true if wasn't already contained in the set
                if (pfrom->setInventoryKnown2.insert(inv).second)
                {
                    pfrom->setInventoryKnown.erase(inv);
                    pfrom->vInventoryToSend.push_back(inv);
                }
            }
        }
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        if (tx.AcceptTransaction(true, &fMissingInputs))
        {
            AddToWalletIfMine(tx, NULL);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                     mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                     ++mi)
                {
                    const CDataStream& vMsg = *((*mi).second);
                    CTransaction tx;
                    CDataStream(vMsg) >> tx;
                    CInv inv(MSG_TX, tx.GetHash());

                    if (tx.AcceptTransaction(true))
                    {
                        printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0,6).c_str());
                        AddToWalletIfMine(tx, NULL);
                        RelayMessage(inv, vMsg);
                        mapAlreadyAskedFor.erase(inv);
                        vWorkQueue.push_back(inv.hash);
                    }
                }
            }

            foreach(uint256 hash, vWorkQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            printf("storing orphan tx %s\n", inv.hash.ToString().substr(0,6).c_str());
            AddOrphanTx(vMsg);
        }
    }


    else if (strCommand == "review")
    {
        CDataStream vMsg(vRecv);
        CReview review;
        vRecv >> review;

        CInv inv(MSG_REVIEW, review.GetHash());
        pfrom->AddInventoryKnown(inv);

        if (review.AcceptReview())
        {
            // Relay the original message as-is in case it's a higher version than we know how to parse
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
        }
    }


    else if (strCommand == "block")
    {
        auto_ptr<CBlock> pblock(new CBlock);
        vRecv >> *pblock;

        //// debug print
        printf("received block:\n"); pblock->print();

        CInv inv(MSG_BLOCK, pblock->GetHash());
        pfrom->AddInventoryKnown(inv);

        if (ProcessBlock(pfrom, pblock.release()))
            mapAlreadyAskedFor.erase(inv);
    }


    else if (strCommand == "getaddr")
    {
        pfrom->vAddrToSend.clear();
        //// need to expand the time range if not enough found
        int64 nSince = GetAdjustedTime() - 60 * 60; // in the last hour
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                if (fShutdown)
                    return true;
                const CAddress& addr = item.second;
                if (addr.nTime > nSince)
                    pfrom->vAddrToSend.push_back(addr);
            }
        }
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        CWalletTx order;
        vRecv >> hashReply >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr.ip))
            mapReuseKey[pfrom->addr.ip] = GenerateNewKey();

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "submitorder")
    {
        uint256 hashReply;
        CWalletTx wtxNew;
        vRecv >> hashReply >> wtxNew;

        // Broadcast
        if (!wtxNew.AcceptWalletTransaction())
        {
            pfrom->PushMessage("reply", hashReply, (int)1);
            return error("submitorder AcceptWalletTransaction() failed, returning error 1");
        }
        wtxNew.fTimeReceivedIsTxTime = true;
        AddToWallet(wtxNew);
        wtxNew.RelayWalletTransaction();
        mapReuseKey.erase(pfrom->addr.ip);

        // Send back confirmation
        pfrom->PushMessage("reply", hashReply, (int)0);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        CRITICAL_BLOCK(pfrom->cs_mapRequests)
        {
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else
    {
        // Ignore unknown commands for extensibility
        printf("ProcessMessage(%s) : Ignored unknown message\n", strCommand.c_str());
    }


    if (!vRecv.empty())
        printf("ProcessMessage(%s) : %d extra bytes\n", strCommand.c_str(), vRecv.size());

    return true;
}








// 发送信息给其他节点
bool SendMessages(CNode* pto)
{
    CheckForShutdown(2);
    CRITICAL_BLOCK(cs_main)
    {
        // Don't send anything until we get their version message
        // 在收到他们的版本消息之后才给他们发送东西
        if (pto->nVersion == 0)
            return true;


        //
        // Message: addr
        //
        vector<CAddress> vAddrToSend;
        vAddrToSend.reserve(pto->vAddrToSend.size());
        foreach(const CAddress& addr, pto->vAddrToSend)
            if (!pto->setAddrKnown.count(addr))
                vAddrToSend.push_back(addr);
        pto->vAddrToSend.clear();
        if (!vAddrToSend.empty())
            pto->PushMessage("addr", vAddrToSend);


        //
        // Message: inventory
        //
        vector<CInv> vInventoryToSend;
        CRITICAL_BLOCK(pto->cs_inventory)
        {
            vInventoryToSend.reserve(pto->vInventoryToSend.size());
            foreach(const CInv& inv, pto->vInventoryToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                    vInventoryToSend.push_back(inv);
            }
            pto->vInventoryToSend.clear();
            pto->setInventoryKnown2.clear();
        }
        if (!vInventoryToSend.empty())
            pto->PushMessage("inv", vInventoryToSend);


        //
        // Message: getdata
        //
        vector<CInv> vAskFor;
        int64 nNow = GetTime() * 1000000;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            printf("sending getdata: %s\n", inv.ToString().c_str());
            if (!AlreadyHave(txdb, inv))
                vAskFor.push_back(inv);
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vAskFor.empty())
            pto->PushMessage("getdata", vAskFor);

    }
    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
// 挖矿 将区块哈希进行格式化
//

int FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

using CryptoPP::ByteReverse;
static int detectlittleendian = 1;

// 进行SHA256运算
void BlockSHA256(const void* pin, unsigned int nBlocks, void* pout)
{
    unsigned int* pinput = (unsigned int*)pin;
    unsigned int* pstate = (unsigned int*)pout;

    CryptoPP::SHA256::InitState(pstate);

    if (*(char*)&detectlittleendian != 0)
    {
        for (int n = 0; n < nBlocks; n++)
        {
            unsigned int pbuf[16];
            for (int i = 0; i < 16; i++)
                pbuf[i] = ByteReverse(pinput[n * 16 + i]);
            CryptoPP::SHA256::Transform(pstate, pbuf);
        }
        for (int i = 0; i < 8; i++)
            pstate[i] = ByteReverse(pstate[i]);
    }
    else
    {
        for (int n = 0; n < nBlocks; n++)
            CryptoPP::SHA256::Transform(pstate, pinput + n * 16);
    }
}


// todo 挖矿流程
bool BitcoinMiner()
{
    printf("BitcoinMiner started\n");
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

    // 生成新的公私钥对 保存coinbase的输出 即收益
    CKey key;
    key.MakeNewKey();
    CBigNum bnExtraNonce = 0; // nonce从0开始
    while (fGenerateBitcoins)
    {
        Sleep(50);
        CheckForShutdown(3);
        while (vNodes.empty())
        {
            Sleep(1000);
            CheckForShutdown(3);
        }

        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;
        // 根据上一个区块得到挖矿难度    后面处理区块的时候，会再次计算验证
        unsigned int nBits = GetNextWorkRequired(pindexPrev);


        //
        // Create coinbase tx
        // 构造coinbase交易
        //
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        txNew.vin[0].scriptSig << nBits << ++bnExtraNonce;
        txNew.vout.resize(1);
        // coinbase交易 挖矿+手续费 打到哪个地址
        txNew.vout[0].scriptPubKey << key.GetPubKey() << OP_CHECKSIG;


        //
        // Create new block
        // 创建一个新的区块
        //
        auto_ptr<CBlock> pblock(new CBlock());
        if (!pblock.get())
            return false;

        // Add our coinbase tx as first transaction
        // 将coinbase交易作为第一个交易放到集合中去
        pblock->vtx.push_back(txNew);

        // Collect the latest transactions into the block
        //收集最新的交易 放入区块
        int64 nFees = 0; // 统计打包一个区块 区块里面包含的交易手续费
        CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            CTxDB txdb("r");
            map<uint256, CTxIndex> mapTestPool;
            // 创建和内存池中交易的数量大小相同的集合 保存交易
            vector<char> vfAlreadyAdded(mapTransactions.size());
            bool fFoundSomething = true;
            unsigned int nBlockSize = 0;  // 区块大小
            // nBlockSize < MAX_SIZE/2 规定一个区块里面包含的总交易的大小 0x02000000/2
            // 外层循环是因为是多线程，可能刚开始对应的交易没有怎么多，则在等待交易，进行打包，只等待一轮，如果mapTransactions有很多交易则一起打包
            while (fFoundSomething && nBlockSize < MAX_SIZE/2)
            {
                fFoundSomething = false;
                unsigned int n = 0;
                // 遍历内存池中的每笔交易
                for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi, ++n)
                {
                    // 防止相同的交易放入两遍
                    if (vfAlreadyAdded[n])
                        continue;
                    CTransaction& tx = (*mi).second;
                    // 过滤coinbase交易
                    if (tx.IsCoinBase() || !tx.IsFinal())
                        continue;

                    // Transaction fee requirements, mainly only needed for flood control
                    // Under 10K (about 80 inputs) is free for first 100 transactions
                    // Base rate is 0.01 per KB
                    // 交易的手续费  前100个交易，交易的大小下于10K，则可以免手续费；
                    // 100个交易过后，剩下的交易差不多 0.01btc/KB
                    int64 nMinFee = tx.GetMinFee(pblock->vtx.size() < 100);

                    // 临时创建一个map
                    map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
                    // 判断当前交易的输入是否合法，对应的nFees在ConnectInputs是进行累加的
                    if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1,1,1), 0, nFees, false, true, nMinFee))
                        continue;
                    // 将处理过后的交易 保存到mapTestPool
                    swap(mapTestPool, mapTestPoolTmp);

                    // 保存交易
                    pblock->vtx.push_back(tx);
                    // 累加每笔交易的大小
                    nBlockSize += ::GetSerializeSize(tx, SER_NETWORK);
                    vfAlreadyAdded[n] = true;
                    fFoundSomething = true;
                }
            }
        }
        // 设置区块的难度值
        pblock->nBits = nBits;
        // coinbase的收益 挖矿奖励+交易手续费
        pblock->vtx[0].vout[0].nValue = pblock->GetBlockValue(nFees);
        printf("\n\nRunning BitcoinMiner with %d transactions in block\n", pblock->vtx.size());


        //
        // Prebuild hash buffer
        //
        struct unnamed1
        {
            struct unnamed2
            {
                int nVersion;
                uint256 hashPrevBlock;
                uint256 hashMerkleRoot;
                unsigned int nTime;
                unsigned int nBits;
                unsigned int nNonce;
            }
            block;
            unsigned char pchPadding0[64];
            uint256 hash1;
            unsigned char pchPadding1[64];
        }
        tmp;

        tmp.block.nVersion       = pblock->nVersion;
        tmp.block.hashPrevBlock  = pblock->hashPrevBlock  = (pindexPrev ? pindexPrev->GetBlockHash() : 0);
        // 构建Merkle Tree ，返回MerkleRoot
        tmp.block.hashMerkleRoot = pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        // 区块时间
        tmp.block.nTime          = pblock->nTime          = max((pindexPrev ? pindexPrev->GetMedianTimePast()+1 : 0), GetAdjustedTime());
        tmp.block.nBits          = pblock->nBits          = nBits;
        tmp.block.nNonce         = pblock->nNonce         = 1;

        unsigned int nBlocks0 = FormatHashBlocks(&tmp.block, sizeof(tmp.block));
        unsigned int nBlocks1 = FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));


        //
        // Search
        //
        unsigned int nStart = GetTime();
        // 目标难度
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        uint256 hash;
        loop
        {
            // 进行哈希运算
            BlockSHA256(&tmp.block, nBlocks0, &tmp.hash1);
            BlockSHA256(&tmp.hash1, nBlocks1, &hash);

            // 挖出新的区块； 区块哈希小于目标难度哈希
            if (hash <= hashTarget)
            {
                pblock->nNonce = tmp.block.nNonce;
                assert(hash == pblock->GetHash());

                    //// debug print
                    printf("BitcoinMiner:\n");
                    printf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                    pblock->print();

                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
                CRITICAL_BLOCK(cs_main)
                {
                    // Save key
                    // 挖出新块 保存coinbase的输出的地址信息
                    if (!AddKey(key))
                        return false;
                    key.MakeNewKey();

                    // Process this block the same as if we had received it from another node
                    // 处理此块，就像我们从另一个节点收到它一样
                    // 对挖出的块 进行检查合法性
                    if (!ProcessBlock(NULL, pblock.release()))
                        printf("ERROR in BitcoinMiner, ProcessBlock, block not accepted\n");
                }
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

                Sleep(500);
                break;
            }

            // Update nTime every few seconds
            // 每几秒钟更新一次nTime
            if ((++tmp.block.nNonce & 0x3ffff) == 0)
            {
                CheckForShutdown(3);
                if (tmp.block.nNonce == 0)
                    break;
                if (pindexPrev != pindexBest)
                    break;
                if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (!fGenerateBitcoins)
                    break;
                tmp.block.nTime = pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
            }
        }
    }

    return true;
}


















//////////////////////////////////////////////////////////////////////////////
//
// Actions
//

// 得到所有的可用花费
int64 GetBalance()
{
    int64 nStart, nEnd;
    QueryPerformanceCounter((LARGE_INTEGER*)&nStart);

    int64 nTotal = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || pcoin->fSpent)
                continue;
            nTotal += pcoin->GetCredit();
        }
    }

    QueryPerformanceCounter((LARGE_INTEGER*)&nEnd);
    ///printf(" GetBalance() time = %16I64d\n", nEnd - nStart);
    return nTotal;
}


/**
 *  选择合适的未花费
 *
 * @param nTargetValue  金额
 * @param setCoinsRet   保存可以使用的未花费
 * @return
 */
bool SelectCoins(int64 nTargetValue, set<CWalletTx*>& setCoinsRet)
{
    setCoinsRet.clear();

    // List of values less than target
    int64 nLowestLarger = _I64_MAX;
    CWalletTx* pcoinLowestLarger = NULL;
    vector<pair<int64, CWalletTx*> > vValue;
    int64 nTotalLower = 0;

    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || pcoin->fSpent)
                continue;
            int64 n = pcoin->GetCredit();
            if (n <= 0)
                continue;
            if (n < nTargetValue)
            {
                vValue.push_back(make_pair(n, pcoin));
                nTotalLower += n;
            }
            else if (n == nTargetValue)
            {
                setCoinsRet.insert(pcoin);
                return true;
            }
            else if (n < nLowestLarger)
            {
                nLowestLarger = n;
                pcoinLowestLarger = pcoin;
            }
        }
    }

    if (nTotalLower < nTargetValue)
    {
        if (pcoinLowestLarger == NULL)
            return false;
        setCoinsRet.insert(pcoinLowestLarger);
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend());
    vector<char> vfIncluded;
    vector<char> vfBest(vValue.size(), true);
    int64 nBest = nTotalLower;

    for (int nRep = 0; nRep < 1000 && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    // If the next larger is still closer, return it
    if (pcoinLowestLarger && nLowestLarger - nTargetValue <= nBest - nTargetValue)
        setCoinsRet.insert(pcoinLowestLarger);
    else
    {
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                setCoinsRet.insert(vValue[i].second);

        //// debug print
        printf("SelectCoins() best subset: ");
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                printf("%s ", FormatMoney(vValue[i].first).c_str());
        printf("total %s\n", FormatMoney(nBest).c_str());
    }

    return true;
}



/**
 * 创建交易
 * @param scriptPubKey   锁定脚本
 * @param nValue  金额
 * @param wtxNew  from+to
 * @param nFeeRequiredRet
 * @return
 */
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, int64& nFeeRequiredRet)
{
    nFeeRequiredRet = 0;
    CRITICAL_BLOCK(cs_main)
    {
        // txdb must be opened before the mapWallet lock
        // 必须在mapWallet锁定之前打开txdb
        CTxDB txdb("r");
        CRITICAL_BLOCK(cs_mapWallet)
        {
            // 交易手续费
            int64 nFee = nTransactionFee;
            loop
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                if (nValue < 0)
                    return false;
                int64 nValueOut = nValue;
                nValue += nFee;

                // Choose coins to use
                // 选择可以使用的未花费
                set<CWalletTx*> setCoins;
                if (!SelectCoins(nValue, setCoins))
                    return false;
                int64 nValueIn = 0;
                foreach(CWalletTx* pcoin, setCoins)
                    nValueIn += pcoin->GetCredit();

                // Fill vout[0] to the payee
                // 填充输出
                wtxNew.vout.push_back(CTxOut(nValueOut, scriptPubKey));

                // Fill vout[1] back to self with any change
                // 填充输出 找零地址
                if (nValueIn > nValue)
                {
                    // Use the same key as one of the coins
                    vector<unsigned char> vchPubKey;
                    CTransaction& txFirst = *(*setCoins.begin());
                    foreach(const CTxOut& txout, txFirst.vout)
                        if (txout.IsMine())
                            if (ExtractPubKey(txout.scriptPubKey, true, vchPubKey))
                                break;
                    if (vchPubKey.empty())
                        return false;

                    // Fill vout[1] to ourself
                    // 找零地址
                    CScript scriptPubKey;
                    scriptPubKey << vchPubKey << OP_CHECKSIG;
                    wtxNew.vout.push_back(CTxOut(nValueIn - nValue, scriptPubKey));
                }

                // Fill vin
                // 填充输入
                foreach(CWalletTx* pcoin, setCoins)
                    for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
                        if (pcoin->vout[nOut].IsMine())
                            wtxNew.vin.push_back(CTxIn(pcoin->GetHash(), nOut));

                // Sign
                // 签名每一个输入
                int nIn = 0;
                foreach(CWalletTx* pcoin, setCoins)
                    for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
                        if (pcoin->vout[nOut].IsMine())
                            SignSignature(*pcoin, wtxNew, nIn++);

                // Check that enough fee is included
                // 检查是否包含足够的手续费
                if (nFee < wtxNew.GetMinFee(true))
                {
                    nFee = nFeeRequiredRet = wtxNew.GetMinFee(true);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                // 通过从以前的交易中复制vtxPrev来填充vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

// Call after CreateTransaction unless you want to abort
// 在CreateTransaction之后调用，除非您想中止
// 将交易输入标记为已花费
bool CommitTransactionSpent(const CWalletTx& wtxNew)
{
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        //// todo: make this transactional, never want to add a transaction
        ////  without marking spent transactions

        // Add tx to wallet, because if it has change it's also ours,
        // otherwise just for transaction history.
        // 将tx添加到钱包，因为如果有更改，它也是我们的，否则仅用于交易历史记录。
        AddToWallet(wtxNew);

        // Mark old coins as spent
        // 将旧的未花费标记为已花费
        set<CWalletTx*> setCoins;
        foreach(const CTxIn& txin, wtxNew.vin)
            setCoins.insert(&mapWallet[txin.prevout.hash]);
        foreach(CWalletTx* pcoin, setCoins)
        {
            pcoin->fSpent = true;
            pcoin->WriteToDisk();
            vWalletUpdated.push_back(make_pair(pcoin->GetHash(), false));
        }
    }
    MainFrameRepaint();
    return true;
}



// 转账 发送
bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew)
{
    CRITICAL_BLOCK(cs_main)
    {
        int64 nFeeRequired;
        // 创建交易
        if (!CreateTransaction(scriptPubKey, nValue, wtxNew, nFeeRequired))
        {
            string strError;
            if (nValue + nFeeRequired > GetBalance())
                strError = strprintf("Error: This is an oversized transaction that requires a transaction fee of %s ", FormatMoney(nFeeRequired).c_str());
            else
                strError = "Error: Transaction creation failed ";
            wxMessageBox(strError, "Sending...");
            return error("SendMoney() : %s\n", strError.c_str());
        }
        // 将交易输入标记为已花费
        if (!CommitTransactionSpent(wtxNew))
        {
            wxMessageBox("Error finalizing transaction", "Sending...");
            return error("SendMoney() : Error finalizing transaction");
        }

        printf("SendMoney: %s\n", wtxNew.GetHash().ToString().substr(0,6).c_str());

        // Broadcast
        // 广播交易
        if (!wtxNew.AcceptTransaction())
        {
            // This must not fail. The transaction has already been signed and recorded.
            // 这一定不能失败。 交易已签名并记录。
            throw runtime_error("SendMoney() : wtxNew.AcceptTransaction() failed\n");
            wxMessageBox("Error: Transaction not valid", "Sending...");
            return error("SendMoney() : Error: Transaction not valid");
        }
        wtxNew.RelayWalletTransaction();
    }
    MainFrameRepaint();
    return true;
}
