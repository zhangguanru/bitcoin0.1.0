// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"

bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);



typedef vector<unsigned char> valtype;
static const valtype vchFalse(0);
static const valtype vchZero(0);
static const valtype vchTrue(1, 1);
static const CBigNum bnZero(0);
static const CBigNum bnOne(1);
static const CBigNum bnFalse(0);
static const CBigNum bnTrue(1);


bool CastToBool(const valtype& vch)
{
    return (CBigNum(vch) != bnZero);
}

void MakeSameSize(valtype& vch1, valtype& vch2)
{
    // Lengthen the shorter one
    if (vch1.size() < vch2.size())
        vch1.resize(vch2.size(), 0);
    if (vch2.size() < vch1.size())
        vch2.resize(vch1.size(), 0);
}



//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))

/**
 * 根据脚本验证交易的合法性
 * @param script  解锁脚本+锁定脚本
 * @param txTo    哪笔交易花费
 * @param nIn     花费的交易哪一个输出
 * @param nHashType 交易类型
 * @param pvStackRet
 * @return
 */
bool EvalScript(const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType,
                vector<vector<unsigned char> >* pvStackRet)
{
    CAutoBN_CTX pctx;
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    vector<bool> vfExec;
    vector<valtype> stack;
    vector<valtype> altstack;
    if (pvStackRet)
        pvStackRet->clear();


    // 遍历解锁脚本+锁定脚本组成的操作码集合
    while (pc < pend)
    {
        bool fExec = !count(vfExec.begin(), vfExec.end(), false);

        //
        // Read instruction
        //
        opcodetype opcode;
        valtype vchPushValue;
        if (!script.GetOp(pc, opcode, vchPushValue))
            return false;

        if (fExec && opcode <= OP_PUSHDATA4)
            // 非操作码入栈 如签名信息、公钥
            stack.push_back(vchPushValue);
        else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
        switch (opcode)
        {
            //
            // Push value
            //
            case OP_1NEGATE:
            case OP_1:
            case OP_2:
            case OP_3:
            case OP_4:
            case OP_5:
            case OP_6:
            case OP_7:
            case OP_8:
            case OP_9:
            case OP_10:
            case OP_11:
            case OP_12:
            case OP_13:
            case OP_14:
            case OP_15:
            case OP_16:
            {
                // ( -- value)
                CBigNum bn((int)opcode - (int)(OP_1 - 1));
                stack.push_back(bn.getvch());
            }
            break;


            //
            // Control
            //
            case OP_NOP:
            break;

            case OP_VER:
            {
                CBigNum bn(VERSION);
                stack.push_back(bn.getvch());
            }
            break;

            case OP_IF:
            case OP_NOTIF:
            case OP_VERIF:
            case OP_VERNOTIF:
            {
                // <expression> if [statements] [else [statements]] endif
                bool fValue = false;
                if (fExec)
                {
                    if (stack.size() < 1)
                        return false;
                    valtype& vch = stacktop(-1);
                    if (opcode == OP_VERIF || opcode == OP_VERNOTIF)
                        fValue = (CBigNum(VERSION) >= CBigNum(vch));
                    else
                        fValue = CastToBool(vch);
                    if (opcode == OP_NOTIF || opcode == OP_VERNOTIF)
                        fValue = !fValue;
                    stack.pop_back();
                }
                vfExec.push_back(fValue);
            }
            break;

            case OP_ELSE:
            {
                if (vfExec.empty())
                    return false;
                vfExec.back() = !vfExec.back();
            }
            break;

            case OP_ENDIF:
            {
                if (vfExec.empty())
                    return false;
                vfExec.pop_back();
            }
            break;

            case OP_VERIFY:
            {
                // (true -- ) or
                // (false -- false) and return
                if (stack.size() < 1)
                    return false;
                bool fValue = CastToBool(stacktop(-1));
                if (fValue)
                    stack.pop_back();
                else
                    pc = pend;
            }
            break;

            case OP_RETURN:
            {
                pc = pend;
            }
            break;


            //
            // Stack ops
            //
            case OP_TOALTSTACK:
            {
                if (stack.size() < 1)
                    return false;
                altstack.push_back(stacktop(-1));
                stack.pop_back();
            }
            break;

            case OP_FROMALTSTACK:
            {
                if (altstack.size() < 1)
                    return false;
                stack.push_back(altstacktop(-1));
                altstack.pop_back();
            }
            break;

            case OP_2DROP:
            {
                // (x1 x2 -- )
                stack.pop_back();
                stack.pop_back();
            }
            break;

            case OP_2DUP:
            {
                // (x1 x2 -- x1 x2 x1 x2)
                if (stack.size() < 2)
                    return false;
                valtype vch1 = stacktop(-2);
                valtype vch2 = stacktop(-1);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_3DUP:
            {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                if (stack.size() < 3)
                    return false;
                valtype vch1 = stacktop(-3);
                valtype vch2 = stacktop(-2);
                valtype vch3 = stacktop(-1);
                stack.push_back(vch1);
                stack.push_back(vch2);
                stack.push_back(vch3);
            }
            break;

            case OP_2OVER:
            {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                if (stack.size() < 4)
                    return false;
                valtype vch1 = stacktop(-4);
                valtype vch2 = stacktop(-3);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_2ROT:
            {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                if (stack.size() < 6)
                    return false;
                valtype vch1 = stacktop(-6);
                valtype vch2 = stacktop(-5);
                stack.erase(stack.end()-6, stack.end()-4);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_2SWAP:
            {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                if (stack.size() < 4)
                    return false;
                swap(stacktop(-4), stacktop(-2));
                swap(stacktop(-3), stacktop(-1));
            }
            break;

            case OP_IFDUP:
            {
                // (x - 0 | x x)
                if (stack.size() < 1)
                    return false;
                valtype vch = stacktop(-1);
                if (CastToBool(vch))
                    stack.push_back(vch);
            }
            break;

            case OP_DEPTH:
            {
                // -- stacksize
                CBigNum bn(stack.size());
                stack.push_back(bn.getvch());
            }
            break;

            case OP_DROP:
            {
                // (x -- )
                if (stack.size() < 1)
                    return false;
                stack.pop_back();
            }
            break;

            // 复制栈顶元素
            case OP_DUP:
            {
                // (x -- x x)
                if (stack.size() < 1)
                    return false;
                valtype vch = stacktop(-1);
                stack.push_back(vch);
            }
            break;

            case OP_NIP:
            {
                // (x1 x2 -- x2)
                if (stack.size() < 2)
                    return false;
                stack.erase(stack.end() - 2);
            }
            break;

            case OP_OVER:
            {
                // (x1 x2 -- x1 x2 x1)
                if (stack.size() < 2)
                    return false;
                valtype vch = stacktop(-2);
                stack.push_back(vch);
            }
            break;

            case OP_PICK:
            case OP_ROLL:
            {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                if (stack.size() < 2)
                    return false;
                int n = CBigNum(stacktop(-1)).getint();
                stack.pop_back();
                if (n < 0 || n >= stack.size())
                    return false;
                valtype vch = stacktop(-n-1);
                if (opcode == OP_ROLL)
                    stack.erase(stack.end()-n-1);
                stack.push_back(vch);
            }
            break;

            case OP_ROT:
            {
                // (x1 x2 x3 -- x2 x3 x1)
                //  x2 x1 x3  after first swap
                //  x2 x3 x1  after second swap
                if (stack.size() < 3)
                    return false;
                swap(stacktop(-3), stacktop(-2));
                swap(stacktop(-2), stacktop(-1));
            }
            break;

            // 交换栈顶的两个元素
            case OP_SWAP:
            {
                // (x1 x2 -- x2 x1)
                if (stack.size() < 2)
                    return false;
                swap(stacktop(-2), stacktop(-1));
            }
            break;

            case OP_TUCK:
            {
                // (x1 x2 -- x2 x1 x2)
                if (stack.size() < 2)
                    return false;
                valtype vch = stacktop(-1);
                stack.insert(stack.end()-2, vch);
            }
            break;


            //
            // Splice ops
            //
            case OP_CAT:
            {
                // (x1 x2 -- out)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                stack.pop_back();
            }
            break;

            case OP_SUBSTR:
            {
                // (in begin size -- out)
                if (stack.size() < 3)
                    return false;
                valtype& vch = stacktop(-3);
                int nBegin = CBigNum(stacktop(-2)).getint();
                int nEnd = nBegin + CBigNum(stacktop(-1)).getint();
                if (nBegin < 0 || nEnd < nBegin)
                    return false;
                if (nBegin > vch.size())
                    nBegin = vch.size();
                if (nEnd > vch.size())
                    nEnd = vch.size();
                vch.erase(vch.begin() + nEnd, vch.end());
                vch.erase(vch.begin(), vch.begin() + nBegin);
                stack.pop_back();
                stack.pop_back();
            }
            break;

            case OP_LEFT:
            case OP_RIGHT:
            {
                // (in size -- out)
                if (stack.size() < 2)
                    return false;
                valtype& vch = stacktop(-2);
                int nSize = CBigNum(stacktop(-1)).getint();
                if (nSize < 0)
                    return false;
                if (nSize > vch.size())
                    nSize = vch.size();
                if (opcode == OP_LEFT)
                    vch.erase(vch.begin() + nSize, vch.end());
                else
                    vch.erase(vch.begin(), vch.end() - nSize);
                stack.pop_back();
            }
            break;

            case OP_SIZE:
            {
                // (in -- in size)
                if (stack.size() < 1)
                    return false;
                CBigNum bn(stacktop(-1).size());
                stack.push_back(bn.getvch());
            }
            break;


            //
            // Bitwise logic
            //
            case OP_INVERT:
            {
                // (in - out)
                if (stack.size() < 1)
                    return false;
                valtype& vch = stacktop(-1);
                for (int i = 0; i < vch.size(); i++)
                    vch[i] = ~vch[i];
            }
            break;

            case OP_AND:
            case OP_OR:
            case OP_XOR:
            {
                // (x1 x2 - out)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                MakeSameSize(vch1, vch2);
                if (opcode == OP_AND)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] &= vch2[i];
                }
                else if (opcode == OP_OR)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] |= vch2[i];
                }
                else if (opcode == OP_XOR)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] ^= vch2[i];
                }
                stack.pop_back();
            }
            break;

            // 判断栈顶两个元素是否相等
            case OP_EQUAL:
            case OP_EQUALVERIFY:
            //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
            {
                // (x1 x2 - bool)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                bool fEqual = (vch1 == vch2);
                // OP_NOTEQUAL is disabled because it would be too easy to say
                // something like n != 1 and have some wiseguy pass in 1 with extra
                // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                //if (opcode == OP_NOTEQUAL)
                //    fEqual = !fEqual;
                stack.pop_back();
                stack.pop_back();
                stack.push_back(fEqual ? vchTrue : vchFalse);
                if (opcode == OP_EQUALVERIFY)
                {
                    if (fEqual)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;


            //
            // Numeric
            //
            case OP_1ADD:
            case OP_1SUB:
            case OP_2MUL:
            case OP_2DIV:
            case OP_NEGATE:
            case OP_ABS:
            case OP_NOT:
            case OP_0NOTEQUAL:
            {
                // (in -- out)
                if (stack.size() < 1)
                    return false;
                CBigNum bn(stacktop(-1));
                switch (opcode)
                {
                case OP_1ADD:       bn += bnOne; break;
                case OP_1SUB:       bn -= bnOne; break;
                case OP_2MUL:       bn <<= 1; break;
                case OP_2DIV:       bn >>= 1; break;
                case OP_NEGATE:     bn = -bn; break;
                case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                case OP_NOT:        bn = (bn == bnZero); break;
                case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                }
                stack.pop_back();
                stack.push_back(bn.getvch());
            }
            break;

            case OP_ADD:
            case OP_SUB:
            case OP_MUL:
            case OP_DIV:
            case OP_MOD:
            case OP_LSHIFT:
            case OP_RSHIFT:
            case OP_BOOLAND:
            case OP_BOOLOR:
            case OP_NUMEQUAL:
            case OP_NUMEQUALVERIFY:
            case OP_NUMNOTEQUAL:
            case OP_LESSTHAN:
            case OP_GREATERTHAN:
            case OP_LESSTHANOREQUAL:
            case OP_GREATERTHANOREQUAL:
            case OP_MIN:
            case OP_MAX:
            {
                // (x1 x2 -- out)
                if (stack.size() < 2)
                    return false;
                CBigNum bn1(stacktop(-2));
                CBigNum bn2(stacktop(-1));
                CBigNum bn;
                switch (opcode)
                {
                case OP_ADD:
                    bn = bn1 + bn2;
                    break;

                case OP_SUB:
                    bn = bn1 - bn2;
                    break;

                case OP_MUL:
                    if (!BN_mul(&bn, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_DIV:
                    if (!BN_div(&bn, NULL, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_MOD:
                    if (!BN_mod(&bn, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_LSHIFT:
                    if (bn2 < bnZero)
                        return false;
                    bn = bn1 << bn2.getulong();
                    break;

                case OP_RSHIFT:
                    if (bn2 < bnZero)
                        return false;
                    bn = bn1 >> bn2.getulong();
                    break;

                case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                }
                stack.pop_back();
                stack.pop_back();
                stack.push_back(bn.getvch());

                if (opcode == OP_NUMEQUALVERIFY)
                {
                    if (CastToBool(stacktop(-1)))
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            case OP_WITHIN:
            {
                // (x min max -- out)
                if (stack.size() < 3)
                    return false;
                CBigNum bn1(stacktop(-3));
                CBigNum bn2(stacktop(-2));
                CBigNum bn3(stacktop(-1));
                bool fValue = (bn2 <= bn1 && bn1 < bn3);
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.push_back(fValue ? vchTrue : vchFalse);
            }
            break;


            //
            // Crypto
            // 脚本中的加码函数
            //
            case OP_RIPEMD160:
            case OP_SHA1:
            case OP_SHA256:
            case OP_HASH160:
            case OP_HASH256:
            {
                // (in -- hash)
                if (stack.size() < 1)
                    return false;
                valtype& vch = stacktop(-1);
                valtype vchHash(opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160 ? 20 : 32);
                if (opcode == OP_RIPEMD160)
                    RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_SHA1)
                    SHA1(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_SHA256)
                    SHA256(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_HASH160)
                {
                    uint160 hash160 = Hash160(vch);
                    memcpy(&vchHash[0], &hash160, sizeof(hash160));
                }
                else if (opcode == OP_HASH256)
                {
                    uint256 hash = Hash(vch.begin(), vch.end());
                    memcpy(&vchHash[0], &hash, sizeof(hash));
                }
                stack.pop_back();
                stack.push_back(vchHash);
            }
            break;

            case OP_CODESEPARATOR:
            {
                // Hash starts after the code separator
                pbegincodehash = pc;
            }
            break;

            // 用公钥验证签名
            case OP_CHECKSIG:
            case OP_CHECKSIGVERIFY:
            {
                // (sig pubkey -- bool)
                if (stack.size() < 2)
                    return false;

                valtype& vchSig    = stacktop(-2); // 签名
                valtype& vchPubKey = stacktop(-1); // 公钥

                ////// debug print
                //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
                //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");

                // Subset of script starting at the most recent codeseparator
                CScript scriptCode(pbegincodehash, pend);

                // Drop the signature, since there's no way for a signature to sign itself
                scriptCode.FindAndDelete(CScript(vchSig));

                // 调用签名函数 用公钥验证签名信息
                bool fSuccess = CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType);

                stack.pop_back();
                stack.pop_back();
                // 公钥能否验证签名 将结果入栈
                stack.push_back(fSuccess ? vchTrue : vchFalse);
                if (opcode == OP_CHECKSIGVERIFY)
                {
                    if (fSuccess)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            // 多重签名
            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY:
            {
                // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                int i = 1;
                if (stack.size() < i)
                    return false;

                int nKeysCount = CBigNum(stacktop(-i)).getint();
                if (nKeysCount < 0)
                    return false;
                int ikey = ++i;
                i += nKeysCount;
                if (stack.size() < i)
                    return false;

                int nSigsCount = CBigNum(stacktop(-i)).getint();
                if (nSigsCount < 0 || nSigsCount > nKeysCount)
                    return false;
                int isig = ++i;
                i += nSigsCount;
                if (stack.size() < i)
                    return false;

                // Subset of script starting at the most recent codeseparator
                CScript scriptCode(pbegincodehash, pend);

                // Drop the signatures, since there's no way for a signature to sign itself
                for (int i = 0; i < nSigsCount; i++)
                {
                    valtype& vchSig = stacktop(-isig-i);
                    scriptCode.FindAndDelete(CScript(vchSig));
                }

                bool fSuccess = true;
                while (fSuccess && nSigsCount > 0)
                {
                    valtype& vchSig    = stacktop(-isig);
                    valtype& vchPubKey = stacktop(-ikey);

                    // Check signature
                    if (CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType))
                    {
                        isig++;
                        nSigsCount--;
                    }
                    ikey++;
                    nKeysCount--;

                    // If there are more signatures left than keys left,
                    // then too many signatures have failed
                    if (nSigsCount > nKeysCount)
                        fSuccess = false;
                }

                while (i-- > 0)
                    stack.pop_back();
                stack.push_back(fSuccess ? vchTrue : vchFalse);

                if (opcode == OP_CHECKMULTISIGVERIFY)
                {
                    if (fSuccess)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            default:
                return false;
        }
    }


    if (pvStackRet)
        *pvStackRet = stack;
    return (stack.empty() ? false : CastToBool(stack.back()));
}

#undef top








/**
 *
 * @param scriptCode
 * @param txTo
 * @param nIn
 * @param nHashType
 * @return
 */
uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    // nIn 为第几个交易输入 不能大于总的交易个数
    if (nIn >= txTo.vin.size())
    {
        printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }
    CTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    // 如果连接两个脚本以两个代码分隔符结束，
    // 或最后加一个，这样可以防止所有可能的不兼容。
    scriptCode.FindAndDelete(CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    // 清空其他输入的签名
    for (int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Blank out some of the outputs
    // 清空一些输出
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // Wildcard payee
        // 通配符收款人 任何人都可以花费这笔交易
        txTmp.vout.clear();

        // Let the others update at will
        // 让其他随意更新
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lockin the txout payee at same index as txin
        // 仅将txout收款人锁定在与txin相同的索引处
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            printf("ERROR: SignatureHash() : nOut=%d out of range\n", nOut);
            return 1;
        }
        txTmp.vout.resize(nOut+1);
        for (int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        //  让其他随意更新
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely, not recommended for open transactions
    // 完全清空其他输入，不建议用于开放的交易
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize and hash
    CDataStream ss(SER_GETHASH);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    return Hash(ss.begin(), ss.end());
}

/**
 * 用公钥验证签名是否正确
 *
 * @param vchSig    签名信息
 * @param vchPubKey   公钥
 * @param scriptCode
 * @param txTo
 * @param nIn
 * @param nHashType 交易类型
 * @return
 */
bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode,
              const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    // 公钥是否合法
    CKey key;
    if (!key.SetPubKey(vchPubKey))
        return false;

    // Hash type is one byte tacked on to the end of the signature
    // 交易类型 是附属在签名后面 eg. 签名后的串[ALL]公钥
    if (vchSig.empty())
        return false;
    if (nHashType == 0)
        nHashType = vchSig.back();  // ALL
    else if (nHashType != vchSig.back())
        return false;
    vchSig.pop_back(); // 将ALL 从栈弹出

    if (key.Verify(SignatureHash(scriptCode, txTo, nIn, nHashType), vchSig))
        return true;

    return false;
}











bool Solver(const CScript& scriptPubKey, vector<pair<opcodetype, valtype> >& vSolutionRet)
{
    // Templates
    static vector<CScript> vTemplates;
    if (vTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        vTemplates.push_back(CScript() << OP_PUBKEY << OP_CHECKSIG);

        // Short account number tx, sender provides hash of pubkey, receiver provides signature and pubkey
        vTemplates.push_back(CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG);
    }

    // Scan templates
    const CScript& script1 = scriptPubKey;
    foreach(const CScript& script2, vTemplates)
    {
        vSolutionRet.clear();
        opcodetype opcode1, opcode2;
        vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        loop
        {
            bool f1 = script1.GetOp(pc1, opcode1, vch1);
            bool f2 = script2.GetOp(pc2, opcode2, vch2);
            if (!f1 && !f2)
            {
                // Success
                reverse(vSolutionRet.begin(), vSolutionRet.end());
                return true;
            }
            else if (f1 != f2)
            {
                break;
            }
            else if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() <= sizeof(uint256))
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));
            }
            else if (opcode1 != opcode2)
            {
                break;
            }
        }
    }

    vSolutionRet.clear();
    return false;
}


bool Solver(const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet)
{
    scriptSigRet.clear();

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    // Compile solution
    CRITICAL_BLOCK(cs_mapKeys)
    {
        foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
        {
            if (item.first == OP_PUBKEY)
            {
                // Sign
                const valtype& vchPubKey = item.second;
                if (!mapKeys.count(vchPubKey))
                    return false;
                if (hash != 0)
                {
                    vector<unsigned char> vchSig;
                    if (!CKey::Sign(mapKeys[vchPubKey], hash, vchSig))
                        return false;
                    vchSig.push_back((unsigned char)nHashType);
                    scriptSigRet << vchSig;
                }
            }
            else if (item.first == OP_PUBKEYHASH)
            {
                // Sign and give pubkey
                map<uint160, valtype>::iterator mi = mapPubKeys.find(uint160(item.second));
                if (mi == mapPubKeys.end())
                    return false;
                const vector<unsigned char>& vchPubKey = (*mi).second;
                if (!mapKeys.count(vchPubKey))
                    return false;
                if (hash != 0)
                {
                    vector<unsigned char> vchSig;
                    if (!CKey::Sign(mapKeys[vchPubKey], hash, vchSig))
                        return false;
                    vchSig.push_back((unsigned char)nHashType);
                    scriptSigRet << vchSig << vchPubKey;
                }
            }
        }
    }

    return true;
}


bool IsMine(const CScript& scriptPubKey)
{
    CScript scriptSig;
    return Solver(scriptPubKey, 0, 0, scriptSig);
}


// 提取PubKey
bool ExtractPubKey(const CScript& scriptPubKey, bool fMineOnly, vector<unsigned char>& vchPubKeyRet)
{
    vchPubKeyRet.clear();

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    CRITICAL_BLOCK(cs_mapKeys)
    {
        foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
        {
            valtype vchPubKey;
            if (item.first == OP_PUBKEY)
            {
                vchPubKey = item.second;
            }
            else if (item.first == OP_PUBKEYHASH)
            {
                map<uint160, valtype>::iterator mi = mapPubKeys.find(uint160(item.second));
                if (mi == mapPubKeys.end())
                    continue;
                vchPubKey = (*mi).second;
            }
            if (!fMineOnly || mapKeys.count(vchPubKey))
            {
                vchPubKeyRet = vchPubKey;
                return true;
            }
        }
    }
    return false;
}


bool ExtractHash160(const CScript& scriptPubKey, uint160& hash160Ret)
{
    hash160Ret = 0;

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
    {
        if (item.first == OP_PUBKEYHASH)
        {
            hash160Ret = uint160(item.second);
            return true;
        }
    }
    return false;
}


bool SignSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType, CScript scriptPrereq)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    uint256 hash = SignatureHash(scriptPrereq + txout.scriptPubKey, txTo, nIn, nHashType);

    if (!Solver(txout.scriptPubKey, hash, nHashType, txin.scriptSig))
        return false;

    txin.scriptSig = scriptPrereq + txin.scriptSig;

    // Test solution
    if (scriptPrereq.empty())
        if (!EvalScript(txin.scriptSig + CScript(OP_CODESEPARATOR) + txout.scriptPubKey, txTo, nIn))
            return false;

    return true;
}

/**
 * 验证签名是否正确
 *
 * @param txFrom  花费的哪笔交易
 * @param txTo    在哪笔交易中被花费
 * @param nIn     交易的第几个输出被花费
 * @param nHashType 交易类型
 * @return
 */
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    // 检查nIn是否合法
    assert(nIn < txTo.vin.size());
    // 交易的第几个输入
    const CTxIn& txin = txTo.vin[nIn];
    // 交易输入txid对应的n如果大于txid的输出数 非法
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    // 第几个交易输出
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // 判断交易输入 是否花费的对应的交易
    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    // 用脚本验证交易是否合法 解锁脚本+锁定脚本
    return EvalScript(txin.scriptSig + CScript(OP_CODESEPARATOR) + txout.scriptPubKey, txTo, nIn, nHashType);
}
