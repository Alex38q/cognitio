#include "masternode.h"
#include "masternodeman.h"
#include "masternode-sync.h"
#include "darksend.h"
#include "core.h"
#include "main.h"
#include "sync.h"
#include "util.h"
#include "addrman.h"
#include <boost/lexical_cast.hpp>


CCriticalSection cs_masternodes;
// keep track of the scanning errors I've seen
map<uint256, int> mapSeenMasternodeScanningErrors;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;


struct CompareValueOnly
{
    bool operator()(const pair<int64_t, CTxIn>& t1,
                    const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

//Get the last hash that matches the modulus given. Processed in reverse order
bool GetBlockHash(uint256& hash, int nBlockHeight)
{
    if (pindexBest == NULL) return false;

    if(nBlockHeight == 0)
        nBlockHeight = pindexBest->nHeight;

    if(mapCacheBlockHashes.count(nBlockHeight)){
        hash = mapCacheBlockHashes[nBlockHeight];
        return true;
    }

    const CBlockIndex *BlockLastSolved = pindexBest;
    const CBlockIndex *BlockReading = pindexBest;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || pindexBest->nHeight+1 < nBlockHeight) return false;

    int nBlocksAgo = 0;
    if(nBlockHeight > 0) nBlocksAgo = (pindexBest->nHeight+1)-nBlockHeight;
    assert(nBlocksAgo >= 0);

    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if(n >= nBlocksAgo){
            hash = BlockReading->GetBlockHash();
            mapCacheBlockHashes[nBlockHeight] = hash;
            return true;
        }
        n++;

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    return false;
}

CMasternode::CMasternode()
{
    LOCK(cs);
    vin = CTxIn();
    addr = CService();
    pubkey = CPubKey();
    pubkey2 = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = MASTERNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastDseep = 0;
    lastTimeSeen = 0;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = MIN_PEER_PROTO_VERSION;
    nLastDsq = 0;
    donationAddress = CScript();
    donationPercentage = 0;
    nVote = 0;
    lastVote = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    //mark last paid as current for new entries
    nLastPaid = GetAdjustedTime();
    lastTimeChecked = 0;
}

CMasternode::CMasternode(const CMasternode& other)
{
    LOCK(cs);
    vin = other.vin;
    addr = other.addr;
    pubkey = other.pubkey;
    pubkey2 = other.pubkey2;
    sig = other.sig;
    activeState = other.activeState;
    sigTime = other.sigTime;
    lastDseep = other.lastDseep;
    lastTimeSeen = other.lastTimeSeen;
    cacheInputAge = other.cacheInputAge;
    cacheInputAgeBlock = other.cacheInputAgeBlock;
    unitTest = other.unitTest;
    allowFreeTx = other.allowFreeTx;
    protocolVersion = other.protocolVersion;
    nLastDsq = other.nLastDsq;
    donationAddress = other.donationAddress;
    donationPercentage = other.donationPercentage;
    nVote = other.nVote;
    lastVote = other.lastVote;
    nScanningErrorCount = other.nScanningErrorCount;
    nLastScanningErrorBlockHeight = other.nLastScanningErrorBlockHeight;
    nLastPaid = other.nLastPaid;
    nLastPaid = GetAdjustedTime();
    lastTimeChecked = 0;
}

CMasternode::CMasternode(const CMasternodeBroadcast& mnb)
{
    LOCK(cs);
    vin = mnb.vin;
    addr = mnb.addr;
    pubkey = mnb.pubkey;
    pubkey2 = mnb.pubkey2;
    sig = mnb.sig;
    activeState = mnb.activeState;
    sigTime = mnb.sigTime;
    lastDseep = mnb.lastDseep;
    lastTimeSeen = mnb.lastTimeSeen;
    cacheInputAge = mnb.cacheInputAge;
    cacheInputAgeBlock = mnb.cacheInputAgeBlock;
    unitTest = mnb.unitTest;
    allowFreeTx = mnb.allowFreeTx;
    protocolVersion = mnb.protocolVersion;
    nLastDsq = mnb.nLastDsq;
    donationAddress = mnb.donationAddress;
    donationPercentage = mnb.donationPercentage;
    nVote = mnb.nVote;
    lastVote = mnb.lastVote;
    nScanningErrorCount = mnb.nScanningErrorCount;
    nLastScanningErrorBlockHeight = mnb.nLastScanningErrorBlockHeight;
    nLastPaid = mnb.nLastPaid;
    nLastPaid = GetAdjustedTime();
    lastTimeChecked = 0;
}

CMasternode::CMasternode(CService newAddr, CTxIn newVin, CPubKey newPubkey, std::vector<unsigned char> newSig, int64_t newSigTime, CPubKey newPubkey2, int protocolVersionIn, CScript newDonationAddress, int newDonationPercentage)
{
    LOCK(cs);
    vin = newVin;
    addr = newAddr;
    pubkey = newPubkey;
    pubkey2 = newPubkey2;
    sig = newSig;
    activeState = MASTERNODE_ENABLED;
    sigTime = newSigTime;
    lastDseep = 0;
    lastTimeSeen = 0;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = protocolVersionIn;
    nLastDsq = 0;
    donationAddress = newDonationAddress;
    donationPercentage = newDonationPercentage;
    nVote = 0;
    lastVote = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
}

//
// When a new masternode broadcast is sent, update our information
//
bool CMasternode::UpdateFromNewBroadcast(CMasternodeBroadcast& mnb)
{
    if (mnb.sigTime > sigTime) {
        pubkey2 = mnb.pubkey2;
        pubkey = mnb.pubkey;
        sigTime = mnb.sigTime;
        sig = mnb.sig;
        protocolVersion = mnb.protocolVersion;
        addr = mnb.addr;
        lastTimeChecked = 0;
        int nDoS = 0;
        if (mnb.lastPing == CMasternodePing() || (mnb.lastPing != CMasternodePing() && mnb.lastPing.CheckAndUpdate(nDoS, false))) {
            lastPing = mnb.lastPing;
            mnodeman.mapSeenMasternodePing.insert(make_pair(lastPing.GetHash(), lastPing));
        }
        return true;
    }
    return false;
}

//
// Deterministically calculate a given "score" for a masternode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 CMasternode::CalculateScore(int mod, int64_t nBlockHeight)
{
    if(pindexBest == NULL) return 0;

    uint256 hash = 0;
    uint256 aux = vin.prevout.hash + vin.prevout.n;

    if(!GetBlockHash(hash, nBlockHeight)) return 0;

    uint256 hash2 = Hash(BEGIN(hash), END(hash));
    uint256 hash3 = Hash(BEGIN(hash), END(hash), BEGIN(aux), END(aux));

    uint256 r = (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);

    return r;
}

void CMasternode::Check(bool forceCheck)
{
    if(ShutdownRequested()) return;

    if (!forceCheck && (GetTime() - lastTimeChecked < MASTERNODE_CHECK_SECONDS)) return;
    lastTimeChecked = GetTime();

    //TODO: Random segfault with this line removed
    TRY_LOCK(cs_main, lockRecv);
    if(!lockRecv) return;

    //once spent, stop doing the checks
    if(activeState == MASTERNODE_VIN_SPENT) return;


    if(!UpdatedWithin(MASTERNODE_REMOVAL_SECONDS)){
        activeState = MASTERNODE_REMOVE;
        return;
    }

    if(!UpdatedWithin(MASTERNODE_EXPIRATION_SECONDS)){
        activeState = MASTERNODE_EXPIRED;
        return;
    }

    if(!unitTest){
        CValidationState state;
        CTransaction tx = CTransaction();
        CTxOut vout = CTxOut(DARKSEND_POOL_MAX, darkSendPool.collateralPubKey);
        tx.vin.push_back(vin);
        tx.vout.push_back(vout);

	if(!AcceptableInputs(mempool, tx, false, NULL)){
            activeState = MASTERNODE_VIN_SPENT;
            return;
        }
    }

    activeState = MASTERNODE_ENABLED; // OK
}

bool CMasternode::IsValidNetAddr()
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkID() == Params().Network::REGTEST ||
           (IsReachable(addr) && addr.IsRoutable());
}

CMasternodeBroadcast::CMasternodeBroadcast()
{
    vin = CTxIn();
    addr = CService();
    pubkey = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = MASTERNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CMasternodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = PROTOCOL_VERSION;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

CMasternodeBroadcast::CMasternodeBroadcast(CService newAddr, CTxIn newVin, CPubKey pubkeyNew, CPubKey pubkey2New, int protocolVersionIn)
{
    vin = newVin;
    addr = newAddr;
    pubkey = pubkeyNew;
    pubkey2 = pubkey2New;
    sig = std::vector<unsigned char>();
    activeState = MASTERNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CMasternodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = protocolVersionIn;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

CMasternodeBroadcast::CMasternodeBroadcast(const CMasternode& mn)
{
    vin = mn.vin;
    addr = mn.addr;
    pubkey = mn.pubkey;
    pubkey2 = mn.pubkey2;
    sig = mn.sig;
    activeState = mn.activeState;
    sigTime = mn.sigTime;
    lastPing = mn.lastPing;
    cacheInputAge = mn.cacheInputAge;
    cacheInputAgeBlock = mn.cacheInputAgeBlock;
    unitTest = mn.unitTest;
    allowFreeTx = mn.allowFreeTx;
    protocolVersion = mn.protocolVersion;
    nLastDsq = mn.nLastDsq;
    nScanningErrorCount = mn.nScanningErrorCount;
    nLastScanningErrorBlockHeight = mn.nLastScanningErrorBlockHeight;
}

bool CMasternodeBroadcast::Create(std::string strService, std::string strKeyMasternode, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CMasternodeBroadcast& mnbRet, bool fOffline)
{
    CTxIn txin;
    CPubKey pubkeyNew;
    CKey keyCollateralAddressNew;
    CPubKey pubkey2New;
    CKey keyMasternodeNew;

    //need correct blocks to send ping
    if (!fOffline && !masternodeSync.IsBlockchainSynced()) {
        strErrorRet = "Sync in progress. Must wait until sync is complete to start Masternode";
        LogPrint("masternode","CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!darkSendSigner.SetKey(strKeyMasternode, strErrorRet, keyMasternodeNew, pubkey2New)) {
        LogPrint("masternode","CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!pwalletMain->GetMasternodeVinAndKeys(txin, pubkeyNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
        strErrorRet = strprintf("Could not allocate txin %s:%s for masternode %s", strTxHash, strOutputIndex, strService);
        LogPrint("masternode","CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    // The service needs the correct default port to work properly
    if(!CheckDefaultPort(strService, strErrorRet, "CMasternodeBroadcast::Create"))
        return false;

    return Create(txin, CService(strService), keyCollateralAddressNew, pubkeyNew, keyMasternodeNew, pubkey2New, strErrorRet, mnbRet);
}

bool CMasternodeBroadcast::Create(CTxIn txin, CService service, CKey keyCollateralAddressNew, CPubKey pubkeyNew, CKey keyMasternodeNew, CPubKey pubkey2New, std::string& strErrorRet, CMasternodeBroadcast& mnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint("masternode", "CMasternodeBroadcast::Create -- pubkeyNew = %s, pubkey2New.GetID() = %s\n",
        EncodeDestination(CTxDestination(pubkeyNew.GetID())),
        pubkey2New.GetID().ToString());

    CMasternodePing mnp(txin);
    if (!mnp.Sign(keyMasternodeNew, pubkey2New)) {
        strErrorRet = strprintf("Failed to sign ping, masternode=%s", txin.prevout.hash.ToString());
        LogPrint("masternode","CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CMasternodeBroadcast();
        return false;
    }

    mnbRet = CMasternodeBroadcast(service, txin, pubkeyNew, pubkey2New, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr()) {
        strErrorRet = strprintf("Invalid IP address %s, masternode=%s", mnbRet.addr.ToStringIP (), txin.prevout.hash.ToString());
        LogPrint("masternode","CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CMasternodeBroadcast();
        return false;
    }

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew)) {
        strErrorRet = strprintf("Failed to sign broadcast, masternode=%s", txin.prevout.hash.ToString());
        LogPrint("masternode","CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CMasternodeBroadcast();
        return false;
    }

    return true;
}

bool CMasternodeBroadcast::CheckDefaultPort(std::string strService, std::string& strErrorRet, std::string strContext)
{
    CService service = CService(strService);
    int nDefaultPort = Params().GetDefaultPort();

    if (service.GetPort() != nDefaultPort) {
        strErrorRet = strprintf("Invalid port %u for masternode %s, only %d is supported on %s-net.",
                                        service.GetPort(), strService, nDefaultPort, Params().NetworkIDString());
        LogPrint("masternode", "%s - %s\n", strContext, strErrorRet);
        return false;
    }

    return true;
}

bool CMasternodeBroadcast::CheckAndUpdate(int& nDos)
{
    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("masternode","mnb - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }

    // incorrect ping or its sigTime
    if(lastPing == CMasternodePing() || !lastPing.CheckAndUpdate(nDos, false, true))
    return false;

    if (protocolVersion < masternodePayments.GetMinMasternodePaymentsProto()) {
        LogPrint("masternode","mnb - ignoring outdated Masternode %s protocol version %d\n", vin.prevout.hash.ToString(), protocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubkey.GetID());

    if (pubkeyScript.size() != 25) {
        LogPrint("masternode","mnb - pubkey the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubkey2.GetID());

    if (pubkeyScript2.size() != 25) {
        LogPrint("masternode","mnb - pubkey2 the wrong size\n");
        nDos = 100;
        return false;
    }

    if (!vin.scriptSig.empty()) {
        LogPrint("masternode","mnb - Ignore Not Empty ScriptSig %s\n", vin.prevout.hash.ToString());
        return false;
    }

    std::string errorMessage = "";
    if (!darkSendSigner.VerifyMessage(pubkey, sig, GetNewStrMessage(), errorMessage)
            && !darkSendSigner.VerifyMessage(pubkey, sig, GetOldStrMessage(), errorMessage))
    {
        // don't ban for old masternodes, their sigs could be broken because of the bug
        nDos = protocolVersion < MIN_PEER_MNANNOUNCE ? 0 : 100;
        return error("CMasternodeBroadcast::CheckAndUpdate - Got bad Masternode address signature : %s", errorMessage);
    }

    if (Params().NetworkID() == Params().Network::MAIN) {
        if (addr.GetPort() != 11771) return false;
    } else if (addr.GetPort() == 11771)
        return false;

    //search existing Masternode list, this is where we update existing Masternodes with new mnb broadcasts
    CMasternode* pmn = mnodeman.Find(vin);

    // no such masternode, nothing to update
    if (pmn == NULL) return true;

    // this broadcast is older or equal than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    // (mapSeenMasternodeBroadcast in CMasternodeMan::ProcessMessage should filter legit duplicates)
    if(pmn->sigTime >= sigTime) {
        return error("CMasternodeBroadcast::CheckAndUpdate - Bad sigTime %d for Masternode %20s %105s (existing broadcast is at %d)",
                      sigTime, addr.ToString(), vin.ToString(), pmn->sigTime);
    }

    // masternode is not enabled yet/already, nothing to update
    if (!pmn->IsEnabled()) return true;

    // mn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
    //   after that they just need to match
    if (pmn->pubkey == pubkey && !pmn->IsBroadcastedWithin(MASTERNODE_MIN_MNB_SECONDS)) {
        //take the newest entry
        LogPrint("masternode","mnb - Got updated entry for %s\n", vin.prevout.hash.ToString());
        if (pmn->UpdateFromNewBroadcast((*this))) {
            pmn->Check();
            if (pmn->IsEnabled()) Relay();
        }
        masternodeSync.AddedMasternodeList(GetHash());
    }

    return true;
}

bool CMasternodeBroadcast::CheckInputsAndAdd(int& nDoS)
{
    // we are a masternode with the same vin (i.e. already activated) and this mnb is ours (matches our Masternode privkey)
    // so nothing to do here for us
    if (fMasterNode && vin.prevout == activeMasternode.vin.prevout && pubkey2 == activeMasternode.pubkey2)
        return true;

    // incorrect ping or its sigTime
    if(lastPing == CMasternodePing() || !lastPing.CheckAndUpdate(nDoS, false, true)) return false;

    // search existing Masternode list
    CMasternode* pmn = mnodeman.Find(vin);

    if (pmn != NULL) {
        // nothing to do here if we already know about this masternode and it's enabled
        if (pmn->IsEnabled()) return true;
        // if it's not enabled, remove old MN first and continue
        else
            mnodeman.Remove(pmn->vin);
    }

    CValidationState state;
    CMutableTransaction tx = CMutableTransaction();
    CTxOut vout = CTxOut(9999.99 * COIN, darkSendPool.collateralPubKey);
    tx.vin.push_back(vin);
    tx.vout.push_back(vout);

    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            // not mnb fault, let it to be checked again later
            mnodeman.mapSeenMasternodeBroadcast.erase(GetHash());
            masternodeSync.mapSeenSyncMNB.erase(GetHash());
            return false;
        }

        if (!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
            //set nDos
            state.IsInvalid(nDoS);
            return false;
        }
    }

    LogPrint("masternode", "mnb - Accepted Masternode entry\n");

    if (GetInputAge(vin) < MASTERNODE_MIN_CONFIRMATIONS) {
        LogPrint("masternode","mnb - Input must have at least %d confirmations\n", MASTERNODE_MIN_CONFIRMATIONS);
        // maybe we miss few blocks, let this mnb to be checked again later
        mnodeman.mapSeenMasternodeBroadcast.erase(GetHash());
        masternodeSync.mapSeenSyncMNB.erase(GetHash());
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 10000 PHR tx got MASTERNODE_MIN_CONFIRMATIONS
    uint256 hashBlock = 0;
    CTransaction tx2;
    GetTransaction(vin.prevout.hash, tx2, hashBlock, true);
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end() && (*mi).second) {
        CBlockIndex* pMNIndex = (*mi).second;                                                        // block for 10000 PHR tx -> 1 confirmation
        CBlockIndex* pConfIndex = chainActive[pMNIndex->nHeight + MASTERNODE_MIN_CONFIRMATIONS - 1]; // block where tx got MASTERNODE_MIN_CONFIRMATIONS
        if (pConfIndex->GetBlockTime() > sigTime) {
            LogPrint("masternode","mnb - Bad sigTime %d for Masternode %s (%i conf block is at %d)\n",
                sigTime, vin.prevout.hash.ToString(), MASTERNODE_MIN_CONFIRMATIONS, pConfIndex->GetBlockTime());
            return false;
        }
    }

    LogPrint("masternode","mnb - Got NEW Masternode entry - %s - %lli \n", vin.prevout.hash.ToString(), sigTime);
    CMasternode mn(*this);
    mnodeman.Add(mn);

    // if it matches our Masternode privkey, then we've been remotely activated
    if (pubkey2 == activeMasternode.pubkey2 && protocolVersion == PROTOCOL_VERSION) {
        activeMasternode.EnableHotColdMasterNode(vin, addr);
    }

    bool isLocal = addr.IsRFC1918() || addr.IsLocal();
    if (Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;

    if (!isLocal) Relay();

    return true;
}

void CMasternodeBroadcast::Relay()
{
    CInv inv(MSG_MASTERNODE_ANNOUNCE, GetHash());
    RelayInv(inv);
}

bool CMasternodeBroadcast::Sign(CKey& keyCollateralAddress)
{
    std::string errorMessage;
    sigTime = GetAdjustedTime();

    std::string strMessage;
    if(chainActive.Height() <= Params().Zerocoin_LastOldParams())
        strMessage = GetOldStrMessage();
    else
        strMessage = GetNewStrMessage();

    if (!darkSendSigner.SignMessage(strMessage, errorMessage, sig, keyCollateralAddress))
        return error("CMasternodeBroadcast::Sign() - Error: %s", errorMessage);


    if (!darkSendSigner.VerifyMessage(pubkey, sig, strMessage, errorMessage))
        return error("CMasternodeBroadcast::Sign() - Error: %s", errorMessage);

    return true;
}

bool CMasternodeBroadcast::VerifySignature()
{
    std::string errorMessage;

    if(!darkSendSigner.VerifyMessage(pubkey, sig, GetNewStrMessage(), errorMessage)
            && !darkSendSigner.VerifyMessage(pubkey, sig, GetOldStrMessage(), errorMessage))
        return error("CMasternodeBroadcast::VerifySignature() - Error: %s", errorMessage);

    return true;
}

std::string CMasternodeBroadcast::GetOldStrMessage()
{
    std::string strMessage;

    std::string vchPubKey(pubkey.begin(), pubkey.end());
    std::string vchPubKey2(pubkey2.begin(), pubkey2.end());
    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);

    return strMessage;
}

std:: string CMasternodeBroadcast::GetNewStrMessage()
{
    std::string strMessage;

    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + pubkey.GetID().ToString() + pubkey2.GetID().ToString() + boost::lexical_cast<std::string>(protocolVersion);

    return strMessage;
}

CMasternodePing::CMasternodePing()
{
    vin = CTxIn();
    blockHash = uint256(0);
    sigTime = 0;
    vchSig = std::vector<unsigned char>();
}

CMasternodePing::CMasternodePing(CTxIn& newVin)
{
    vin = newVin;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    vchSig = std::vector<unsigned char>();
}


bool CMasternodePing::Sign(CKey& keyMasternode, CPubKey& pubkey2)
{
    std::string errorMessage;
    std::string strMasterNodeSignMessage;

    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if (!darkSendSigner.SignMessage(strMessage, errorMessage, vchSig, keyMasternode)) {
        LogPrint("masternode","CMasternodePing::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubkey2, vchSig, strMessage, errorMessage)) {
        LogPrint("masternode","CMasternodePing::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    return true;
}

bool CMasternodePing::VerifySignature(CPubKey& pubkey2, int &nDos) {
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string errorMessage = "";

    if(!darkSendSigner.VerifyMessage(pubkey2, vchSig, strMessage, errorMessage)){
        nDos = 33;
        return error("CMasternodePing::VerifySignature - Got bad Masternode ping signature %s Error: %s", vin.ToString(), errorMessage);
    }
    return true;
}

bool CMasternodePing::CheckAndUpdate(int& nDos, bool fRequireEnabled, bool fCheckSigTimeOnly)
{
    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("masternode","mnb - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }


    if(fCheckSigTimeOnly) {
        CMasternode* pmn = mnodeman.Find(vin);
        if(pmn) return VerifySignature(pmn->pubkey2, nDos);
        return true;
    }

    LogPrint("masternode", "CMasternodePing::CheckAndUpdate - New Ping - %s - %s - %lli\n", GetHash().ToString(), blockHash.ToString(), sigTime);

    // see if we have this Masternode
    CMasternode* pmn = mnodeman.Find(vin);
    if (pmn != NULL && pmn->protocolVersion >= masternodePayments.GetMinMasternodePaymentsProto()) {
        if (fRequireEnabled && !pmn->IsEnabled()) return false;

        // LogPrint("masternode","mnping - Found corresponding mn for vin: %s\n", vin.ToString());
        // update only if there is no known ping for this masternode or
        // last ping was more then MASTERNODE_MIN_MNP_SECONDS-60 ago comparing to this one
        if (!pmn->IsPingedWithin(MASTERNODE_MIN_MNP_SECONDS - 60, sigTime)) {
            if (!VerifySignature(pmn->pubkey2, nDos))
                return false;

            BlockMap::iterator mi = mapBlockIndex.find(blockHash);
            if (mi != mapBlockIndex.end() && (*mi).second) {
                if ((*mi).second->nHeight < chainActive.Height() - 24) {
                    LogPrint("masternode","CMasternodePing::CheckAndUpdate - Masternode %s block hash %s is too old\n", vin.prevout.hash.ToString(), blockHash.ToString());
                    // Do nothing here (no Masternode update, no mnping relay)
                    // Let this node to be visible but fail to accept mnping

                    return false;
                }
            } else {
                if (fDebug) LogPrint("masternode","CMasternodePing::CheckAndUpdate - Masternode %s block hash %s is unknown\n", vin.prevout.hash.ToString(), blockHash.ToString());
                // maybe we stuck so we shouldn't ban this node, just fail to accept it
                // TODO: or should we also request this block?

                return false;
            }

            pmn->lastPing = *this;

            //mnodeman.mapSeenMasternodeBroadcast.lastPing is probably outdated, so we'll update it
            CMasternodeBroadcast mnb(*pmn);
            uint256 hash = mnb.GetHash();
            if (mnodeman.mapSeenMasternodeBroadcast.count(hash)) {
                mnodeman.mapSeenMasternodeBroadcast[hash].lastPing = *this;
            }

            pmn->Check(true);
            if (!pmn->IsEnabled()) return false;

            LogPrint("masternode", "CMasternodePing::CheckAndUpdate - Masternode ping accepted, vin: %s\n", vin.prevout.hash.ToString());

            Relay();
            return true;
        }
        LogPrint("masternode", "CMasternodePing::CheckAndUpdate - Masternode ping arrived too early, vin: %s\n", vin.prevout.hash.ToString());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }
    LogPrint("masternode", "CMasternodePing::CheckAndUpdate - Couldn't find compatible Masternode entry, vin: %s\n", vin.prevout.hash.ToString());

    return false;
}

void CMasternodePing::Relay()
{
    CInv inv(MSG_MASTERNODE_PING, GetHash());
    RelayInv(inv);
}