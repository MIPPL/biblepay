// Copyright (c) 2014-2019 The Dash Core developers
// Copyright (c) 2018-2020 The DAC Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#define ENABLE_DEBUG

#include "governance-classes.h"
#include "core_io.h"
#include "init.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "rpcpog.h"
#include "smartcontract-server.h"
#include <boost/algorithm/string.hpp>

#include <univalue.h>

// DECLARE GLOBAL VARIABLES FOR GOVERNANCE CLASSES
CGovernanceTriggerManager triggerman;

// SPLIT UP STRING BY DELIMITER
// http://www.boost.org/doc/libs/1_58_0/doc/html/boost/algorithm/split_idp202406848.html
std::vector<std::string> SplitBy(const std::string& strCommand, const std::string& strDelimit)
{
    std::vector<std::string> vParts;
    boost::split(vParts, strCommand, boost::is_any_of(strDelimit));

    for (int q = 0; q < (int)vParts.size(); q++) {
        if (strDelimit.find(vParts[q]) != std::string::npos) {
            vParts.erase(vParts.begin() + q);
            --q;
        }
    }

    return vParts;
}

CAmount ParsePaymentAmount(const std::string& strAmount)
{
    DBG(std::cout << "ParsePaymentAmount Start: strAmount = " << strAmount << std::endl;);

    CAmount nAmount = 0;
    if (strAmount.empty()) {
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Amount is empty";
        throw std::runtime_error(ostr.str());
    }
    if (strAmount.size() > 20) {
        // String is much too long, the functions below impose stricter
        // requirements
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Amount string too long";
        throw std::runtime_error(ostr.str());
    }
    // Make sure the string makes sense as an amount
    // Note: No spaces allowed
    // Also note: No scientific notation
    size_t pos = strAmount.find_first_not_of("0123456789.");
    if (pos != std::string::npos) {
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Amount string contains invalid character";
        throw std::runtime_error(ostr.str());
    }

    pos = strAmount.find(".");
    if (pos == 0) {
        // JSON doesn't allow values to start with a decimal point
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Invalid amount string, leading decimal point not allowed";
        throw std::runtime_error(ostr.str());
    }

    // Make sure there's no more than 1 decimal point
    if ((pos != std::string::npos) && (strAmount.find(".", pos + 1) != std::string::npos)) {
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Invalid amount string, too many decimal points";
        throw std::runtime_error(ostr.str());
    }

    // Note this code is taken from AmountFromValue in rpcserver.cpp
    // which is used for parsing the amounts in createrawtransaction.
    if (!ParseFixedPoint(strAmount, 8, &nAmount)) {
        nAmount = 0;
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: ParseFixedPoint failed for string: " << strAmount;
        throw std::runtime_error(ostr.str());
    }
    if (!MoneyRange(nAmount)) {
        nAmount = 0;
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Invalid amount string, value outside of valid money range";
        throw std::runtime_error(ostr.str());
    }

    DBG(std::cout << "ParsePaymentAmount Returning true nAmount = " << nAmount << std::endl;);

    return nAmount;
}

/**
*   Add Governance Object
*/

bool CGovernanceTriggerManager::AddNewTrigger(uint256 nHash)
{
    DBG(std::cout << "CGovernanceTriggerManager::AddNewTrigger: Start" << std::endl;);
    AssertLockHeld(governance.cs);

    // IF WE ALREADY HAVE THIS HASH, RETURN
    if (mapTrigger.count(nHash)) {
        LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::AddNewTrigger -- Already have hash, nHash = %s, count = %d, size = %s\n",
                    nHash.GetHex(), mapTrigger.count(nHash), mapTrigger.size());
        return false;
    }

    CSuperblock_sptr pSuperblock;
    try {
        CSuperblock_sptr pSuperblockTmp(new CSuperblock(nHash));
        pSuperblock = pSuperblockTmp;
    } catch (std::exception& e) {
        DBG(std::cout << "CGovernanceTriggerManager::AddNewTrigger Error creating superblock"
                      << ", e.what() = " << e.what()
                      << std::endl;);
        LogPrintf("CGovernanceTriggerManager::AddNewTrigger -- Error creating superblock: %s\n", e.what());
        return false;
    } catch (...) {
        LogPrintf("CGovernanceTriggerManager::AddNewTrigger: Unknown Error creating superblock\n");
        DBG(std::cout << "CGovernanceTriggerManager::AddNewTrigger Error creating superblock catchall" << std::endl;);
        return false;
    }

    pSuperblock->SetStatus(SEEN_OBJECT_IS_VALID);

    DBG(std::cout << "CGovernanceTriggerManager::AddNewTrigger: Inserting trigger" << std::endl;);
    mapTrigger.insert(std::make_pair(nHash, pSuperblock));

    DBG(std::cout << "CGovernanceTriggerManager::AddNewTrigger: End" << std::endl;);

    return true;
}

/**
*
*   Clean And Remove
*
*/

void CGovernanceTriggerManager::CleanAndRemove()
{
    if (fDebugSpam)
		LogPrint("gobject", "CGovernanceTriggerManager::CleanAndRemove -- Start\n");

	if (fDebugSpam)
		DBG(std::cout << "CGovernanceTriggerManager::CleanAndRemove: Start" << std::endl;);
    AssertLockHeld(governance.cs);

    // Remove triggers that are invalid or expired
    LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- mapTrigger.size() = %d\n", mapTrigger.size());

    trigger_m_it it = mapTrigger.begin();
    while (it != mapTrigger.end()) {
        bool remove = false;
        CGovernanceObject* pObj = nullptr;
        CSuperblock_sptr& pSuperblock = it->second;
        if (!pSuperblock) {
            LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- nullptr superblock\n");
            remove = true;
        } else {
            pObj = governance.FindGovernanceObject(it->first);
            if (!pObj || pObj->GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) {
                LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- Unknown or non-trigger superblock\n");
                pSuperblock->SetStatus(SEEN_OBJECT_ERROR_INVALID);
            }

            LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- superblock status = %d\n", pSuperblock->GetStatus());
            switch (pSuperblock->GetStatus()) {
            case SEEN_OBJECT_ERROR_INVALID:
            case SEEN_OBJECT_UNKNOWN:
                LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- Unknown or invalid trigger found\n");
                remove = true;
                break;
            case SEEN_OBJECT_IS_VALID:
            case SEEN_OBJECT_EXECUTED: {
                LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- Valid trigger found\n");
                if (pSuperblock->IsExpired()) {
                    // update corresponding object
                    pObj->SetExpired();
                    remove = true;
                }
                break;
            }
            default:
                break;
            }
        }
        LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- %smarked for removal\n", remove ? "" : "NOT ");

        if (remove) {
            std::string strDataAsPlainString = "nullptr";
            if (pObj) {
                strDataAsPlainString = pObj->GetDataAsPlainString();
                // mark corresponding object for deletion
                pObj->PrepareDeletion(GetAdjustedTime());
            }
            LogPrint(BCLog::GOBJECT, "CGovernanceTriggerManager::CleanAndRemove -- Removing trigger object %s\n", strDataAsPlainString);
            // delete the trigger
            mapTrigger.erase(it++);
        } else {
            ++it;
        }
    }

    DBG(std::cout << "CGovernanceTriggerManager::CleanAndRemove: End" << std::endl;);
}

/**
*   Get Active Triggers
*
*   - Look through triggers and scan for active ones
*   - Return the triggers in a list
*/

std::vector<CSuperblock_sptr> CGovernanceTriggerManager::GetActiveTriggers()
{
    AssertLockHeld(governance.cs);
    std::vector<CSuperblock_sptr> vecResults;

	if (fDebugSpam)
		DBG(std::cout << "GetActiveTriggers: mapTrigger.size() = " << mapTrigger.size() << std::endl;);

    // LOOK AT THESE OBJECTS AND COMPILE A VALID LIST OF TRIGGERS
    for (const auto& pair : mapTrigger) {
        CGovernanceObject* pObj = governance.FindGovernanceObject(pair.first);
        if (pObj) {
            DBG(std::cout << "GetActiveTriggers: pObj->GetDataAsPlainString() = " << pObj->GetDataAsPlainString() << std::endl;);
            vecResults.push_back(pair.second);
        }
    }

	if (fDebugSpam)
		DBG(std::cout << "GetActiveTriggers: vecResults.size() = " << vecResults.size() << std::endl;);

    return vecResults;
}

/**
*   Is Superblock Triggered
*
*   - Does this block have a non-executed and actived trigger?
*/

bool CSuperblockManager::IsSuperblockTriggered(int nBlockHeight)
{
    LogPrint(BCLog::GOBJECT, "CSuperblockManager::IsSuperblockTriggered -- Start nBlockHeight = %d\n", nBlockHeight);
    if (!CSuperblock::IsValidBlockHeight(nBlockHeight)) {
        return false;
    }
    if (fDebugSpam)
		LogPrint("gobject", "CSuperblockManager::IsSuperblockTriggered -- Start nBlockHeight = %d\n", nBlockHeight);

    LOCK(governance.cs);
	
    // GET ALL ACTIVE TRIGGERS
    std::vector<CSuperblock_sptr> vecTriggers = triggerman.GetActiveTriggers();

    LogPrint(BCLog::GOBJECT, "CSuperblockManager::IsSuperblockTriggered -- vecTriggers.size() = %d\n", vecTriggers.size());

    DBG(std::cout << "IsSuperblockTriggered Number triggers = " << vecTriggers.size() << std::endl;);

    for (const auto& pSuperblock : vecTriggers) 
	{
        if (!pSuperblock) {
            LogPrintf("CSuperblockManager::IsSuperblockTriggered -- Non-superblock found, continuing\n");
            DBG(std::cout << "IsSuperblockTriggered Not a superblock, continuing " << std::endl;);
            continue;
        }

        CGovernanceObject* pObj = pSuperblock->GetGovernanceObject();

        if (!pObj) {
            LogPrintf("CSuperblockManager::IsSuperblockTriggered -- pObj == nullptr, continuing\n");
            DBG(std::cout << "IsSuperblockTriggered pObj is NULL, continuing" << std::endl;);
            continue;
        }

        LogPrint(BCLog::GOBJECT, "CSuperblockManager::IsSuperblockTriggered -- data = %s\n", pObj->GetDataAsPlainString());

        // note : 12.1 - is epoch calculation correct?

        if (nBlockHeight != pSuperblock->GetBlockHeight()) {
            LogPrint(BCLog::GOBJECT, "CSuperblockManager::IsSuperblockTriggered -- block height doesn't match nBlockHeight = %d, blockStart = %d, continuing\n",
                nBlockHeight,
                pSuperblock->GetBlockHeight());
            DBG(std::cout << "IsSuperblockTriggered Not the target block, continuing"
                          << ", nBlockHeight = " << nBlockHeight
                          << ", superblock->GetBlockHeight() = " << pSuperblock->GetBlockHeight()
                          << std::endl;);
            continue;
        }

        // MAKE SURE THIS TRIGGER IS ACTIVE VIA FUNDING CACHE FLAG

        pObj->UpdateSentinelVariables();

        if (pObj->IsSetCachedFunding()) 
		{
			// DAC - If this is a Smart Contract, first we need to verify it meets the Quorum requirements
			if (CSuperblock::IsSmartContract(nBlockHeight))
			{
				int iVotes = pObj->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING);
				int iRequiredVotes = GetRequiredQuorumLevel(nBlockHeight);
				bool bPassed = iVotes >= iRequiredVotes;
				LogPrintf("\nCSuperblockManager::IsGSCSuperblockTriggered - Height %f, Votes %f, Required Votes %f, Status %f",
					(double)nBlockHeight, (double)iVotes, (double)iRequiredVotes, (double)bPassed);
				// If IsSetCachedFunding() is set, it met the requirements
				return true;
			}
			else
			{
				LogPrint(BCLog::GOBJECT, "CSuperblockManager::IsSuperblockTriggered -- fCacheFunding = false, continuing\n");
				DBG(std::cout << "IsSuperblockTriggered returning true" << std::endl;);
				return true;
			}
        }
		else 
		{
            LogPrint("gobject", "CSuperblockManager::IsSuperblockTriggered -- fCacheFunding = false, continuing\n");
            DBG(std::cout << "IsSuperblockTriggered No fCachedFunding, continuing" << std::endl;);
        }
    }

	if (CSuperblock::IsSmartContract(nBlockHeight)) 
		LogPrintf("IsSuperblockTriggered::SmartContract -- WARNING: No GSC superblock triggered at this height %f. ", nBlockHeight);

    return false;
}


bool CSuperblockManager::GetBestSuperblock(CSuperblock_sptr& pSuperblockRet, int nBlockHeight)
{
    if (!CSuperblock::IsValidBlockHeight(nBlockHeight) && !CSuperblock::IsSmartContract(nBlockHeight)) 
	{
		if (fDebugSpam)
			LogPrintf("**GetBestSuperblock::HEIGHT %f, Not a valid superblock height**", nBlockHeight);
        return false;
    }

    AssertLockHeld(governance.cs);
    std::vector<CSuperblock_sptr> vecTriggers = triggerman.GetActiveTriggers();
    int nYesCount = 0;

    for (const auto& pSuperblock : vecTriggers) {
        if (!pSuperblock) {
            DBG(std::cout << "GetBestSuperblock Not a superblock, continuing" << std::endl;);
            continue;
        }

        CGovernanceObject* pObj = pSuperblock->GetGovernanceObject();

        if (!pObj) {
            DBG(std::cout << "GetBestSuperblock pObj is NULL, continuing" << std::endl;);
            continue;
        }

        if (nBlockHeight != pSuperblock->GetBlockHeight()) {
            DBG(std::cout << "GetBestSuperblock Not the target block, continuing" << std::endl;);
            continue;
        }

        // DO WE HAVE A NEW WINNER?

        int nTempYesCount = pObj->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING);
        DBG(std::cout << "GetBestSuperblock nTempYesCount = " << nTempYesCount << std::endl;);
        if (nTempYesCount > nYesCount) {
            nYesCount = nTempYesCount;
            pSuperblockRet = pSuperblock;
            DBG(std::cout << "GetBestSuperblock Valid superblock found, pSuperblock set" << std::endl;);
        }
    }

    return nYesCount > 0;
}

std::string GetQTPhaseXML(uint256 gObj)
{
	CGovernanceObject *myGov = governance.FindGovernanceObject(gObj);
	if (myGov)
	{
		UniValue obj = myGov->GetJSONObject();
		if (obj.size() > 0)
		{
			std::string sPrice = obj["price"].getValStr();
			std::string sQTPhase = obj["qtphase"].getValStr();
			std::string sBTC = obj["btcprice"].getValStr();
			std::string sSporkData = obj["spork_data"].getValStr();
			std::string sXML = "<price>" + sPrice + "</price><qtphase>" + sQTPhase + "</qtphase><btcprice>" + sBTC + "</btcprice>";
			sXML += sSporkData;
			return sXML;
		}
	}
	return "<price>-0.00</price><qtphase>-0.00</qtphase><btcprice>-0</btcprice>";
}


/**
*   Get Superblock Payments
*
*   - Returns payments for superblock
*/

bool CSuperblockManager::GetSuperblockPayments(int nBlockHeight, std::vector<CTxOut>& voutSuperblockRet)
{
    DBG(std::cout << "CSuperblockManager::GetSuperblockPayments Start" << std::endl;);

    LOCK(governance.cs);

    // GET THE BEST SUPERBLOCK FOR THIS BLOCK HEIGHT

    CSuperblock_sptr pSuperblock;
    if (!CSuperblockManager::GetBestSuperblock(pSuperblock, nBlockHeight)) {
        LogPrint(BCLog::GOBJECT, "CSuperblockManager::GetSuperblockPayments -- Can't find superblock for height %d\n", nBlockHeight);
        return false;
    }

    // make sure it's empty, just in case
    voutSuperblockRet.clear();

    // GET SUPERBLOCK OUTPUTS

    // Superblock payments will be appended to the end of the coinbase vout vector
    DBG(std::cout << "CSuperblockManager::GetSuperblockPayments Number payments: " << pSuperblock->CountPayments() << std::endl;);

    // TODO: How many payments can we add before things blow up?
    //       Consider at least following limits:
    //          - max coinbase tx size
    //          - max "budget" available
    bool bQTPhaseEmitted = false;

    for (int i = 0; i < pSuperblock->CountPayments(); i++) {
        CGovernancePayment payment;
        DBG(std::cout << "CSuperblockManager::GetSuperblockPayments i = " << i << std::endl;);
        if (pSuperblock->GetPayment(i, payment)) {
            DBG(std::cout << "CSuperblockManager::GetSuperblockPayments Payment found " << std::endl;);
            // SET COINBASE OUTPUT TO SUPERBLOCK SETTING

            CTxOut txout = CTxOut(payment.nAmount, payment.script);
			// DAC - QT
			if (!bQTPhaseEmitted) 
			{
				txout.sTxOutMessage = GetQTPhaseXML(pSuperblock->GetGovernanceObject()->GetHash());
				bQTPhaseEmitted = true;
			}
    
            voutSuperblockRet.push_back(txout);

            // PRINT NICE LOG OUTPUT FOR SUPERBLOCK PAYMENT

            CTxDestination address1;
            ExtractDestination(payment.script, address1);
            CBitcoinAddress address2(address1);

            // TODO: PRINT NICE N.N COIN OUTPUT

            LogPrint(BCLog::GOBJECT, "CSuperblockManager::GetSuperblockPayments -- NEW Superblock: output %d (addr %s, amount %lld)\n",
                        i, address2.ToString(), payment.nAmount);
        } else {
            LogPrint(BCLog::GOBJECT, "CSuperblockManager::GetSuperblockPayments -- Payment not found\n");
        }
    }

    DBG(std::cout << "CSuperblockManager::GetSuperblockPayments End" << std::endl;);

    return true;
}

bool CSuperblockManager::IsValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward)
{
    // GET BEST SUPERBLOCK, SHOULD MATCH
    LOCK(governance.cs);

    CSuperblock_sptr pSuperblock;
    if (CSuperblockManager::GetBestSuperblock(pSuperblock, nBlockHeight)) {
        return pSuperblock->IsValid(txNew, nBlockHeight, blockReward);
    }

    return false;
}

void CSuperblockManager::ExecuteBestSuperblock(int nBlockHeight)
{
    LOCK(governance.cs);

    CSuperblock_sptr pSuperblock;
    if (GetBestSuperblock(pSuperblock, nBlockHeight)) {
        // All checks are done in CSuperblock::IsValid via IsBlockValueValid and IsBlockPayeeValid,
        // tip wouldn't be updated if anything was wrong. Mark this trigger as executed.
        pSuperblock->SetExecuted();
    }
}

CSuperblock::
    CSuperblock() :
    nGovObjHash(),
    nBlockHeight(0),
    nStatus(SEEN_OBJECT_UNKNOWN),
    vecPayments()
{
}

CSuperblock::
    CSuperblock(uint256& nHash) :
    nGovObjHash(nHash),
    nBlockHeight(0),
    nStatus(SEEN_OBJECT_UNKNOWN),
    vecPayments()
{
    DBG(std::cout << "CSuperblock Constructor Start" << std::endl;);

    CGovernanceObject* pGovObj = GetGovernanceObject();

    if (!pGovObj) {
        DBG(std::cout << "CSuperblock Constructor pGovObjIn is NULL, returning" << std::endl;);
        throw std::runtime_error("CSuperblock: Failed to find Governance Object");
    }

    LogPrint(BCLog::GOBJECT, "CSuperblock -- Constructor pGovObj: %s, nObjectType = %d\n",
                pGovObj->GetDataAsPlainString(), pGovObj->GetObjectType());

    if (pGovObj->GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) {
        DBG(std::cout << "CSuperblock Constructor pGovObj not a trigger, returning" << std::endl;);
        throw std::runtime_error("CSuperblock: Governance Object not a trigger");
    }

    UniValue obj = pGovObj->GetJSONObject();

    // FIRST WE GET THE START HEIGHT, THE BLOCK HEIGHT AT WHICH THE PAYMENT SHALL OCCUR
    nBlockHeight = obj["event_block_height"].get_int();

    // NEXT WE GET THE PAYMENT INFORMATION AND RECONSTRUCT THE PAYMENT VECTOR
    std::string strAddresses = obj["payment_addresses"].get_str();
    std::string strAmounts = obj["payment_amounts"].get_str();
    ParsePaymentSchedule(strAddresses, strAmounts);

    LogPrint(BCLog::GOBJECT, "CSuperblock -- nBlockHeight = %d, strAddresses = %s, strAmounts = %s, vecPayments.size() = %d\n",
        nBlockHeight, strAddresses, strAmounts, vecPayments.size());

    DBG(std::cout << "CSuperblock Constructor End" << std::endl;);
}

/**
 *   Is Valid Superblock Height
 *
 *   - See if a block at this height can be a superblock
 */

bool CSuperblock::IsValidBlockHeight(int nBlockHeight)
{
    // SUPERBLOCKS CAN HAPPEN ONLY after hardfork and only ONCE PER CYCLE
    return nBlockHeight >= Params().GetConsensus().nSuperblockStartBlock &&
           ((nBlockHeight % Params().GetConsensus().nSuperblockCycle) == 0);
}

void CSuperblock::GetNearestSuperblocksHeights(int nBlockHeight, int& nLastSuperblockRet, int& nNextSuperblockRet)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    int nSuperblockStartBlock = consensusParams.nSuperblockStartBlock;
    int nSuperblockCycle = consensusParams.nSuperblockCycle;

    // Get first superblock
    int nFirstSuperblockOffset = (nSuperblockCycle - nSuperblockStartBlock % nSuperblockCycle) % nSuperblockCycle;
    int nFirstSuperblock = nSuperblockStartBlock + nFirstSuperblockOffset;

    if (nBlockHeight < nFirstSuperblock) {
        nLastSuperblockRet = 0;
        nNextSuperblockRet = nFirstSuperblock;
    } else {
        nLastSuperblockRet = nBlockHeight - nBlockHeight % nSuperblockCycle;
        nNextSuperblockRet = nLastSuperblockRet + nSuperblockCycle;
    }
}

bool CSuperblock::IsSmartContract(int nHeight)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
	if (nHeight > consensusParams.FPOG_CUTOVER_HEIGHT)
	{
		return nHeight >= Params().GetConsensus().nDCCSuperblockStartBlock && ((nHeight % Params().GetConsensus().nDCCSuperblockCycle) == 20);
	}
	else
	{
		return false;
	}
}

bool CSuperblock::IsDCCSuperblock(int nHeight)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
	if (nHeight > consensusParams.PODC_LAST_BLOCK) return false;
	if (nHeight > consensusParams.F13000_CUTOVER_HEIGHT)
	{
		return nHeight >= Params().GetConsensus().nDCCSuperblockStartBlock &&
            ((nHeight % Params().GetConsensus().nDCCSuperblockCycle) == 10);
	}
	else
	{
		return nHeight >= Params().GetConsensus().nDCCSuperblockStartBlock &&
            ((nHeight % Params().GetConsensus().nDCCSuperblockCycle) == 0);
	}
}

int Get24HourAvgBits(const CBlockIndex* pindexSource, int nPrevBits)
{
	const CBlockIndex *pindexLast = pindexSource;
	if (pindexLast == NULL || pindexLast->nHeight == 0)  return nPrevBits;
	int nLookback = BLOCKS_PER_DAY;
	double nTotal = 0;
	double nSamples = 0;
	for (int i = 1; i <= nLookback; i++) 
	{
		if (pindexLast->pprev == NULL) { break; }
		nTotal += pindexLast->nBits;
		nSamples++;
		pindexLast = pindexLast->pprev;
	}
	if (nSamples < 1) return nPrevBits;
	double nAvg = nTotal / nSamples;
	return (int)nAvg;
}

CAmount CSuperblock::GetPaymentsLimit(int nBlockHeight, bool fIncludeWhaleStakes)
{
	if (nBlockHeight < 1) return 0;

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if (!IsValidBlockHeight(nBlockHeight) && !IsDCCSuperblock(nBlockHeight) && !IsSmartContract(nBlockHeight)) 
        return 0;
    
	// Use this difficulty only for Monthly governance (which accounts for 20% of emissions, but use trailing 24 hour diff for smart contracts)
	int nBits = 486585255;
		
    // Some part of all blocks issued during the cycle goes to superblock, see GetBlockSubsidy
	// We have 48.50% escrow being held back from each block, 28.5% is for the daily generic smart contract superblock, 20% for the monthly governance budget; split into 65% for Daily rewards and 35% for monthly rewards.
	
	int nSuperblockCycle = 0;
	double nBudgetFactor = 0;
	int nType = 0;
		
	if (IsValidBlockHeight(nBlockHeight))
	{
		// Active - Monthly
		nSuperblockCycle = consensusParams.nSuperblockCycle;
		nBudgetFactor = .30;
		nType = 0;
	}
	else if (IsDCCSuperblock(nBlockHeight))
	{
		// RETIRED - Daily
		nSuperblockCycle = consensusParams.nDCCSuperblockCycle;
 		nBudgetFactor = .65;
		nType = 1;
		if (fProd && nBlockHeight > 33600 && nBlockHeight < consensusParams.PODC_LAST_BLOCK) nBudgetFactor = 1.0; // Early DC Superblocks paid the entire budget.
	}
	else if (IsSmartContract(nBlockHeight))
	{
		// Active - Daily
		nSuperblockCycle = consensusParams.nDCCSuperblockCycle;
		nBudgetFactor  = nBlockHeight > consensusParams.POOM_PHASEOUT_HEIGHT ? .42 : .65;
		nType = 2;
		// LogPrintf(" AssessmentHeight %f, BlockHeight %f, 24HrAvgBits %f \n", (double)nAssessmentHeight, (double)nBlockHeight, (double)nBits);
	}
	else
	{
		return 0;
	}

	// Note at block 98400, our budget is 13518421, deflating.
	// The first call to GetBlockSubsidy calculates the future reward (and this has our standard deflation of 19% per year in it)
	CAmount nMaxMonthlyBudget = 13500000 * COIN;
	CAmount nMaxDailyBudget   = 1000000  * COIN;
	//QT - Get reference block subsidy from last months subsidy
	int nAssessmentHeight = nBlockHeight - 1;
	if (nBlockHeight > consensusParams.QTHeight)
		nAssessmentHeight -= (BLOCKS_PER_DAY * 32);
    CAmount nSuperblockPartOfSubsidy = GetBlockSubsidy(nBits, nAssessmentHeight, consensusParams, true);
    CAmount nPaymentsLimit = nSuperblockPartOfSubsidy * nSuperblockCycle * nBudgetFactor;
	CAmount nAbsoluteMaxMonthlyBudget = MAX_BLOCK_SUBSIDY * BLOCKS_PER_DAY * 30 * .20 * COIN; // Ensure monthly budget is never > 20% of avg monthly total block emission regardless of low difficulty in PODC
	if (nPaymentsLimit > nAbsoluteMaxMonthlyBudget) nPaymentsLimit = nAbsoluteMaxMonthlyBudget;
	
	if (Params().NetworkIDString() == "main")
	{
		if (nType == 0 && nBlockHeight > (consensusParams.EVOLUTION_CUTOVER_HEIGHT - 6150) && nPaymentsLimit > nMaxMonthlyBudget)
		{
			nPaymentsLimit = nMaxMonthlyBudget;
		}
		else if (nType == 2 && nBlockHeight > consensusParams.EVOLUTION_CUTOVER_HEIGHT && nPaymentsLimit > nMaxDailyBudget)
		{
			nPaymentsLimit = nMaxDailyBudget;
		}
	}
	// Dynamic Whale Staking - R Andrews - 11/11/2019
	if (nType == 2 && fIncludeWhaleStakes)
	{
		/*
		double dTotalWhalePayments = 0;
		std::vector<WhaleStake> dws = GetPayableWhaleStakes(nBlockHeight, dTotalWhalePayments);
		CAmount nTotalWhalePayments = dTotalWhalePayments * COIN;
		LogPrintf("\nGetPaymentsLimit::Whale Payments=%f over %f recs.", dTotalWhalePayments, dws.size());
		nPaymentsLimit += nTotalWhalePayments;
		*/
		nPaymentsLimit += (MAX_DAILY_WHALE_COMMITMENTS * COIN);
	}
	// End of Dynamic Whale Staking
	
    LogPrint("net", "CSuperblock::GetPaymentsLimit -- Valid superblock height %d, payments max %d \n", (double)nBlockHeight, (double)nPaymentsLimit/COIN);
	
    return nPaymentsLimit;
}

void CSuperblock::ParsePaymentSchedule(const std::string& strPaymentAddresses, const std::string& strPaymentAmounts)
{
    // SPLIT UP ADDR/AMOUNT STRINGS AND PUT IN VECTORS

    std::vector<std::string> vecParsed1;
    std::vector<std::string> vecParsed2;
    vecParsed1 = SplitBy(strPaymentAddresses, "|");
    vecParsed2 = SplitBy(strPaymentAmounts, "|");

    // IF THESE DONT MATCH, SOMETHING IS WRONG

    if (vecParsed1.size() != vecParsed2.size()) {
        std::ostringstream ostr;
        ostr << "CSuperblock::ParsePaymentSchedule -- Mismatched payments and amounts";
        LogPrintf("%s\n", ostr.str());
        throw std::runtime_error(ostr.str());
    }

    if (vecParsed1.size() == 0) {
        std::ostringstream ostr;
        ostr << "CSuperblock::ParsePaymentSchedule -- Error no payments";
        LogPrintf("%s\n", ostr.str());
        throw std::runtime_error(ostr.str());
    }

    // LOOP THROUGH THE ADDRESSES/AMOUNTS AND CREATE PAYMENTS
    /*
      ADDRESSES = [ADDR1|2|3|4|5|6]
      AMOUNTS = [AMOUNT1|2|3|4|5|6]
    */

    DBG(std::cout << "CSuperblock::ParsePaymentSchedule vecParsed1.size() = " << vecParsed1.size() << std::endl;);

    for (int i = 0; i < (int)vecParsed1.size(); i++) {
        CBitcoinAddress address(vecParsed1[i]);
        if (!address.IsValid()) {
            std::ostringstream ostr;
            ostr << "CSuperblock::ParsePaymentSchedule -- Invalid Address : " << vecParsed1[i];
            LogPrintf("%s\n", ostr.str());
            throw std::runtime_error(ostr.str());
        }
        /*
            TODO

            - There might be an issue with multisig in the coinbase on mainnet, we will add support for it in a future release.
            - Post 12.3+ (test multisig coinbase transaction)
        */
        if (address.IsScript()) {
            std::ostringstream ostr;
            ostr << "CSuperblock::ParsePaymentSchedule -- Script addresses are not supported yet : " << vecParsed1[i];
            LogPrintf("%s\n", ostr.str());
            throw std::runtime_error(ostr.str());
        }

        DBG(std::cout << "CSuperblock::ParsePaymentSchedule i = " << i
                      << ", vecParsed2[i] = " << vecParsed2[i]
                      << std::endl;);

        CAmount nAmount = ParsePaymentAmount(vecParsed2[i]);

        LogPrint(BCLog::GOBJECT, "CSuperblock::ParsePaymentSchedule -- i = %d, amount string = %s, nAmount = %lld\n", i, vecParsed2[i], nAmount);

        CGovernancePayment payment(address, nAmount);
        if (payment.IsValid()) {
            vecPayments.push_back(payment);
        } else {
            vecPayments.clear();
            std::ostringstream ostr;
            ostr << "CSuperblock::ParsePaymentSchedule -- Invalid payment found: address = " << address.ToString()
                 << ", amount = " << nAmount;
            LogPrintf("%s\n", ostr.str());
            throw std::runtime_error(ostr.str());
        }
    }
}

bool CSuperblock::GetPayment(int nPaymentIndex, CGovernancePayment& paymentRet)
{
    if ((nPaymentIndex < 0) || (nPaymentIndex >= (int)vecPayments.size())) {
        return false;
    }

    paymentRet = vecPayments[nPaymentIndex];
    return true;
}

CAmount CSuperblock::GetPaymentsTotalAmount()
{
    CAmount nPaymentsTotalAmount = 0;
    int nPayments = CountPayments();

    for (int i = 0; i < nPayments; i++) {
        nPaymentsTotalAmount += vecPayments[i].nAmount;
    }

    return nPaymentsTotalAmount;
}

/**
*   Is Transaction Valid
*
*   - Does this transaction match the superblock?
*/

bool CSuperblock::IsValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward)
{
    // TODO : LOCK(cs);
    // No reason for a lock here now since this method only accesses data
    // internal to *this and since CSuperblock's are accessed only through
    // shared pointers there's no way our object can get deleted while this
    // code is running.
    if (!IsValidBlockHeight(nBlockHeight) && !IsSmartContract(nBlockHeight)) {
        LogPrintf("CSuperblock::IsValid -- ERROR: Block invalid, incorrect block height\n");
        return false;
    }

    std::string strPayeesPossible = "";

    // CONFIGURE SUPERBLOCK OUTPUTS

    int nOutputs = txNew.vout.size();
    int nPayments = CountPayments();
    int nMinerAndMasternodePayments = nOutputs - nPayments;

    LogPrint(BCLog::GOBJECT, "CSuperblock::IsValid -- nOutputs = %d, nPayments = %d, GetDataAsHexString = %s\n",
        nOutputs, nPayments, GetGovernanceObject()->GetDataAsHexString());

    // We require an exact match (including order) between the expected
    // superblock payments and the payments actually in the block.

    if (nMinerAndMasternodePayments < 0) {
        // This means the block cannot have all the superblock payments
        // so it is not valid.
        // TODO: could that be that we just hit coinbase size limit?
        LogPrintf("CSuperblock::IsValid -- ERROR: Block invalid, too few superblock payments\n");
        return false;
    }

    // payments should not exceed limit
    CAmount nPaymentsTotalAmount = GetPaymentsTotalAmount();
    CAmount nPaymentsLimit = GetPaymentsLimit(nBlockHeight, true);
    if (nPaymentsTotalAmount > nPaymentsLimit) {
        LogPrintf("CSuperblock::IsValid -- ERROR: Block invalid, payments limit exceeded: payments %lld, limit %lld\n", nPaymentsTotalAmount, nPaymentsLimit);
        return false;
    }

    // miner and masternodes should not get more than they would usually get
    CAmount nBlockValue = txNew.GetValueOut();
    if (nBlockValue > blockReward + nPaymentsTotalAmount) {
        LogPrintf("CSuperblock::IsValid -- ERROR: Block invalid, block value limit exceeded: block %lld, limit %lld\n", nBlockValue, blockReward + nPaymentsTotalAmount);
        return false;
    }

    int nVoutIndex = 0;
    for (int i = 0; i < nPayments; i++) {
        CGovernancePayment payment;
        if (!GetPayment(i, payment)) {
            // This shouldn't happen so log a warning
            LogPrintf("CSuperblock::IsValid -- WARNING: Failed to find payment: %d of %d total payments\n", i, nPayments);
            continue;
        }

        bool fPaymentMatch = false;

        for (int j = nVoutIndex; j < nOutputs; j++) {
            // Find superblock payment
            fPaymentMatch = ((payment.script == txNew.vout[j].scriptPubKey) &&
                             (payment.nAmount == txNew.vout[j].nValue));

            if (fPaymentMatch) {
                nVoutIndex = j;
                break;
            }
        }

        if (!fPaymentMatch) {
            // Superblock payment not found!

            CTxDestination address1;
            ExtractDestination(payment.script, address1);
            CBitcoinAddress address2(address1);
            LogPrintf("CSuperblock::IsValid -- ERROR: Block invalid: %d payment %d to %s not found\n", i, payment.nAmount, address2.ToString());

            return false;
        }
    }

    return true;
}

bool CSuperblock::IsExpired() const
{
    int nExpirationBlocks{0};
    // Executed triggers are kept for another superblock cycle (approximately 1 month),
    // other valid triggers are kept for ~1 day only, everything else is pruned after ~1h.
    switch (nStatus) {
    case SEEN_OBJECT_EXECUTED:
        nExpirationBlocks = Params().GetConsensus().nSuperblockCycle;
        break;
    case SEEN_OBJECT_IS_VALID:
        nExpirationBlocks = 576;
        break;
    default:
        nExpirationBlocks = 24;
        break;
    }

    int nExpirationBlock = nBlockHeight + nExpirationBlocks;

    LogPrint(BCLog::GOBJECT, "CSuperblock::IsExpired -- nBlockHeight = %d, nExpirationBlock = %d\n", nBlockHeight, nExpirationBlock);

    if (governance.GetCachedBlockHeight() > nExpirationBlock) {
        LogPrint(BCLog::GOBJECT, "CSuperblock::IsExpired -- Outdated trigger found\n");
        fExpired = true;
        CGovernanceObject* pgovobj = GetGovernanceObject();
        if (pgovobj) 
		{
            LogPrint("gobject", "CSuperblock::IsExpired -- Expiring outdated object: %s\n", pgovobj->GetHash().ToString());
            pgovobj->fExpired = true;
            pgovobj->nDeletionTime = GetAdjustedTime();
        }
        return true;
    }

    return false;
}

/**
*   Get Required Payment String
*
*   - Get a string representing the payments required for a given superblock
*/

std::string CSuperblockManager::GetRequiredPaymentsString(int nBlockHeight)
{
    LOCK(governance.cs);
    std::string ret = "Unknown";

    // GET BEST SUPERBLOCK

    CSuperblock_sptr pSuperblock;
    if (!GetBestSuperblock(pSuperblock, nBlockHeight)) {
        LogPrint(BCLog::GOBJECT, "CSuperblockManager::GetRequiredPaymentsString -- Can't find superblock for height %d\n", nBlockHeight);
        return "error";
    }

    // LOOP THROUGH SUPERBLOCK PAYMENTS, CONFIGURE OUTPUT STRING

    for (int i = 0; i < pSuperblock->CountPayments(); i++) {
        CGovernancePayment payment;
        if (pSuperblock->GetPayment(i, payment)) {
            // PRINT NICE LOG OUTPUT FOR SUPERBLOCK PAYMENT

            CTxDestination address1;
            ExtractDestination(payment.script, address1);
            CBitcoinAddress address2(address1);

            // RETURN NICE OUTPUT FOR CONSOLE

            if (ret != "Unknown") {
                ret += ", " + address2.ToString();
            } else {
                ret = address2.ToString();
            }
        }
    }

    return ret;
}
