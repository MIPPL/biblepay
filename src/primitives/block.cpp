// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "streams.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "randomx_bbp.h"
#include <pthread.h>

/*
//#include <mutex>
//#include <thread>

std::string ExtractXML2(std::string XMLdata, std::string key, std::string key_end)
{
	std::string extraction = "";
	std::string::size_type loc = XMLdata.find( key, 0 );
	if( loc != std::string::npos )
	{
		std::string::size_type loc_end = XMLdata.find( key_end, loc+3);
		if (loc_end != std::string::npos )
		{
			extraction = XMLdata.substr(loc+(key.length()),loc_end-loc-(key.length()));
		}
	}
	return extraction;
}
*/

//static std::mutex cs_rxhasher;
uint256 CBlockHeader::GetHash() const
{
	/*
	if (this->nVersion >= 0x50000000UL && this->nVersion < 0x60000000UL)
	{
		// *****************************************                      RandomX - DAC                              ************************************************************************
		// Starting at RANDOMX_HEIGHT, we now solve for an equation, rather than simply the difficulty and target.
		// This is so our miners may earn a dual revenue stream (RandomX coins + DAC Coins).
		// The equation is:  BlakeHash(Previous_DAC_Hash + RandomX_Hash(RandomX_Coin_Header)) < Current_DAC_Block_Difficulty
		// **********************************************************************************************************************************************************************************
		// std::unique_lock<std::mutex> lock(cs_rxhasher);
		std::vector<unsigned char> vch(160);
		CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
		std::string randomXBlockHeader = ExtractXML2(RandomXData, "<rxheader>", "</rxheader>");
		std::vector<unsigned char> data0 = ParseHex(randomXBlockHeader);
		uint256 uRXMined = RandomX_Hash(data0, RandomXKey, iThreadID);
		ss << hashPrevBlock << uRXMined;
		return HashBlake((const char *)vch.data(), (const char *)vch.data() + vch.size());
	}
	else
	{
	*/
		// Legacy Hashes (Before consensusParams.RANDOMX_HEIGHT):
		std::vector<unsigned char> vch(80);
		CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
		ss << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce;
		return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
	//}
}

/*
uint256 CBlockHeader::GetHashBible() const
{
	return HashLegacy(BEGIN(nVersion),END(nNonce));
}
*/



std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
