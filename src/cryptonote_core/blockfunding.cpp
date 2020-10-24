// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "blockfunding.h"
#include "include_base_utils.h"
// height to enable monero block funding
#define MONERO_ENABLE_FUNDING_HEIGHT_MAINNET 1686050 
#define MONERO_ENABLE_FUNDING_HEIGHT_STAGENET 15
#define MONERO_ENABLE_FUNDING_HEIGHT_TESTNET 2950
#define MONERO_ENABLE_FUNDING_HEIGHT_REGTESTNET 10
#define MONERO_BLOCK_FUNDING_RATE 0.1
#define MONERO_BLOCK_FUNDING_RATE_NEW 0.7 // from version 60
#define MONERO_BLOCK_MINER_POW_RATE_NEW 0.1
#define MONERO_BLOCK_MINER_POS_RATE_NEW 0.2

using namespace cryptonote;
using namespace std;
bool BlockFunding::init(const network_type nettype)
{
    m_network_type = nettype;

    if (!get_funding_address_and_key(m_account_keys))
    {
        MERROR("parse funding account failed");
        return false;
    }

    return true;
}

bool BlockFunding::get_funding_address_and_key(account_keys& funding_keys)
{

    std::string funding_addr;
    std::string funding_view_secret_key;

    switch(m_network_type)
    {
        case FAKECHAIN:
        case MAINNET:
            {
                funding_addr = config::MONERO_FUNDING_ADDR;
                funding_view_secret_key = config::MONERO_FUNDING_VIEW_SECRET_KEY;
            }
            break;
        case STAGENET:
            {
                funding_addr = config::stagenet::MONERO_FUNDING_ADDR;
                funding_view_secret_key = config::stagenet::MONERO_FUNDING_VIEW_SECRET_KEY;
            }
            break;
        case TESTNET:
            {
                funding_addr = config::testnet::MONERO_FUNDING_ADDR;
                funding_view_secret_key = config::testnet::MONERO_FUNDING_VIEW_SECRET_KEY;
            }
            break;
        default:
            {
                MERROR("unknown network type");
                return false;
            }
    }

    cryptonote::address_parse_info info;
    bool r = cryptonote::get_account_address_from_str(info, m_network_type, funding_addr);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse funding address");
    funding_keys.m_account_address = info.address;
    cryptonote::blobdata view_secret_key_data;
    if(!epee::string_tools::parse_hexstr_to_binbuff(funding_view_secret_key, view_secret_key_data) || view_secret_key_data.size() != sizeof(crypto::hash))
    {
        MERROR("failed to parse funding view secret key");
        return false;
    }
    funding_keys.m_view_secret_key = *reinterpret_cast<const crypto::secret_key*>(view_secret_key_data.data());
    return true;
}

bool BlockFunding::funding_enabled(uint64_t height)
{
    if(m_network_type == MAINNET)
    {
        return height >= MONERO_ENABLE_FUNDING_HEIGHT_MAINNET;
    }
    else if(m_network_type == STAGENET)
    {
        return height >= MONERO_ENABLE_FUNDING_HEIGHT_STAGENET;
    }
    else if(m_network_type == TESTNET)
    {
        return height >= MONERO_ENABLE_FUNDING_HEIGHT_TESTNET;
    }
    else if(m_network_type == FAKECHAIN)
    {
        return height >= MONERO_ENABLE_FUNDING_HEIGHT_REGTESTNET;
    }
    return false;
}

uint64_t BlockFunding::get_funding_enabled_height()
{
    if(m_network_type == MAINNET)
    {
        return MONERO_ENABLE_FUNDING_HEIGHT_MAINNET;
    }
    else if(m_network_type == STAGENET)
    {
        return MONERO_ENABLE_FUNDING_HEIGHT_STAGENET;
    }
    else if(m_network_type == TESTNET)
    {
        return MONERO_ENABLE_FUNDING_HEIGHT_TESTNET;
    }

    return 0;
}

//bool BlockFunding::fund_from_block(uint64_t original_reward, uint64_t& miner_reward, uint64_t& funding)
bool BlockFunding::fund_from_block(uint64_t original_reward, uint64_t& miner_reward, uint64_t& funding, uint64_t& pos_reward, double pos_reward_rate, bool fork)
{
    //funding = (uint64_t)(original_reward * MONERO_BLOCK_FUNDING_RATE);
    funding = fork ? (uint64_t)(original_reward * MONERO_BLOCK_FUNDING_RATE_NEW) : (uint64_t)(original_reward * MONERO_BLOCK_FUNDING_RATE);
    //miner_reward = (uint64_t)(original_reward - funding);
    miner_reward = fork ? (uint64_t)(original_reward * MONERO_BLOCK_MINER_POW_RATE_NEW) : (uint64_t)(original_reward - funding);
    pos_reward = fork ? (uint64_t)(original_reward * MONERO_BLOCK_MINER_POS_RATE_NEW * pos_reward_rate) : 0;

    //check
    return true;
}

//bool BlockFunding::check_block_funding(uint64_t actual_miner_reward, uint64_t actual_funding, uint64_t real_reward)
bool BlockFunding::check_block_funding(uint64_t actual_miner_reward, uint64_t actual_funding, uint64_t std_reward, double stake_reward_rate, bool fork)
{
    uint64_t real_miner_reward, real_funding, real_stake_reward;
    fund_from_block(std_reward, real_miner_reward, real_funding, real_stake_reward, stake_reward_rate, fork);
    return (actual_miner_reward == real_miner_reward + real_stake_reward) && (actual_funding == real_funding);
}

bool BlockFunding::get_funding_from_miner_tx(const transaction& miner_tx, uint64_t& funding_amount)
{
    crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(miner_tx.extra);
    const tx_out& tax_out = miner_tx.vout[miner_tx.vout.size() - 1];
    cryptonote::txout_to_key funding_out_key = boost::get < txout_to_key > (tax_out.target);
    crypto::key_derivation derivation;
    //generate derivation by view secret key
    //bool r = crypto::generate_key_derivation(tx_pub_key, m_account_keys.m_view_secret_key, derivation);
    //MERROR_VER("vout index: " << b.miner_tx.vout.size() - 1 << ", vout count: " << b.miner_tx.vout.size());
    //derive public_spend_key to compare with target of vout
    std::vector<crypto::public_key> additional_derivations;
    if(!cryptonote::is_out_to_acc(m_account_keys, funding_out_key, tx_pub_key, additional_derivations, miner_tx.vout.size() - 1))
    {
        MERROR("funding address incorrect");
        return false;
    }
    funding_amount = miner_tx.vout[miner_tx.vout.size() - 1].amount;
    return true;
}

account_public_address& BlockFunding::public_address()
{
    return m_account_keys.m_account_address;
}

