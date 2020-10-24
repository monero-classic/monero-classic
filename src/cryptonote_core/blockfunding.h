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
#pragma once
#include "string_tools.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "common/util.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/verification_context.h"
#include "crypto/hash.h"

namespace cryptonote{
    class BlockFunding
    {
        public:
            BlockFunding(){}
            bool init(const network_type nettype = MAINNET);
            bool funding_enabled(uint64_t height);
//            bool check_block_funding(uint64_t actual_miner_reward, uint64_t actual_funding, uint64_t real_reward);
            bool check_block_funding(uint64_t actual_miner_reward, uint64_t actual_funding, uint64_t std_reward, double stake_reward_rate, bool fork);
            bool get_funding_from_miner_tx(const transaction& miner_tx, uint64_t& funding_amount);
//            bool fund_from_block(uint64_t original_reward, uint64_t& miner_reward, uint64_t& funding);
            bool fund_from_block(uint64_t original_reward, uint64_t& miner_reward, uint64_t& funding, uint64_t& pos_reward, double pos_reward_rate, bool fork);
            uint64_t get_funding_enabled_height();
            account_public_address& public_address();
        private:
            bool get_funding_address_and_key(account_keys& funding_keys);

        public:
            network_type m_network_type;
            account_keys m_account_keys;
    };

};


