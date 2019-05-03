// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MERKLE_H
#define BITCOIN_CONSENSUS_MERKLE_H

#include <vector>
#include <uint256.h>

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated = nullptr);
uint64_t CalcTreeWidth(uint64_t height, uint64_t leaves);
uint64_t CalcTreeHeight(const std::vector<uint256>& hashes);
uint256 CalcHash(uint64_t height, uint64_t pos, const std::vector<uint256>& hashs);
uint64_t findDiffLeaf(const std::vector<uint256>& hashs1, const std::vector<uint256>& hashs2);
#endif // BITCOIN_CONSENSUS_MERKLE_H
