// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include "crypto/sha256.h"
#include "hash.h"

/*     WARNING! If you're reading this because you're learning about crypto
	   and/or designing a new system that will use merkle trees, keep in mind
	   that the following merkle tree algorithm has a serious flaw related to
	   duplicate txids, resulting in a vulnerability (CVE-2012-2459).

	   The reason is that if the number of hashes in the list at a given time
	   is odd, the last one is duplicated before computing the next level (which
	   is unusual in Merkle trees). This results in certain sequences of
	   transactions leading to the same merkle root. For example, these two
	   trees:

					A               A
				  /  \            /   \
				B     C         B       C
			   / \    |        / \     / \
			  D   E   F       D   E   F   F
			 / \ / \ / \     / \ / \ / \ / \
			 1 2 3 4 5 6     1 2 3 4 5 6 5 6

	   for transaction lists [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] (where 5 and
	   6 are repeated) result in the same root hash A (because the hash of both
	   of (F) and (F,F) is C).

	   The vulnerability results from being able to send a block with such a
	   transaction list, with the same merkle root, and the same block hash as
	   the original without duplication, resulting in failed validation. If the
	   receiving node proceeds to mark that block as permanently invalid
	   however, it will fail to accept further unmodified (and thus potentially
	   valid) versions of the same block. We defend against this by detecting
	   the case where we would hash two identical hashes at the end of the list
	   together, and treating that identically to the block having an invalid
	   merkle root. Assuming no double-SHA256 collisions, this will detect all
	   known ways of changing the transactions without affecting the merkle
	   root.
*/

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
	bool mutation = false;
	while (hashes.size() > 1) {
		if (mutated) {
			for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
				if (hashes[pos] == hashes[pos + 1]) mutation = true;
			}
		}
		if (hashes.size() & 1) {
			hashes.push_back(hashes.back());
		}
		SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
		hashes.resize(hashes.size() / 2);
	}
	if (mutated) * mutated = mutation;
	if (hashes.size() == 0) return uint256();
	return hashes[0];
}

uint64_t CalcTreeWidth(uint64_t height, uint64_t leaves) {
	return (leaves + ((uint64_t)1 << height) - 1) >> height;
}

uint64_t CalcTreeHeight(const std::vector<uint256> & hashes)
{
	uint64_t height = 0;
	auto leaves = hashes.size();
	while (leaves > 1)
	{
		if (leaves & 1)
			leaves += 1;
		leaves >>= 1;
		++height;
	}
	return height;
}

template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
	const T2 p2begin, const T2 p2end) {
	static const unsigned char pblank[1] = {};
	uint256 result;
	CHash256().Write(p1begin == p1end ? pblank : (const unsigned char*)& p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
		.Write(p2begin == p2end ? pblank : (const unsigned char*)& p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
		.Finalize((unsigned char*)& result);
	return result;
}

uint256 CalcHash(uint64_t height, uint64_t pos, const std::vector<uint256> & hashs)
{
	//we can never have zero txs in a merkle block, we always need the coinbase tx
	//if we do not have this assert, we can hit a memory access violation when indexing into vTxid
	auto leaves = hashs.size();
	assert(leaves != 0);
	if (height == 0) {
		// hash at height 0 is the txids themself
		return hashs[pos];
	}
	else {
		// calculate left hash
		uint256 left = CalcHash(height - 1, pos * 2, hashs), right;
		// calculate right hash if not beyond the end of the array - copy left hash otherwise
		if (pos * 2 + 1 < CalcTreeWidth(height - 1, leaves))
			right = CalcHash(height - 1, pos * 2 + 1, hashs);
		else
			right = left;
		// combine subhashes
		return Hash(left.begin(), left.end(), right.begin(), right.end());
	}
}

uint64_t findDiffLeaf(const std::vector<uint256> & hashs1, const std::vector<uint256> & hashs2)
{
	bool dummy;
	uint64_t index = 0;
	if (ComputeMerkleRoot(hashs1, &dummy) == ComputeMerkleRoot(hashs2, &dummy))
		return index;
	else
	{
		auto height = CalcTreeHeight(hashs1);
		auto height2 = CalcTreeHeight(hashs2);
		assert(height == height2);

		while (--height)
		{
			if (CalcHash(height, index, hashs1) != CalcHash(height, index, hashs2)) //left diff
				index = index * 2;
			else //right diff
				index = index * 2 + 2;
		}
		if ((height == 0) && (CalcHash(height, index, hashs1) == CalcHash(height, index, hashs2))) //leaves now
			index = index + 1;
		return index;
	}
}
