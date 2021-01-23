#include <Python.h>
#include <string.h>

#include "util.h"
#include "markov.h"

#define MAX_PLAINLEN	18
#define NUMCANDIDATES

struct consecpr_t {
	uint8_t P[MAX_PLAINLEN];
	mydouble pr;
};

static int argmax_t(consecpr_t probs[256])
{
	int currpos = 0;
	mydouble currmax = probs[currpos].pr;

	for (int i = 1; i < 256; ++i) {
		if (probs[i].pr > currmax) {
			currmax = probs[i].pr;
			currpos = i;
		}
	}

	return currpos;
}

mydouble viterbi_decrypt_log(mydouble lambdas[][256][256], int numpairs, uint8_t startval, uint8_t endval, bool charset[256], uint8_t plaintext[])
{
	/** Most likely plaintext ending in index (with the specified probability) */
	consecpr_t probs[256];

	assert(numpairs + 1 <= MAX_PLAINLEN);

	//
	// Step 1 -- Due to the given startval we can immediately start with candidates of length 2
	//

	for (int u = 0; u < 256; ++u) {
		if (!charset[u]) continue;

		probs[u].pr = lambdas[0][startval][u];
		probs[u].P[0] = startval;
		probs[u].P[1] = u;
	}


	//
	// Step 2 -- Now go over each position and keep track of the possible global optimal plaintext candidate.
	//

	// Variable `pos` refers to the plaintext byte of which we already calculated probabilities.
	for (int pos = 1; pos < numpairs; ++pos)
	{
		consecpr_t nextprobs[256];
		memset(nextprobs, 0, sizeof(nextprobs));

		// In each loop extend current most likely candidates with `u`, and then select
		// only the one with the highest probability and put in in `nextprobs`.
		for (int u = 0; u < 256; ++u)
		{
			// Take into account that `endval` may not be an allowed character
			if (!charset[u] && !(pos == numpairs - 1 && u == endval)) continue;

			// Add the byte u to all current most likely candidates
			consecpr_t prs_appendu[256];
			memcpy(prs_appendu, probs, sizeof(prs_appendu));

			for (int i = 0; i < 256; ++i)
			{
				if (!charset[i]) {
					prs_appendu[i].pr = -INFINITY;
					continue;
				}

				// Extend P with u
				prs_appendu[i].P[pos + 1] = u;

				// Calculate new probability of extended P
				uint8_t prevu = prs_appendu[i].P[pos];
				prs_appendu[i].pr += lambdas[pos][prevu][u];
			}

			// add the highest to nextprobs
			int maxpos = argmax_t(prs_appendu);
			nextprobs[u] = prs_appendu[maxpos];
		}

		memcpy(probs, nextprobs, sizeof(probs));
	}


	//
	// Step 3 -- Take the plaintext that ends in `endval`
	//

	memcpy(plaintext, probs[endval].P, numpairs + 1);
	return probs[endval].pr;
}

