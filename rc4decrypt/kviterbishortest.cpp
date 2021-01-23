#include <Python.h>
#include <string.h>
#include <assert.h>

#include <queue>

#include "kviterbishortest.h"


/** to efficiently run the algorithm */
struct VitPrInfo
{
	/** ending value (converted to allowed character index) of this candidate */
	uint8_t previ;
	/** position in the K-best candidates of `previ` list */
	size_t candpos;
	/** probability of this candidate */
	vitprivfloat nextpr;

	VitPrInfo(vitprivfloat nextpr, uint8_t previ) : previ(previ), candpos(0), nextpr(nextpr) {}

	bool operator<(const VitPrInfo &right) const
	{
		return this->nextpr < right.nextpr;
	}
};

/** because we store pointers to our objects */
struct VitMyComparator {
	bool operator() (VitPrInfo *lhs, VitPrInfo *rhs) { return *lhs < *rhs; }
};

static void priority_queue_free(std::priority_queue<VitPrInfo *, std::vector<VitPrInfo *>, VitMyComparator> &prlist)
{
	while (!prlist.empty()) {
		VitPrInfo *curr = prlist.top();
		prlist.pop();

		delete curr;
	}
}


/**
 * The algorithm is constructed in such a way so `startval` and `endval` don't have to be allowed chars according to `charset`.
 */
ViterbiCandidate * kviterbishortest_find(mydouble lambdas[17][256][256], size_t numcandidates, uint8_t startval, uint8_t endval, bool charset[256])
{
	// These are NOT indixed by character value. When having a character value use char2idx
	ViterbiCandidate *candidates[256];
	ViterbiCandidate *newcandidates[256];
	size_t numchars = 0;
	uint8_t char2idx[256], idx2char[256];

	//
	// Step 0. Initialize the algorithm
	//

	for (unsigned u = 0; u < 256; ++u) {
		if (charset[u]) {
			char2idx[u] = numchars;
			idx2char[numchars] = u;
			numchars++;
		}
	}

	// Allocate two big arrays so we can easily return extra results beyond `numcandidates`.
	ViterbiCandidate *candidates_big    = new ViterbiCandidate[numcandidates * numchars];
	ViterbiCandidate *newcandidates_big = new ViterbiCandidate[numcandidates * numchars];
        if (candidates_big == NULL || newcandidates_big == NULL) {
                delete[] candidates_big;
                delete[] newcandidates_big;

		PyErr_SetString(PyExc_MemoryError, "Could not allocate sufficient memory of k-best viterbi algorithm");
		return NULL;
        }

	for (unsigned i = 0; i < numchars; ++i) {
		candidates[i]    = &candidates_big   [numcandidates * i];
		newcandidates[i] = &newcandidates_big[numcandidates * i];
	}

	// Since we know the start value, we can immediately start with candidates of length 2. The first value of all candidates
	// is of course `startval`. The second byte can be any value `u` whos pair probability is now lambdas[0][startval][u].
	for (unsigned i = 0; i < numchars; ++i)
	{
		candidates[i][0].pr = lambdas[0][startval][idx2char[i]];
		candidates[i][0].P[0] = startval;
		candidates[i][0].P[1] = idx2char[i];
	}


	//
	// Step 1. Do normal K-best Viterbi algorithm for every position except the last
	//

	for (unsigned pos = 1; pos < 16; ++pos)
	{
		// Maximum number of candidates we can generate this round.
		size_t maxcandidates = numcandidates;
		// At position `pos` we can have at most numchars**(pos-1) candidates for each prevu value.
		if (logl(numcandidates) >= (pos - 1) * logl(numchars))
			maxcandidates = (size_t)pow(numchars, pos - 1);

		PySys_WriteStdout("\tCalculating candidates of length %2u (max: %lu)\n", pos + 1, maxcandidates);

		for (unsigned u = 0; u < 256; ++u)
		{
			if (!charset[u]) continue;

			std::priority_queue<VitPrInfo *, std::vector<VitPrInfo *>, VitMyComparator> prlist;

			// Iterative over previous plaintext value
			for (unsigned previ = 0; previ < numchars; ++previ)
				prlist.push(new VitPrInfo(candidates[previ][0].pr + lambdas[pos][idx2char[previ]][u], previ));

			VitPrInfo *curr = prlist.top();
			prlist.pop();

			// FIXME: Save `lambdas[pos][curr->prevu][u]` in PrInfo ?? See kshortest.cpp
			for (size_t i = 0; i < numcandidates; ++i)
			{
				newcandidates[char2idx[u]][i] = candidates[curr->previ][curr->candpos];
				newcandidates[char2idx[u]][i].P[pos + 1] = u;
				newcandidates[char2idx[u]][i].pr += lambdas[pos][idx2char[curr->previ]][u];

				curr->candpos++;

				/** byte has been added to all candidates, throw it away and get next one */
				if (curr->candpos >= maxcandidates)
				{
					if (prlist.empty())
						break;

					delete curr;
					curr = prlist.top();
					prlist.pop();
				}
				/** next element on priority queue results in lower pr, use it instead */
				else if (candidates[curr->previ][curr->candpos].pr + lambdas[pos][idx2char[curr->previ]][u] < prlist.top()->nextpr)
				{
					curr->nextpr = candidates[curr->previ][curr->candpos].pr + lambdas[pos][idx2char[curr->previ]][u];
					prlist.push(curr);

					curr = prlist.top();
					prlist.pop();
				}
			}

			delete curr;
			priority_queue_free(prlist);
		}

		// Set our new candidates
		for (unsigned i = 0; i < numchars; ++i)
		{
			ViterbiCandidate *temp = candidates[i];
			candidates[i] = newcandidates[i];
			newcandidates[i] = temp;
		}
	}


	//
	// Step 2. Generate as many candidates as possible ending on this specific value
	//

	PySys_WriteStdout("\tCalculating candidates of length 17 (max: %lu)\n", numcandidates);

	std::priority_queue<VitPrInfo *, std::vector<VitPrInfo *>, VitMyComparator> prlist;
	for (unsigned previ = 0; previ < numchars; ++previ)
		prlist.push(new VitPrInfo(candidates[previ][0].pr + lambdas[16][idx2char[previ]][endval], previ));

	VitPrInfo *curr = prlist.top();
	prlist.pop();

	size_t totalnum = 0;
	while (true)
	{
		newcandidates_big[totalnum] = candidates[curr->previ][curr->candpos];
		newcandidates_big[totalnum].P[17] = endval;
		newcandidates_big[totalnum].pr += lambdas[16][idx2char[curr->previ]][endval];

		curr->candpos++;
		totalnum++;

		/** byte has been added to all candidates, throw it away and get next one */
		if (curr->candpos >= numcandidates)
		{
			break;
		}
		/** next element on priority queue results in lower pr, use it instead */
		else if (candidates[curr->previ][curr->candpos].pr + lambdas[16][idx2char[curr->previ]][endval] < prlist.top()->nextpr)
		{
			curr->nextpr = candidates[curr->previ][curr->candpos].pr + lambdas[16][idx2char[curr->previ]][endval];
			prlist.push(curr);

			curr = prlist.top();
			prlist.pop();
		}
	}

	// Add sentinel
	newcandidates_big[totalnum].pr = -INFINITY;

	PySys_WriteStdout("Optimization: we now have %lu candidates instead of %lu.\n", totalnum, numcandidates);
	
	delete curr;
	priority_queue_free(prlist);

	delete[] candidates_big;
	return newcandidates_big;
}


