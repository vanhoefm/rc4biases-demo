#ifndef biases_kviterbishortest_h_
#define biases_kviterbishortest_h_

#include <stdint.h>

#include "util.h"

/**
 * - When using float (without any lambda normalization) we fail to detect the correct CRC at position 103.
 * - When using double it did work properly.
 */
typedef double vitprivfloat;

struct ViterbiCandidate
{
	uint8_t P[18];
	vitprivfloat pr;

	ViterbiCandidate() : pr(0) {
		memset(P, 0, sizeof(P));
	}
};

ViterbiCandidate * kviterbishortest_find(mydouble lambdas[17][256][256], size_t numcandidates, uint8_t startval, uint8_t endval, bool charset[256]);


#endif // biases_kviterbishortest_h_
