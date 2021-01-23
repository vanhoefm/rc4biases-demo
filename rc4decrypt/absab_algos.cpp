#include <Python.h>
#include <stdint.h>
#include <stdio.h>
#include <algorithm>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#define NO_IMPORT
#include <numpy/arrayobject.h>

#include "util.h"
#include "rdeps.h"
#include "markov.h"
#include "absab_algos.h"


// ================================================================================
//
//			Util Functions & Differential Properties
//
// ================================================================================

mydouble get_bias_pr(int gap)
{
	mydouble q = expl(-(4 + 8 * gap)/256.0L) / 256.0L;
	return 0x1p-16L * (1.0L + q);
}

mydouble get_uni_pr(int gap)
{
	return (1.0L - get_bias_pr(gap)) / (256*256 - 1);
}

void get_absab_pr(mydouble probs[256][256], int gap, int d1, int d2)
{
	mydouble unipr;

	// Fill in the uniform probabilities
	unipr = get_uni_pr(0);
	for (int i = 0; i < 256; ++i)
		for (int j = 0; j < 256; ++j)
			probs[i][j] = unipr;

	// d1 and d2 are the expected differentials
	probs[d1][d2] = get_bias_pr(gap);
}

