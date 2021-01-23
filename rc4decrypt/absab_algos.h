#ifndef biases_absab_algos_h__
#define biases_absab_algos_h__

mydouble get_bias_pr(int gap);
mydouble get_uni_pr(int gap);
void get_absab_pr(mydouble probs[256][256], int gap, int d1=0, int d2=0);

/**
 * Convert the differential counts to probabilities using a MLE approach.
 */
template<typename T>
void maxlikely_absab_log(T counts[256][256], mydouble lambdas[256][256], int gap, uint8_t known1 = 0, uint8_t known2 = 0)
{
	mydouble logbiaspr = logl(get_bias_pr(gap));
	mydouble logunipr  = logl(get_uni_pr(gap));

	// 1. Calculate number of ciphertexts we have
	uint64_t numciphers = 0;
	for (int c1 = 0; c1 < 256; ++c1) {
		for (int c2 = 0; c2 < 256; ++c2) {
			numciphers += counts[c1][c2];
		}
	}

	// 2. Calculate the actual MLEs for each differential (u1, u2)
	for (int u1 = 0; u1 < 256; ++u1) {
	for (int u2 = 0; u2 < 256; ++u2) {
		// Here `d1 = u1 ^ known1` and `d2 = u2 ^ known2` and we want
		// to look up this differential in the count array.
		T tempcount = counts[u1 ^ known1][u2 ^ known2];
		lambdas[u1][u2] += logbiaspr * tempcount;
		lambdas[u1][u2] += logunipr  * (numciphers - tempcount);
	}}
}

#endif // biases_absab_algos_h__
