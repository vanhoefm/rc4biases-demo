#ifndef biases_fm_algos_h__
#define biases_fm_algos_h__

struct fmbias_t
{
	int k1;
	int k2;
	mydouble pr;
};

struct fmbiases_t
{
	fmbias_t bias[12];
	int num;
	mydouble uniform;
};

/** parameter `conseq` indicates whether consecutive equal biases should be included */
void fluhrer_mcgrew_only(fmbiases_t *fmbiases, int i, bool conseq = true);
void fluhrer_mcgrew(mydouble prs[256][256], int i);
void fluhrer_mcgrew_log(mydouble prs[256][256], int i);

void simulate_doublebyte_longterm(mydouble lambdas[256][256], unsigned fm_i,
	uint64_t numsamples, uint8_t plaintext[2]);

/** likelihood estimate based on the Fluhrer-McGrew biases at position i */
void maxlikely_fm_log(int i, uint32_t counts[256][256], mydouble lambdas[256][256]);

#endif // biases_fm_algos_h__
