#ifndef biases_shared_rdeps_h__
#define biases_shared_rdeps_h__

#include <limits.h>
#include <math.h>
#include <stdint.h>


// ============= Dependecies of the R functions =============

// Defines used internally
#define R_FINITE(x)    R_finite(x)
#define R_forceint(x)   nearbyint(x)

#define ML_ERROR(x, msg) fprintf(stderr, "%s: ERROR in " msg, __FUNCTION__)
#define ML_ERR_return_NAN { ML_ERROR(ME_DOMAIN, ""); return ML_NAN; }

#define ISNAN(x) (std::isnan(x)!=0)
#define NA_INTEGER	R_NaInt
#define NA_REAL		R_NaReal
#define ML_NAN		(0.0 / 0.0)
#define R_NaInt		INT_MIN
// R actually uses `static double R_ValueOfNA(void)` in `arithmetic.` but it seems overly complex
#define R_NaReal	ML_NAN
#define R_PosInf	INFINITY
#define R_NaN		ML_NAN

#define LDOUBLE long double
#define ME_DOMAIN	1


// Utility functions used by rbinom and rmultinom

int R_finite(double);
double R_pow_di(double x, int n);
double unif_rand();
double R_pow(double x, double y);

/* handle x ^ 2 inline */
static inline double R_POW(double x, double y) {
    return y == 2.0 ? x * x : R_pow(x, y);
}
/* handle fmin2 inline */
static inline double fmin2(double x, double y) {
	return (x < y) ? x : y;
}



// ============= Main exported R functions =============

/** Initialize Mersenne-Twister random number generator */
void MT_sgenrand(uint32_t seed);

/**
 * Simulate binomial and multinomial distribution.
 *
 * @param nin		Number of experiments
 * @param pp		Probability of success
 *
 * @returns Number of successes
 */
uint64_t rbinom(uint64_t nin, long double pp);


/**
 * void rmultinom(uint64_t n, long double *prob, uint64_t K, T *rN);
 *
 * This is a template function where T is designed to be either 32 or 64 bit.
 *
 * Returns vector  rN[1:K] {K := length(prob)} where
 * rN[j] ~ Bin(n, prob[j]) ,  sum_j rN[j] == n,  sum_j prob[j] == 1.
 */
#include "rmultinom.h"


#endif // biases_shared_rdeps_h__
