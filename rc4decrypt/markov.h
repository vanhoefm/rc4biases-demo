#ifndef biases_markov_h__
#define biases_markov_h__

#include <stdint.h>

/**
 * [ GENERAL REMARKS ]
 *
 * In our use cases we use a Hidden Markov Module (HMM), but *without* observations. Theoretically
 * this is modelled by assuming only one "empty" observation, which occurs with probability 1
 * for every state. Hence none of the functions below will mention observations and/or their
 * probabilities. We only work with transition probabilities (here called 'pair probabilities').
 *
 * See "A tutorial on hidden Markov models and selected applications in speech recognition" for
 * an introduction to Markov models. Also see our own paper.
 */


mydouble viterbi_decrypt_log(mydouble lambdas[][256][256], int numpairs, uint8_t startval, uint8_t endval, bool charset[256], uint8_t plaintext[]);


#endif // biases_markov_h__
