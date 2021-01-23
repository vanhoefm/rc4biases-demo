#include <algorithm>

#include "absab.h"


/**
 * The target differentials we calculate are over the cookie, and the two known bytes at the side:
 *
 *      | KNOWN0 | COOKE1 | COOKE2 | ... | COOKIE15 | COOKIE16 | KNOWN1 |
 *      <----------------->                         <------------------->
 *         differential 1                ...          differential 17
 *               <----------------->
 *                  differential 2
 *
 * Remark that the differentials over the cookie are also over (X, KNOWN0) and (KNOWN1, Y). This is
 * why the initial gap position has the conditional assignment: if the target differential we are
 * calculating already includes one of these known bytes, we cannot use these pairs anymore.
 */
size_t absab_numpairs(unsigned cookielen, unsigned absabmaxgap)
{
	unsigned currdiff = 0;
	for (unsigned pos = 0; pos < cookielen + 1; ++pos)
	{
		// Position of the target differential (the byte-pair which we consider unknown)
		//int diffpos = cookiepos + pos - 1;

		// Left
		for (unsigned gap = pos < 1 ? 0 : pos - 1; gap < absabmaxgap; ++gap) {
			// Differential positions: (diffpos - gap - 2, diffpos - gap - 1) ^ (diffpos, diffpos + 1)
			currdiff++;
		}

		// Right
		for (unsigned gap = pos >= cookielen ? 0 : cookielen - pos - 1; gap < absabmaxgap; ++gap) {
			// Differential positions: (diffpos, diffpos + 1) ^ (diffpos + gap + 2, diffpos + gap + 3)
			currdiff++;
		}
	}

	return currdiff;
}

