#include <Python.h>
#include <stdint.h>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#include <numpy/arrayobject.h>

#include "util.h"
#include "brutecookie.h"

// ================================ PYTHON BINDINGS ================================ 

static PyMethodDef modmethods[] = {
	METHOD_ENTRY(brutecookie, "Bruteforce the cookie based on a given candidate list"),

	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initbruter(void)
{
	import_array();

	/** init C functions */
	Py_InitModule("bruter", modmethods);
}


