#include "secport.h"

#define return_val_if_fail(x, v) PORT_Assert(x)

#define return_if_fail(x) PORT_Assert(x)

#define return_if_reached() PORT_Assert(PR_FALSE)

#define return_val_if_reached(v) PORT_Assert(PR_FALSE)
