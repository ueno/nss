/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef NSS_USE_DTRACE_PROBES

#undef NSS_HAS_PROBES
#define NSS_HAS_PROBES 1

#include "sslprobes_generated.h"

#define PROBE(x) x

#else

#define PROBE(x)

#endif
