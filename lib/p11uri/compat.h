#include <sys/types.h>
#include <prtypes.h>
#include "seccomon.h"

#include "rename.h"

#undef CRYPTOKI_GNU
#define P11_KIT_DISABLE_DEPRECATED

#undef bool
#define bool PRBool

#undef true
#define true PR_TRUE

#undef false
#define false PR_FALSE

#undef malloc
#define malloc PORT_Alloc

#undef realloc
#define realloc PORT_Realloc

#undef calloc
#define calloc(nmemb,size) PORT_ZAlloc((nmemb) * (size))

#undef free
#define free PORT_Free

#undef strdup
#define strdup PORT_Strdup

#undef memdup
#define memdup p11_memdup

#undef assert
#define assert PORT_Assert

SEC_BEGIN_PROTOS

void *memdup(const void *data, size_t length);
size_t p11_kit_space_strlen (const unsigned char *string, size_t max_length);

SEC_END_PROTOS
