#ifndef _CCGFS_H
#define _CCGFS_H 1

#include <sys/types.h>
#include <stdint.h>
#include "config.h"

/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x, y) ({		\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void)(&_x == &_y);	\
	(_x < _y) ? _x : _y; })

#define max(x, y) ({		\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void)(&_x == &_y);	\
	(_x > _y) ? _x : _y;	\
})

#ifdef PKTSWAP
static inline uint32_t swap32(uint32_t x)
{
	return ((x & 0x000000FF) << 24) |
	       ((x & 0x0000FF00) << 8) |
	       ((x & 0x00FF0000) >> 8) |
	       ((x & 0xFF000000) >> 24);
}
static inline uint64_t swap64(uint64_t x)
{
	return ((uint64_t)swap32(x & 0xFFFFFFFF) << 32) |
	       (swap32(x >> 32) & 0xFFFFFFFF);
}
#	define le32_to_cpu(x) swap32(x)
#	define le64_to_cpu(x) swap64(x)
#	define cpu_to_le32(x) swap32(x)
#	define cpu_to_le64(x) swap64(x)
#else
#	define le32_to_cpu(x) (x)
#	define le64_to_cpu(x) (x)
#	define cpu_to_le32(x) (x)
#	define cpu_to_le64(x) (x)
#endif

#endif /* _CCGFS_H */
