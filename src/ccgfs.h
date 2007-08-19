#ifndef _CCGFS_H
#define _CCGFS_H 1

#include <sys/types.h>
#include <stdint.h>

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

#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)

#define reinterpret_cast(type, x) ((type)(x))
#define static_cast(type, x)      ((type)(x))

#endif /* _CCGFS_H */
