#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <utime.h>

int main(void)
{
	struct stat sb;
	char buf[40];
	int fd;

	chdir("mnt");
	fd = open("foo", O_RDWR | O_CREAT | O_TRUNC, 0640);
	fchmod(fd, 0660);
	chmod("foo", 0640);
	fchown(fd, 1, 1);
	chown("foo", 0, 0);
	stat("foo", &sb);
	fstat(fd, &sb);
	ftruncate(fd, 0);
	truncate("foo", 0);
	mkdir("bar", 0700);
	symlink("bar", "baz");
	rename("baz", "bazzzz");
	rmdir("bar");
	utimes("bazzzz", (struct timeval [2]){{0,0},{0,0}});
	write(fd, "Hello World", 2*5+1);
	lseek(fd, 0, 0);
	read(fd, buf, 40);
	printf(">>%s<<\n", buf);
	return 0;
}
