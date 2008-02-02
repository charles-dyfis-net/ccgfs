#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
	while (*++argv != NULL)
		open(*argv, O_RDWR);
	while (1)
		sleep(60000);
}
