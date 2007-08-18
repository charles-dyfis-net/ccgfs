#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
	while (*++argv != NULL)
		open(*argv, O_RDWR);
	while (true)
		sleep(60000);
}
