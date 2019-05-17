#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <sys/ioctl.h>

#include "helloWorld.h"

#define HELLO_WORLD_DEV "/dev/hello"

int main(int argc, char * argv[])
{
	int fd = open(HELLO_WORLD_DEV, O_RDWR);
	if(fd < 0)
	{
		printf("open (%s) failed\n", HELLO_WORLD_DEV);
		return -1;
	}
	
	char buff[16] = {0};
	
	ioctl(fd, HELLO_WORLD_TEST, buff);
	printf("readValue=%s\n", buff);
	
	close(fd);
	
	return 0;
}