#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

int main() {
	
	struct timeval delta, olddelta;
	const struct timeval* ptr_delta = &delta;
	struct timeval* ptr_old_delta = &olddelta;

    delta.tv_sec = 4294967295;
	delta.tv_usec = 0;
	
	olddelta.tv_sec  = 0;
	olddelta.tv_usec = 0;


	int ret = adjtime(ptr_delta, ptr_old_delta);
	
	printf("%ld, %ld\n", olddelta.tv_sec, olddelta.tv_usec);
	if (ret)
		printf("Adjust success!\n");
	else
		printf("Error!\n");

	sleep(1);

	return 0;
}
