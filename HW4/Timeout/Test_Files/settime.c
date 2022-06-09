#include <time.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

int main() {
	struct timespec tc;
	struct timespec* tpc = &tc;

	clock_gettime(CLOCK_REALTIME, tpc);
	printf("Now   = %ld\n", tc.tv_sec);
	
	long tmp = tc.tv_sec;
	tmp = tmp + 4294967295;
	
	printf("%ld -> %ld\n", tc.tv_sec, tmp);
	
	tc.tv_sec  = (time_t) tmp;
	tc.tv_nsec = 0;

	struct timeval delta, olddelta;
	const struct timeval* ptr_delta = &delta;
	struct timeval* ptr_old_delta = &olddelta;

    // delta.tv_sec = 4294967295;
    delta.tv_sec = 200;
	delta.tv_usec = 0;
	
	olddelta.tv_sec  = 0;
	olddelta.tv_usec = 0;


	int ret = adjtime(ptr_delta, ptr_old_delta);
	if (!ret)
		printf("Adjust success!\n");
	else
		printf("Error!\n");

	// sleep(3);
	clock_settime(CLOCK_REALTIME, tpc);	

	clock_gettime(CLOCK_REALTIME, tpc);
	printf("After = %ld\n", tc.tv_sec);
	return 0;
}
