#include <time.h>
#include <stdio.h>

int main() {
	struct timespec tc;
	struct timespec* tpc = &tc;

	clock_gettime(CLOCK_REALTIME, tpc);
	printf("Now   = %ld\n", tc.tv_sec);
	
	long tmp = tc.tv_sec;
	tmp = 1000000;
	
	tc.tv_sec  = (time_t) tmp;
	tc.tv_nsec = 0;

	clock_settime(CLOCK_REALTIME, tpc);	

	clock_gettime(CLOCK_REALTIME, tpc);
	printf("Reset = %ld\n", tc.tv_sec);
	return 0;
}
