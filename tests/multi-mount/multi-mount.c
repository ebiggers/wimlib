#include <wimlib.h>
#include <assert.h>
#include <omp.h>

int main(int argc, char **argv)
{
	int ret;
	WIMStruct *w1;
	WIMStruct *w2;

	assert(argc == 5);
	ret = wimlib_open_wim(argv[1], 0, &w1, NULL);
	assert(ret == 0);

	ret = wimlib_open_wim(argv[2], 0, &w2, NULL);
	assert(ret == 0);

	#pragma omp parallel num_threads(2)
	{
		int ret;
		assert(omp_get_num_threads() == 2);
		if (omp_get_thread_num() == 0) {
			ret = wimlib_mount_image(w1, 1, argv[3],
						 WIMLIB_MOUNT_FLAG_DEBUG, NULL);
		} else {
			ret = wimlib_mount_image(w2, 1, argv[4],
						 WIMLIB_MOUNT_FLAG_DEBUG, NULL);
		}
		assert(ret == 0);
	}
	return 0;
}
