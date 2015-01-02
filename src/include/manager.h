#ifndef __MANAGER_H
#define __MANAGER_H

#include <sys/time.h>		/* gettimeofday */
#include <unistd.h>

int timespec_subtract(struct timespec *x, struct timespec *y, struct timespec *result);

void *thread_manager(void *t_data); // password reader from dictionry

#endif
