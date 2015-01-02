#ifndef __THREAD_DATA_H
#define __THREAD_DATA_H

#include <pthread.h>
#include <sys/types.h>
#include <crypt.h>			/* crypt_data */

extern int LIM_THREADS; // upper limit of threads ( 1 reader, 99 comparers)

extern int MAX_THREADS;	// maximum number of threads
extern int MIN_THREADS;	// minimum number of threads

typedef struct {
	char *password, *hash, *line, *dict_path; // protected by pass_lock, mtx_reader
	ssize_t read; 		// number of char's read by reader - protected by mtx_reader
	long pass_read_c; 	// counter of password read by reader - protected by mtx_reader
	long pass_proced_c; // counter of password proceed by comparer - protected by mtx_comparer
	long num_threads;	// number of active threads - protected by mtx_manager
	int verbose;		// verbose mode - protected by settings_lock
} SHARED_DATA;

struct thread_data {
	long  thread_id;	// thread ID
	char *spassword;	// comparer's local copy of password's hash he is looking for 
	int verbose;		// TODO settings_lock in manager
	struct crypt_data *c_data;
};

SHARED_DATA shared_data;
pthread_mutex_t  mtx_reader;			// mutex to signal need of another word to compare
pthread_mutex_t  mtx_comparer;		// mutex to signal accomplishment of password searching
pthread_mutex_t  mtx_comparer_hold; 	// mutex to signal need of change comparer's state
pthread_mutex_t  mtx_manager;		// mutex to block manager until change of comparer's state
pthread_cond_t 	 cnd_r_pass;		// condition to indicate need of next word to compare
pthread_cond_t   cnd_p_pass;			// condition to indicate readness of another word to compare
pthread_cond_t   hold_breaker;		// condition to block comparers
pthread_cond_t   changed_num_threads;// condition to block thread until accomplishment of comparer state changes
pthread_cond_t   done;				// condition to block thread until accomplishment of password searching
pthread_rwlock_t pass_lock;			// lock for shared:password
pthread_rwlock_t c_proc_lock;		// lock for shared:pass_proced_c
pthread_rwlock_t c_read_lock;		// lock for shared:pass_read_c
pthread_rwlock_t settings_lock; 		// lock for shared:verbose, shared:min_max_threads

#endif
