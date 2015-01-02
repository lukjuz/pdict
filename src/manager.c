#define _GNU_SOURCE

#include "manager.h"
#include "reader.h"
#include "comparer.h"
#include "thread_data.h"

#include <stdio.h>      	/* printf, NULL */
#include <stdlib.h>     	/* malloc, free */
#include <sys/syscall.h>

int timespec_subtract(x, y, result) // time subtract
	struct timespec *result, *x, *y;
	{
	if (x->tv_nsec < y->tv_nsec) { /* Perform the carry for the later subtraction by updating y. */
		int nsec = (y->tv_nsec - x->tv_nsec) / 1000000 + 1;
		y->tv_nsec -= 1000000 * nsec;
 		y->tv_sec += nsec;
	}
	if (x->tv_nsec - y->tv_nsec > 1000000) {
		int nsec = (x->tv_nsec - y->tv_nsec) / 1000000;
 		y->tv_nsec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}
	result->tv_sec = x->tv_sec - y->tv_sec;    /* Compute the time remaining to wait. */
	result->tv_nsec = x->tv_nsec - y->tv_nsec; /* tv_usec is certainly positive. */
	return x->tv_sec < y->tv_sec; /* Return 1 if result is negative. */
}

void *thread_manager(void *t_data) { // workers number thread manager
	int rc, change_flag = 1, decision_flag; //change_flag trzyma informacje czy dodano, czy odjeto watek
	long t, comparers_created, old_pass_counter_value;
	double ratio = 1, pass_per_sec = 1, new_pass_per_sec;
	t = comparers_created = old_pass_counter_value = decision_flag = new_pass_per_sec = 0;
	struct timespec tsold, tsnew, tsres;
	struct thread_data *m_data = (struct thread_data *) t_data;
	struct thread_data *thread_data_array = malloc(LIM_THREADS * sizeof(struct thread_data));	
	pthread_t *call_thread = calloc(LIM_THREADS, sizeof(pthread_t)); // malloc z zerami
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_mutex_init(&mtx_reader, NULL);	
	pthread_mutex_init(&mtx_comparer_hold, NULL);	
	pthread_mutex_init(&mtx_manager, NULL);
	pthread_cond_init(&cnd_r_pass, NULL);
	pthread_cond_init(&cnd_p_pass, NULL);
	pthread_cond_init(&hold_breaker, NULL);
	pthread_cond_init(&changed_num_threads, NULL);
	pthread_rwlock_init(&pass_lock, NULL);
	pthread_rwlock_init(&c_proc_lock, NULL);
	pthread_rwlock_init(&c_read_lock, NULL);
	pthread_rwlock_init(&settings_lock, NULL);
	if (m_data->verbose > 1) printf("Manager(%ld): creating reader thread %ld\n", syscall(SYS_gettid), t);
	thread_data_array[t].verbose = m_data->verbose;	
	rc = pthread_create(&call_thread[t], &attr, dictionary_reader, (void *) &thread_data_array[t]);
	if (rc) {
		printf("ERROR; return code from pthread_create() is %d\n", rc);
		pthread_exit((void*) t);
	}
	t = 1;
	comparers_created = 0;
	clock_gettime(CLOCK_REALTIME, &tsold);
	pthread_rwlock_rdlock(&pass_lock);
	while (shared_data.password == NULL) {
		pthread_rwlock_unlock(&pass_lock);
		while (t < MIN_THREADS) {
			if (comparers_created < t) {
				if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
				thread_data_array[t].thread_id = t;
				thread_data_array[t].spassword = m_data->spassword;
				thread_data_array[t].verbose = m_data->verbose;
				thread_data_array[t].c_data = malloc(sizeof(struct crypt_data));
				pthread_mutex_lock(&mtx_manager);
				rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
				if (rc != 0)
					printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
				else {
					t++;
					shared_data.num_threads = t;
					pthread_cond_wait(&changed_num_threads, &mtx_manager);
					comparers_created++;
				}
				pthread_mutex_unlock(&mtx_manager);
			} else { //budzenie watkow			
				if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
				t++;
				pthread_mutex_lock(&mtx_comparer_hold);
				pthread_mutex_lock(&mtx_manager);
				shared_data.num_threads = t;
				pthread_cond_signal(&hold_breaker);
				pthread_mutex_unlock(&mtx_comparer_hold);
				pthread_cond_wait(&changed_num_threads, &mtx_manager);
				pthread_mutex_unlock(&mtx_manager);
			}				
			decision_flag = 0;
			change_flag = 1;
		}
		while (t > MAX_THREADS) {
			t--;	
			if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);										
			pthread_mutex_lock(&mtx_manager);
			shared_data.num_threads = t;
			pthread_cond_wait(&changed_num_threads, &mtx_manager);
			pthread_mutex_unlock(&mtx_manager);
			decision_flag = change_flag = 0;
		}	
		if (ratio > 1.05) { 
			if (change_flag == 1 && t < MAX_THREADS) {		
				if (comparers_created < t) {
					if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
					thread_data_array[t].thread_id = t;
					thread_data_array[t].spassword = m_data->spassword;
					thread_data_array[t].verbose = m_data->verbose;
					thread_data_array[t].c_data = malloc(sizeof(struct crypt_data));
					pthread_mutex_lock(&mtx_manager);
					rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
					if (rc != 0)
						printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
					else {
						t++;
						shared_data.num_threads = t;
						pthread_cond_wait(&changed_num_threads, &mtx_manager);
						comparers_created++;
					}
					pthread_mutex_unlock(&mtx_manager);
				} else { //budzenie watkow			
					if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
					t++;
					pthread_mutex_lock(&mtx_comparer_hold);
					pthread_mutex_lock(&mtx_manager);
					shared_data.num_threads = t;
					pthread_cond_signal(&hold_breaker);
					pthread_mutex_unlock(&mtx_comparer_hold);
					pthread_cond_wait(&changed_num_threads, &mtx_manager);
					pthread_mutex_unlock(&mtx_manager);
				}				
				decision_flag = 0;
				change_flag = 1;
			} else if (change_flag == 0 && t > MIN_THREADS) {
				t--;	
				if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);										
				pthread_mutex_lock(&mtx_manager);
				shared_data.num_threads = t;
				pthread_cond_wait(&changed_num_threads, &mtx_manager);
				pthread_mutex_unlock(&mtx_manager);
				decision_flag = change_flag = 0;
			} else change_flag = !change_flag; // brzegowy, aby nie utknac na 1 lub max watkow
		} else if (ratio < 0.95) {
			if (change_flag == 1 && t > MIN_THREADS) {			
				t--;
				if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);			
				pthread_mutex_lock(&mtx_manager);
				shared_data.num_threads = t;
				pthread_cond_wait(&changed_num_threads, &mtx_manager);
				pthread_mutex_unlock(&mtx_manager);
				decision_flag = change_flag = 0;
			} else if (change_flag == 0 && t < MAX_THREADS) {
				if (comparers_created < t) {
					if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
					thread_data_array[t].thread_id = t;
					thread_data_array[t].spassword = m_data->spassword;
					thread_data_array[t].verbose = m_data->verbose;
					thread_data_array[t].c_data = malloc(sizeof(struct crypt_data));
					pthread_mutex_lock(&mtx_manager);
					rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
					if (rc != 0)
						printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
					else {
						t++;
						shared_data.num_threads = t;
						pthread_cond_wait(&changed_num_threads, &mtx_manager);
						comparers_created++;
					}
					pthread_mutex_unlock(&mtx_manager);
				} else { //budzenie watkow			
					if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
					t++;
					pthread_mutex_lock(&mtx_comparer_hold);
					pthread_mutex_lock(&mtx_manager);
					shared_data.num_threads = t;
					pthread_cond_signal(&hold_breaker);
					pthread_mutex_unlock(&mtx_comparer_hold);
					pthread_cond_wait(&changed_num_threads, &mtx_manager);
					pthread_mutex_unlock(&mtx_manager);
				}				
				decision_flag = 0;
				change_flag = 1;
			} else change_flag = !change_flag; // brzegowy, aby nie utknac na 1 lub max watkow
		} else { // wymus zmiane liczby watkow w celu proby podniesienia wydajnosci
			(ratio > 1.0) ? decision_flag++ : decision_flag--;
			if (decision_flag > 10) {
				if (change_flag == 1 && t < MAX_THREADS) {
					if (comparers_created < t) {
						if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
						thread_data_array[t].thread_id = t;
						thread_data_array[t].spassword = m_data->spassword;
						thread_data_array[t].verbose = m_data->verbose;
						thread_data_array[t].c_data = malloc(sizeof(struct crypt_data));
						pthread_mutex_lock(&mtx_manager);
						rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
						if (rc != 0)
							printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
						else {
							t++;
							shared_data.num_threads = t;
							pthread_cond_wait(&changed_num_threads, &mtx_manager);
							comparers_created++;
						}
						pthread_mutex_unlock(&mtx_manager);
					} else { //budzenie watkow			
						if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
						t++;
						pthread_mutex_lock(&mtx_comparer_hold);
						pthread_mutex_lock(&mtx_manager);
						shared_data.num_threads = t;
						pthread_cond_signal(&hold_breaker);
						pthread_mutex_unlock(&mtx_comparer_hold);
						pthread_cond_wait(&changed_num_threads, &mtx_manager);
						pthread_mutex_unlock(&mtx_manager);
					}				
					decision_flag = 0;
					change_flag = 1;				
				} else if (change_flag == 0 && t > MIN_THREADS) {					
					t--;
					if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);			
					pthread_mutex_lock(&mtx_manager);
					shared_data.num_threads = t;
					pthread_cond_wait(&changed_num_threads, &mtx_manager);
					pthread_mutex_unlock(&mtx_manager);
					decision_flag = change_flag = 0;
				} else change_flag = !change_flag; // brzegowy, aby nie utknac na 1 lub max watkow		
			} else if (decision_flag < -10) {
				if (change_flag == 1 && t > MIN_THREADS) {
					t--;					
					if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);						
					pthread_mutex_lock(&mtx_manager);
					shared_data.num_threads = t;
					pthread_cond_wait(&changed_num_threads, &mtx_manager);
					pthread_mutex_unlock(&mtx_manager);
					decision_flag = change_flag = 0;
				} else if (change_flag == 0 && t < MAX_THREADS) {
					if (comparers_created < t) {
						if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
						thread_data_array[t].thread_id = t;
						thread_data_array[t].spassword = m_data->spassword;
						thread_data_array[t].verbose = m_data->verbose;
						thread_data_array[t].c_data = malloc(sizeof(struct crypt_data));
						pthread_mutex_lock(&mtx_manager);
						rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
						if (rc != 0)
							printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
						else {
							t++;
							shared_data.num_threads = t;
							pthread_cond_wait(&changed_num_threads, &mtx_manager);
							comparers_created++;
						}
						pthread_mutex_unlock(&mtx_manager);
					} else { //budzenie watkow			
						if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
						t++;
						pthread_mutex_lock(&mtx_manager);
						pthread_mutex_lock(&mtx_comparer_hold);						
						shared_data.num_threads = t;
						pthread_cond_signal(&hold_breaker);
						pthread_mutex_unlock(&mtx_comparer_hold);
						pthread_cond_wait(&changed_num_threads, &mtx_manager);
						pthread_mutex_unlock(&mtx_manager);
					}				
					decision_flag = 0;
					change_flag = 1;
				} else change_flag = !change_flag; // brzegowy, aby nie utknac na 1 lub max watkow		
			} 	
		}
		pass_per_sec = new_pass_per_sec;	
		clock_gettime(CLOCK_REALTIME, &tsold);
		tsnew.tv_sec = tsold.tv_sec + 1;
		tsnew.tv_nsec = tsold.tv_nsec;
		pthread_mutex_lock(&mtx_comparer);
		pthread_cond_timedwait(&done, &mtx_comparer, &tsnew);
		pthread_mutex_unlock(&mtx_comparer);
		clock_gettime(CLOCK_REALTIME, &tsnew);
		timespec_subtract(&tsnew, &tsold, &tsres);
		tsold = tsnew;
		pthread_rwlock_rdlock(&c_proc_lock);
		new_pass_per_sec = ((double) shared_data.pass_proced_c - (double) old_pass_counter_value) / ((double) tsres.tv_sec + (double) tsres.tv_nsec / 1000000000);
		old_pass_counter_value = shared_data.pass_proced_c;
		pthread_rwlock_unlock(&c_proc_lock);
		timespec_subtract(&tsnew, &tsold, &tsres);
		ratio = new_pass_per_sec / pass_per_sec;
		pthread_rwlock_rdlock(&settings_lock);
		if ( shared_data.verbose != m_data->verbose ) {
			m_data->verbose = shared_data.verbose;
			int i = 0;
			for ( i = 0; i < LIM_THREADS && call_thread[i] != 0; i++)
				thread_data_array[i].verbose = m_data->verbose;
		}
		pthread_rwlock_unlock(&settings_lock);
		if (m_data->verbose > 0) {
			pthread_rwlock_rdlock(&c_proc_lock);
			pthread_rwlock_rdlock(&c_read_lock);
			printf("Comparers: %ld (%ld)  Pps: %lf  Ratio: %lf  PRead: %ld  PProc: %ld\n", t - 1, comparers_created, new_pass_per_sec, ratio, shared_data.pass_read_c, old_pass_counter_value);
			pthread_rwlock_unlock(&c_read_lock);			
			pthread_rwlock_unlock(&c_proc_lock);																		
		}
		pthread_rwlock_rdlock(&pass_lock);
	}
	pthread_mutex_lock(&mtx_comparer_hold);	
	pthread_cond_broadcast(&hold_breaker);
	pthread_mutex_unlock(&mtx_comparer_hold);
	pthread_rwlock_unlock(&pass_lock);
	pthread_mutex_lock(&mtx_reader);
	pthread_cond_signal(&cnd_r_pass); // odblokowanie readera, aby mogl zakonczyc dzialanie
	pthread_cond_broadcast(&cnd_p_pass);
	pthread_mutex_unlock(&mtx_reader);
	void *res;	
	for (t = 0; t < LIM_THREADS; t++)
		if (call_thread[t] != 0)
			pthread_join(call_thread[t], &res);
		else
			break;
	free(thread_data_array);
	free(call_thread);
	if (m_data->verbose > 1) printf("Manager: exiting!\n");
	pthread_attr_destroy(&attr);
	pthread_exit(NULL);
}
