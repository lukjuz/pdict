#define _GNU_SOURCE

#include "comparer.h"
#include "thread_data.h"

#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <crypt.h>			/* crypt_r */
#include <unistd.h>			/* syscall */

void *password_comparer(void *thread_arg) { // hash generator and comparer
	struct thread_data *t_data;
	struct crypt_data *c_data; // = malloc(sizeof(struct crypt_data));
	int comp_len, i;
	ssize_t read = 0;
	char *password, *result;
	pid_t tid = syscall(SYS_gettid);
	t_data = (struct thread_data *) thread_arg;
	c_data = t_data->c_data;
	c_data->initialized = 0;
   	if (t_data->verbose > 1) printf("Comparer#%ld(%d): starting!\n", t_data->thread_id, tid);
	pthread_mutex_lock(&mtx_manager);
	pthread_cond_signal(&changed_num_threads);
	pthread_mutex_unlock(&mtx_manager);
	pthread_rwlock_rdlock(&pass_lock);
	while (shared_data.password == NULL) {
		pthread_rwlock_unlock(&pass_lock);
		pthread_mutex_lock(&mtx_reader);
		while (shared_data.line == NULL) {
			pthread_cond_signal(&cnd_r_pass);
			pthread_cond_wait(&cnd_p_pass, &mtx_reader);
			pthread_rwlock_rdlock(&pass_lock);
			if (shared_data.password != NULL) {
				pthread_mutex_unlock(&mtx_reader);	
				goto exit; // double loop exit
			}
			pthread_rwlock_unlock(&pass_lock);
		}
		pthread_mutex_lock(&mtx_manager);
		if (shared_data.num_threads > t_data->thread_id) {
			pthread_mutex_unlock(&mtx_manager);
			password = shared_data.line;
			read = shared_data.read;
			shared_data.line = NULL;
			pthread_cond_signal(&cnd_r_pass);
			pthread_mutex_unlock(&mtx_reader);	
			password[read - 1] = '\0';
			if (t_data->verbose > 2) printf("Comparer#%ld: %s\n", t_data->thread_id, password);
			result = crypt_r(password, t_data->spassword, c_data); /* malloc(sizeof(char)); */
			for (i = 0, comp_len = 0; result[i] == t_data->spassword[i]; i++)
				if (result[i] == '\0') //sprawdz czy podane haslo jest takie samo jak w pliku.		
					comp_len = 1;				
			if (comp_len) {	
				pthread_rwlock_wrlock(&pass_lock);		
				shared_data.password = password;
				for (comp_len = 0; result[comp_len] != '\0'; comp_len++);
				shared_data.hash = malloc((comp_len + 1) * sizeof(char));		
				for (i = 0; i < comp_len+1; i++)
					shared_data.hash[i] = result[i];
				pthread_rwlock_unlock(&pass_lock);
				pthread_mutex_lock(&mtx_comparer);
				pthread_cond_broadcast(&done);
				pthread_mutex_unlock(&mtx_comparer);	
			} else free(password);
			pthread_rwlock_wrlock(&c_proc_lock);
			shared_data.pass_proced_c++;
			pthread_rwlock_unlock(&c_proc_lock);
		} else {
			pthread_mutex_unlock(&mtx_reader);
			if (t_data->verbose > 1) printf("Comparer#%ld(%d): holding!\n", t_data->thread_id, tid);
			pthread_cond_signal(&changed_num_threads);		
			pthread_mutex_unlock(&mtx_manager);
			pthread_mutex_lock(&mtx_comparer_hold);
			pthread_cond_wait(&hold_breaker, &mtx_comparer_hold);
			pthread_mutex_unlock(&mtx_comparer_hold);
			pthread_mutex_lock(&mtx_manager);	
			t_data->thread_id = shared_data.num_threads - 1; // przyjmij nowe ID
			if (t_data->verbose > 1) printf("Comparer#%ld(%d): waking up!\n", t_data->thread_id, tid);
			pthread_cond_signal(&changed_num_threads);
			pthread_mutex_unlock(&mtx_manager);		
		}
		pthread_rwlock_rdlock(&pass_lock);
	}	
	exit:
	pthread_rwlock_unlock(&pass_lock);
	pthread_mutex_lock(&mtx_manager);
	pthread_cond_signal(&changed_num_threads);
	pthread_mutex_unlock(&mtx_manager);	
	if (t_data->verbose > 1) printf("Comparer#%ld(%d): exiting!\n", t_data->thread_id, tid); // num moga sie powtarzac! co jest mylace!
	free(c_data);  	
	pthread_exit(NULL);
}
