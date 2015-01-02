#include "reader.h"
#include "thread_data.h"

#include <stdio.h>      	/* printf, NULL */
#include <stdlib.h>     	/* malloc, free */
#include <unistd.h>	
#include <sys/syscall.h>

void *dictionary_reader(void *thread_arg) { // password reader from dictionry
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read = -1;
	struct timespec ts;
	struct thread_data *t_data = (struct thread_data *) thread_arg;
	if (t_data->verbose > 1) printf("Reader(%ld): starting!\n", syscall(SYS_gettid));
	fp = fopen(shared_data.dict_path,"r"); //otworz plik slownika
	if (!fp) // sprawdz czy plik zostal otworzony prawidlowo
		printf("\nReader: Failed to open dictionary. Path: %s\n", shared_data.dict_path);
	else
		read = getline(&line, &len, fp);
	pthread_rwlock_wrlock(&c_proc_lock);
	pthread_rwlock_wrlock(&c_read_lock);
	shared_data.pass_read_c = shared_data.pass_proced_c = 0;
	pthread_rwlock_unlock(&c_read_lock);
	pthread_rwlock_unlock(&c_proc_lock);
	pthread_rwlock_rdlock(&pass_lock);
	while (read > -1 && shared_data.password == NULL) { //odczytaj linie ze slownika
		pthread_rwlock_unlock(&pass_lock);			
		if (t_data->verbose > 2) printf("Reader: %s", line);
		pthread_rwlock_wrlock(&c_read_lock);
		shared_data.pass_read_c++;
		pthread_rwlock_unlock(&c_read_lock);
		pthread_mutex_lock(&mtx_reader);
		while (shared_data.line != NULL) {
			pthread_cond_signal(&cnd_p_pass);		
			pthread_cond_wait(&cnd_r_pass, &mtx_reader);
			pthread_rwlock_rdlock(&pass_lock);
			if (shared_data.password != NULL) {
				pthread_mutex_unlock(&mtx_reader);	
				goto exit;
			}
			pthread_rwlock_unlock(&pass_lock);		
		}
		shared_data.line = line;
		shared_data.read = read;
		line = NULL;
		pthread_cond_signal(&cnd_p_pass);	//WTF
		pthread_mutex_unlock(&mtx_reader);
		len = 0;
		read = getline(&line, &len, fp);
		pthread_rwlock_rdlock(&pass_lock);
	}
	exit:
	pthread_rwlock_rdlock(&c_proc_lock);
	pthread_rwlock_rdlock(&c_read_lock);
	while (shared_data.password == NULL && shared_data.pass_read_c != shared_data.pass_proced_c) {
		if (t_data->verbose > 2) printf("Reader: waiting for comparers!\n");
		pthread_rwlock_unlock(&c_read_lock);
		pthread_rwlock_unlock(&c_proc_lock);		
		pthread_rwlock_unlock(&pass_lock);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
		pthread_mutex_lock(&mtx_reader);
		pthread_cond_broadcast(&cnd_p_pass);
		pthread_cond_timedwait(&cnd_r_pass, &mtx_reader, &ts);
		pthread_mutex_unlock(&mtx_reader);
		pthread_rwlock_rdlock(&pass_lock);
		pthread_rwlock_rdlock(&c_proc_lock);
		pthread_rwlock_rdlock(&c_read_lock);
	}
	pthread_rwlock_unlock(&c_read_lock);
	pthread_rwlock_unlock(&c_proc_lock);
	pthread_rwlock_unlock(&pass_lock);	
	if (fp != NULL) fclose(fp);
	free(line);
	if (read == -1) {
		pthread_rwlock_wrlock(&pass_lock);
		shared_data.password = "";
		pthread_rwlock_unlock(&pass_lock);
	}
	pthread_mutex_lock(&mtx_comparer);
	pthread_cond_broadcast(&done);
	pthread_mutex_unlock(&mtx_comparer);
	if (t_data->verbose > 1) printf("Reader: exiting!\n");	
	pthread_exit(NULL);
}
