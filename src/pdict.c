/* 
wielowatkowe czytanie hasel z /etc/shadow
kompilacja: gcc -lcrypt -pthread -Ofast -o pdict pdict.c
*/
#ifdef _REENTRANT
#endif
#define _GNU_SOURCE

#include <stdio.h>      	/* printf, NULL */
#include <stdlib.h>     	/* malloc, free */
#include <pthread.h>		/* pthread_* */
#include <sys/syscall.h>	/* syscall */
#include <sys/time.h>		/* gettimeofday */
#include <sys/types.h>		/* uid_t, setuid */
#include <unistd.h>			/* syscall */
#include <shadow.h> 		/* getspnam */
#include <crypt.h>			/* crypt_r */
#include <pwd.h>
#include <grp.h>
#include <signal.h>			/* signal */

#define MAX_THREADS     100

typedef struct {
	char *password, *hash, *line, *dict_path; // mutex_breaker, mutex_breaker, mutex_reader
	ssize_t read; // mutex_reader
	long pass_read_c; // licznik hasel odczytanych przez reader'a. mutex_reader
	long pass_proced_c; // licznik danych przetworzonych przez comparery. mutex_breaker
	long num_threads; // mutex_manager
} SHARED_DATA;

struct thread_data {
	long  thread_id;
	char *spassword;
	int verbose;
};

SHARED_DATA shared_data;
pthread_mutex_t  mutex_reader;
pthread_mutex_t  mutex_breaker;
pthread_mutex_t  mutex_breaker_hold;
pthread_mutex_t  mutex_manager;
pthread_cond_t 	 read_pass;
pthread_cond_t   proc_pass; // TODO optymalizacja pod wzgledem ilosci warunkow
pthread_cond_t   hold_breaker;
pthread_cond_t   changed_num_threads;
pthread_cond_t   done;
pthread_rwlock_t pass_lock;
pthread_rwlock_t c_proc_lock; // rwlock dla pass_proced_c
pthread_rwlock_t c_read_lock;

int timespec_subtract(x, y, result)
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

void *password_comparer(void *thread_arg) {
	struct thread_data *t_data;
	struct crypt_data *c_data = malloc(sizeof(struct crypt_data));
	c_data->initialized = 0;
	int comp_len, i;
	ssize_t read = 0;
	char *password, *result;
	t_data = (struct thread_data *) thread_arg;
   	if (t_data->verbose > 1) printf("Comparer#%ld(%ld): starting!\n", t_data->thread_id, syscall(SYS_gettid));
	pthread_mutex_lock(&mutex_manager);
	pthread_cond_signal(&changed_num_threads);
	pthread_mutex_unlock(&mutex_manager);
	pthread_rwlock_rdlock(&pass_lock);
	while (shared_data.password == NULL) {
		pthread_rwlock_unlock(&pass_lock);
		pthread_mutex_lock(&mutex_reader);
		while (shared_data.line == NULL) {
			pthread_cond_signal(&read_pass);
			pthread_cond_wait(&proc_pass, &mutex_reader);
			pthread_rwlock_rdlock(&pass_lock);
			if (shared_data.password != NULL) {
				pthread_mutex_unlock(&mutex_reader);	
				goto exit; // double loop exit
			}
			pthread_rwlock_unlock(&pass_lock);
		}
		pthread_mutex_lock(&mutex_manager);
		if (shared_data.num_threads > t_data->thread_id) {
			pthread_mutex_unlock(&mutex_manager);
			password = shared_data.line;
			read = shared_data.read;
			shared_data.line = NULL;
			pthread_cond_signal(&read_pass);
			pthread_mutex_unlock(&mutex_reader);	
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
				pthread_mutex_lock(&mutex_breaker);
				pthread_cond_broadcast(&done);
				pthread_mutex_unlock(&mutex_breaker);	
			} else free(password);
			pthread_rwlock_wrlock(&c_proc_lock);
			shared_data.pass_proced_c++;
			pthread_rwlock_unlock(&c_proc_lock);
		} else {
			pthread_mutex_unlock(&mutex_reader);
			if (t_data->verbose > 1) printf("Comparer#%ld: holding!\n", t_data->thread_id);
			pthread_cond_signal(&changed_num_threads);
			pthread_mutex_unlock(&mutex_manager);
			pthread_mutex_lock(&mutex_breaker_hold);
			pthread_cond_wait(&hold_breaker, &mutex_breaker_hold);
			pthread_mutex_unlock(&mutex_breaker_hold);
			pthread_mutex_lock(&mutex_manager);	
			if (shared_data.num_threads - 1 != t_data->thread_id && shared_data.num_threads != 0)
				t_data->thread_id = shared_data.num_threads - 1; // przyjmij nowe ID
			if (t_data->verbose > 1) printf("Comparer#%ld: waking up!\n", t_data->thread_id);
			pthread_cond_signal(&changed_num_threads);
			pthread_mutex_unlock(&mutex_manager);		
		}
		pthread_rwlock_rdlock(&pass_lock);
	}	
	exit:
	pthread_rwlock_unlock(&pass_lock);
	pthread_mutex_lock(&mutex_manager);
	pthread_cond_signal(&changed_num_threads);
	pthread_mutex_unlock(&mutex_manager);	
	if (t_data->verbose > 1) printf("Comparer#%ld: exiting!\n", t_data->thread_id); // ID moga sie powtarzac! co jest mylace!
	free(c_data);  	
	pthread_exit(NULL);
}

void *dictionary_reader(void *thread_arg) {
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read = -1;
	struct timespec ts;
	struct thread_data *t_data = (struct thread_data *) thread_arg;
	if (t_data->verbose > 1) printf("Reader(%ld): starting!\n", syscall(SYS_gettid));
	fp = fopen(shared_data.dict_path,"r"); //otworz plik slownika
	if (!fp) // sprawdz czy plik zostal otworzony prawidlowo
		printf("Reader: Failed to open dictionary. Path: %s\n", shared_data.dict_path);
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
		pthread_mutex_lock(&mutex_reader);
		while (shared_data.line != NULL) {
			pthread_cond_signal(&proc_pass);		
			pthread_cond_wait(&read_pass, &mutex_reader);
			pthread_rwlock_rdlock(&pass_lock);
			if (shared_data.password != NULL) {
				pthread_mutex_unlock(&mutex_reader);	
				goto exit;
			}
			pthread_rwlock_unlock(&pass_lock);		
		}
		shared_data.line = line;
		shared_data.read = read;
		line = NULL;
		pthread_cond_signal(&proc_pass);	//WTF
		pthread_mutex_unlock(&mutex_reader);
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
		pthread_mutex_lock(&mutex_reader);
		pthread_cond_broadcast(&proc_pass);
		pthread_cond_timedwait(&read_pass, &mutex_reader, &ts);
		pthread_mutex_unlock(&mutex_reader);
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
	pthread_mutex_lock(&mutex_breaker);
	pthread_cond_broadcast(&done);
	pthread_mutex_unlock(&mutex_breaker);
	if (t_data->verbose > 1) printf("Reader: exiting!\n");	
	pthread_exit(NULL);
}

void *thread_manager(void *t_data) {
	int rc, change_flag = 1, decision_flag; //change_flag trzyma informacje czy dodano, czy odjeto watek
	long t, comparers_created, old_pass_counter_value;
	double ratio = 1, pass_per_sec = 1, new_pass_per_sec;
	t = comparers_created = old_pass_counter_value = decision_flag = new_pass_per_sec = 0;
	struct timespec tsold, tsnew, tsres;
	struct thread_data *m_data = (struct thread_data *) t_data;
	struct thread_data *thread_data_array = malloc(MAX_THREADS * sizeof(struct thread_data));	
	pthread_t *call_thread = calloc(MAX_THREADS, sizeof(pthread_t)); // malloc z zerami
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_mutex_init(&mutex_reader, NULL);	
	pthread_mutex_init(&mutex_breaker_hold, NULL);	
	pthread_mutex_init(&mutex_manager, NULL);
	pthread_cond_init(&read_pass, NULL);
	pthread_cond_init(&proc_pass, NULL);
	pthread_cond_init(&hold_breaker, NULL);
	pthread_cond_init(&changed_num_threads, NULL);
	pthread_rwlock_init(&pass_lock, NULL);
	pthread_rwlock_init(&c_proc_lock, NULL);
	pthread_rwlock_init(&c_read_lock, NULL);
	if (m_data->verbose > 1) printf("Manager(%ld): creating reader thread %ld\n", syscall(SYS_gettid), t);
	thread_data_array[t].verbose = m_data->verbose;	
	rc = pthread_create(&call_thread[t], &attr, dictionary_reader, (void *) &thread_data_array[t]);
	if (rc) {
		printf("ERROR; return code from pthread_create() is %d\n", rc);
		pthread_exit((void*) t);
	}
	clock_gettime(CLOCK_REALTIME, &tsold);
	tsnew.tv_sec = tsold.tv_sec;
	tsnew.tv_nsec = tsold.tv_nsec;
	tsnew.tv_sec += 1;
	pthread_mutex_lock(&mutex_manager);
	for (t = 1, comparers_created = 0; t < shared_data.num_threads; t++, comparers_created++){
		if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
		thread_data_array[t].thread_id = t;
		thread_data_array[t].verbose = m_data->verbose;
		thread_data_array[t].spassword = m_data->spassword;	
		rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
		if (rc != 0) {
			printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
			shared_data.password = "";
			break;
		}
		pthread_cond_wait(&changed_num_threads, &mutex_manager);
	}
	pthread_mutex_unlock(&mutex_manager);
	pthread_mutex_lock(&mutex_breaker);
	pthread_cond_timedwait(&done, &mutex_breaker, &tsnew);
	pthread_mutex_unlock(&mutex_breaker);
	clock_gettime(CLOCK_REALTIME, &tsnew);
	timespec_subtract(&tsnew, &tsold, &tsres);
	pthread_rwlock_rdlock(&c_proc_lock);
	old_pass_counter_value = (double)shared_data.pass_proced_c;
	pthread_rwlock_unlock(&c_proc_lock);
	ratio = new_pass_per_sec = old_pass_counter_value / ((double)tsres.tv_sec + (double)tsres.tv_nsec / 1000000000);
	pthread_rwlock_rdlock(&pass_lock);	
	while (shared_data.password == NULL) {
		if (m_data->verbose > 0) {
			pthread_rwlock_rdlock(&c_proc_lock);
			pthread_rwlock_rdlock(&c_read_lock);
			printf("Comparers: %ld (%ld)  Pps: %lf  Ratio: %lf  PRead: %ld  PProc: %ld\n", t - 1, comparers_created, new_pass_per_sec, ratio, shared_data.pass_read_c, old_pass_counter_value);
			pthread_rwlock_unlock(&c_read_lock);			
			pthread_rwlock_unlock(&c_proc_lock);																		
		}
		pthread_rwlock_unlock(&pass_lock);		
		if (ratio > 1.05) { 
			if (change_flag == 1 && t < MAX_THREADS) {		
				if (comparers_created < t) {
					if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
					thread_data_array[t].thread_id = t;
					thread_data_array[t].spassword = m_data->spassword;
					thread_data_array[t].verbose = m_data->verbose;
					pthread_mutex_lock(&mutex_manager);
					rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
					if (rc != 0)
						printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
					else {
						t++;
						shared_data.num_threads = t;
						pthread_cond_wait(&changed_num_threads, &mutex_manager);
						comparers_created++;
					}
					pthread_mutex_unlock(&mutex_manager);
				} else { //budzenie watkow			
					if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
					t++;
					pthread_mutex_lock(&mutex_breaker_hold);
					pthread_mutex_lock(&mutex_manager);
					shared_data.num_threads = t;
					pthread_cond_signal(&hold_breaker);
					pthread_mutex_unlock(&mutex_breaker_hold);
					pthread_cond_wait(&changed_num_threads, &mutex_manager);
					pthread_mutex_unlock(&mutex_manager);
				}				
				pass_per_sec = new_pass_per_sec;
				decision_flag = 0;
				change_flag = 1;
			} else if (change_flag == 0 && t > 2) {
				t--;	
				if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);										
				pthread_mutex_lock(&mutex_manager);
				shared_data.num_threads = t;
				pthread_cond_wait(&changed_num_threads, &mutex_manager);
				pthread_mutex_unlock(&mutex_manager);
				pass_per_sec = new_pass_per_sec;
				decision_flag = change_flag = 0;
			} else change_flag = !change_flag; // brzegowy, aby nie utknac na 1 lub max watkow
		} else if (ratio < 0.95) {
			if (change_flag == 1 && t > 2) {			
				t--;
				if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);			
				pthread_mutex_lock(&mutex_manager);
				shared_data.num_threads = t;
				pthread_cond_wait(&changed_num_threads, &mutex_manager);
				pthread_mutex_unlock(&mutex_manager);
				pass_per_sec = new_pass_per_sec;
				decision_flag = change_flag = 0;
			} else if (change_flag == 0 && t < MAX_THREADS) {
				if (comparers_created < t) {
					if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
					thread_data_array[t].thread_id = t;
					thread_data_array[t].spassword = m_data->spassword;
					thread_data_array[t].verbose = m_data->verbose;
					pthread_mutex_lock(&mutex_manager);
					rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
					if (rc != 0)
						printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
					else {
						t++;
						shared_data.num_threads = t;
						pthread_cond_wait(&changed_num_threads, &mutex_manager);
						comparers_created++;
					}
					pthread_mutex_unlock(&mutex_manager);
				} else { //budzenie watkow			
					if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
					t++;
					pthread_mutex_lock(&mutex_breaker_hold);
					pthread_mutex_lock(&mutex_manager);
					shared_data.num_threads = t;
					pthread_cond_signal(&hold_breaker);
					pthread_mutex_unlock(&mutex_breaker_hold);
					pthread_cond_wait(&changed_num_threads, &mutex_manager);
					pthread_mutex_unlock(&mutex_manager);
				}				
				pass_per_sec = new_pass_per_sec;
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
						pthread_mutex_lock(&mutex_manager);
						rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
						if (rc != 0)
							printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
						else {
							t++;
							shared_data.num_threads = t;
							pthread_cond_wait(&changed_num_threads, &mutex_manager);
							comparers_created++;
						}
						pthread_mutex_unlock(&mutex_manager);
					} else { //budzenie watkow			
						if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
						t++;
						pthread_mutex_lock(&mutex_breaker_hold);
						pthread_mutex_lock(&mutex_manager);
						shared_data.num_threads = t;
						pthread_cond_signal(&hold_breaker);
						pthread_mutex_unlock(&mutex_breaker_hold);
						pthread_cond_wait(&changed_num_threads, &mutex_manager);
						pthread_mutex_unlock(&mutex_manager);
					}				
					pass_per_sec = new_pass_per_sec;
					decision_flag = 0;
					change_flag = 1;				
				} else if (change_flag == 0 && t > 2) {					
					t--;
					if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);			
					pthread_mutex_lock(&mutex_manager);
					shared_data.num_threads = t;
					pthread_cond_wait(&changed_num_threads, &mutex_manager);
					pthread_mutex_unlock(&mutex_manager);
					pass_per_sec = new_pass_per_sec;
					decision_flag = change_flag = 0;
				} else change_flag = !change_flag; // brzegowy, aby nie utknac na 1 lub max watkow		
			} else if (decision_flag < -10) {
				if (change_flag == 1 && t > 2) {
					t--;					
					if (m_data->verbose > 1) printf("Manager: stopping comparer thread %ld\n", t);						
					pthread_mutex_lock(&mutex_manager);
					shared_data.num_threads = t;
					pthread_cond_wait(&changed_num_threads, &mutex_manager);
					pthread_mutex_unlock(&mutex_manager);
					pass_per_sec = new_pass_per_sec;
					decision_flag = change_flag = 0;
				} else if (change_flag == 0 && t < MAX_THREADS) {
					if (comparers_created < t) {
						if (m_data->verbose > 1) printf("Manager: creating comparer thread %ld\n", t);
						thread_data_array[t].thread_id = t;
						thread_data_array[t].spassword = m_data->spassword;
						thread_data_array[t].verbose = m_data->verbose;
						pthread_mutex_lock(&mutex_manager);
						rc = pthread_create(&call_thread[t], &attr, password_comparer, (void *) &thread_data_array[t]);
						if (rc != 0)
							printf("Manager: ERROR; return code from pthread_create() is %d\n", rc);
						else {
							t++;
							shared_data.num_threads = t;
							pthread_cond_wait(&changed_num_threads, &mutex_manager);
							comparers_created++;
						}
						pthread_mutex_unlock(&mutex_manager);
					} else { //budzenie watkow			
						if (m_data->verbose > 1) printf("Manager: waking up Comparer#%ld\n", t);
						t++;
						pthread_mutex_lock(&mutex_breaker_hold);
						pthread_mutex_lock(&mutex_manager);
						shared_data.num_threads = t;
						pthread_cond_signal(&hold_breaker);
						pthread_mutex_unlock(&mutex_breaker_hold);
						pthread_cond_wait(&changed_num_threads, &mutex_manager);
						pthread_mutex_unlock(&mutex_manager);
					}				
					pass_per_sec = new_pass_per_sec;
					decision_flag = 0;
					change_flag = 1;
				} else change_flag = !change_flag; // brzegowy, aby nie utknac na 1 lub max watkow		
			} 	
		}
		pass_per_sec = new_pass_per_sec;		
		clock_gettime(CLOCK_REALTIME, &tsold);
		tsnew.tv_sec = tsold.tv_sec;
		tsnew.tv_nsec = tsold.tv_nsec;
		tsnew.tv_sec += 1;
		pthread_mutex_lock(&mutex_breaker);
		pthread_cond_timedwait(&done, &mutex_breaker, &tsnew);
		pthread_mutex_unlock(&mutex_breaker);
		clock_gettime(CLOCK_REALTIME, &tsnew);
		pthread_rwlock_rdlock(&c_proc_lock);
		new_pass_per_sec = ((double) shared_data.pass_proced_c - (double) old_pass_counter_value) / ((double) tsres.tv_sec + (double) tsres.tv_nsec / 1000000000);
		old_pass_counter_value = shared_data.pass_proced_c;
		pthread_rwlock_unlock(&c_proc_lock);
		timespec_subtract(&tsnew, &tsold, &tsres);
		ratio = new_pass_per_sec / pass_per_sec;
		pthread_rwlock_rdlock(&pass_lock);
	}
	pthread_rwlock_unlock(&pass_lock);
	pthread_mutex_lock(&mutex_reader);
	pthread_cond_signal(&read_pass); // odblokowanie readera, aby mogl zakonczyc dzialanie
	pthread_cond_broadcast(&proc_pass);
	pthread_mutex_unlock(&mutex_reader);
	pthread_mutex_lock(&mutex_breaker_hold);	
	pthread_cond_broadcast(&hold_breaker);
	pthread_mutex_unlock(&mutex_breaker_hold);
	void *res;	
	for (t = 0; t < MAX_THREADS; t++)
		if (call_thread[t] == 0)
			break;
		else
			pthread_join(call_thread[t], &res);
	pthread_mutex_lock(&mutex_breaker);					
	pthread_cond_signal(&done);
	pthread_mutex_unlock(&mutex_breaker);
	free(thread_data_array);
	free(call_thread);
	if (m_data->verbose > 1) printf("Manager: exiting!\n");
	pthread_attr_destroy(&attr);
	pthread_exit(NULL);
}

int strncmp(const char *s1, const char *s2, size_t n) {
	if (!n) return 0;
	while (--n && *s1 && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *(unsigned char *) s1 - *(unsigned char *) s2;
}

void int_handler(int signum) {
    printf("\nMain: Stopping!\n");
	pthread_mutex_lock(&mutex_breaker);
	shared_data.password = ""; // zatrzymanie watkow
	pthread_mutex_unlock(&mutex_breaker);
	pthread_mutex_lock(&mutex_reader);	
	pthread_cond_broadcast(&proc_pass); // wyslij info do wszystkich comparerow
	pthread_cond_signal(&read_pass); // wyslij info do readera
	pthread_mutex_unlock (&mutex_reader);
	pthread_mutex_lock(&mutex_breaker_hold);
	pthread_cond_broadcast(&hold_breaker); // obudz wszystkie comparery
	pthread_mutex_unlock(&mutex_breaker_hold);
}

void print_usage(char* name) {
	printf("\n Usage:\n");
	printf("  %s <user><--dict PATH><login>[options]\n\n", name);
	printf("   --dict <PATH_TO_DICTIONARY> \tpass location of dictionary\n");
	printf("   -v \t\t\t\tverbose - print progress info\n");
	printf("   -fv \t\t\t\tfull verbose - print progress info,\n\t\t\t\tthread's state changes\n");
	printf("   -debug \t\t\tdebug - print progress info, thread's info\n\n");
}

int main(int argc, char *argv[]) {
	pthread_attr_t attr;
	pthread_t t_manager;
	struct thread_data *m_data;				
	int i, rc, verbose = 0;	
	uid_t save_uid;
	struct spwd *userdata = NULL;
	struct passwd *pwd_su = NULL, *pwd_usr = NULL;
	char *slogin = NULL, *spassword = NULL;		
	if (argc > 1) { //sprawdz czy sa dodatkowe informacje z lini polecen	
		for (i = 1; i < argc; i++) { //sa
			if (strncmp(argv[i], "--dict", 7) == 0 && argc > i) {
				shared_data.dict_path = argv[++i];
			} else if (strncmp(argv[i], "-v", 3) == 0) { //  verbose, stat od managera
				verbose = 1;
			} else if (strncmp(argv[i], "-fv", 4) == 0) { // full verbose, stat od managera, info od watkow
				verbose = 2;
			} else if (strncmp(argv[i], "-debug", 7) == 0) { // mega verbose, spam od wszystkich watkow (debug)
				verbose = 3;
			} else if (strncmp(argv[i], "--help", 7) == 0) {
				print_usage(argv[0]);
				pthread_exit(NULL);
			} else if (slogin == NULL) {
				slogin = argv[i];
			} else {
				printf("Invalid argument: %s\n", argv[i]);
				print_usage(argv[0]);
				pthread_exit(NULL);
			}
		}
		save_uid = geteuid();
		i = seteuid((uid_t) 0);
		if (i != 0) {
			printf("\n No privileges. Try again as Super User ('wheel' member).\n\n");
			return -1;
		}
		if (slogin != NULL) {
			pwd_su = getpwuid(geteuid());
			pwd_usr = getpwnam(slogin);
			gid_t *groups = malloc(10 * sizeof(gid_t));
			gid_t adm_gid = getgrnam("wheel")->gr_gid;
			int ngroups = 10;
			getgrouplist(slogin, pwd_usr->pw_gid, groups, &ngroups);			
			for (i = 0, rc = 0; i < ngroups; i++) {
				if (adm_gid == groups[i]) {
					rc = 1;
				}
			}
			if (groups != NULL) free(groups);
			if ( pwd_usr == NULL) { //sprawdz czy uzytkownik istnieje w systemie 
				printf("\n There is no user like: %s\n\n", argv[1]); //wypisz informacje ze nie ma takiego uzytkownika		
				return -2;
			} else if ( rc || pwd_su->pw_gid == pwd_usr->pw_gid ) { //sprawdz czy jest %wheel lub root
				printf("\n No privileges. Target user cannot be a Super User.\n\n");
				return -3;
			} else { //jest
				userdata = getspnam( slogin );
				slogin = userdata->sp_namp; //zapisz login uzytkownika
				spassword = userdata->sp_pwdp; //zapisz haslo uzytkownika
			}
		} else {
			printf("\n Missing user's login. For user list run %s with no arguments.\n\n", argv[0]);
			return -4; 
		}
	} else { // nie ma = wypisz wszystkich uzytkownikow w systemie
		save_uid = geteuid();
		i = seteuid((uid_t) 0);
		if (i == 0) {
			setspent( );
			printf("\n User list:\n");
			while( ( userdata=getspent( ) ) != ( struct spwd * )0 )
				printf( "  %s\n", userdata->sp_namp );
			printf("\n");
			endspent();
			free(userdata);
		} else {
			printf("\n No privileges. Try again as Super User.\n\n");
			return -1;		
		}
		seteuid((uid_t) save_uid);
		return 0; // po wypisaniu zakoncz dzialanie programu
	}
	seteuid((uid_t) save_uid);
	signal(SIGINT, int_handler);
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_mutex_init(&mutex_breaker, NULL);
	pthread_cond_init (&done, NULL);	
	struct timeval start, stop, res;
	gettimeofday(&start, NULL);
	if (verbose > 1) printf("Main(%ld): creating manager thread\n", syscall(SYS_gettid));
	m_data = (struct thread_data*) malloc(sizeof(struct thread_data));
	shared_data.num_threads = 2; // startowa ilosc watkow
	m_data->spassword = spassword;
	m_data->verbose = verbose;
	rc = pthread_create(&t_manager, &attr, thread_manager, (void *)m_data);
	if (rc) {
		printf("ERROR; return code from pthread_create() is %d\n", rc);
		return -1;
	}
	pthread_mutex_lock(&mutex_breaker);
	pthread_cond_wait(&done, &mutex_breaker); /* Wait on the other threads */
	pthread_mutex_unlock(&mutex_breaker);
	gettimeofday(&stop, NULL);
	printf("Login:\t\t%s\n",  slogin);
	pthread_rwlock_rdlock(&pass_lock);
	if (shared_data.password == NULL || shared_data.password[0] == '\0')
		printf("Password: \t(failed to find password)\n");
	else {
		printf("Password: \t%s\n", shared_data.password);
		free(shared_data.password);
	}
	printf("Hash:\t\t%s\n", shared_data.hash);
	timersub(&stop, &start, &res);
	pthread_rwlock_unlock(&pass_lock);
	printf("Time:\t\t%lu.%lus\n", res.tv_sec, res.tv_usec);
	pthread_join(t_manager, NULL);
	pthread_rwlock_rdlock(&c_read_lock);	
	printf("Read passwds:\t%ld\n", shared_data.pass_read_c);
	pthread_rwlock_unlock(&c_read_lock);
	pthread_rwlock_rdlock(&c_proc_lock);
	printf("Proced passwds:\t%ld\n", shared_data.pass_proced_c);
	printf("Avg pps:\t%lf\n", (double) shared_data.pass_proced_c / ((double) res.tv_sec + (double) res.tv_usec / 1000000));
	pthread_rwlock_unlock(&c_proc_lock);	
	pthread_attr_destroy(&attr);
	free(m_data);
	free(shared_data.hash);
	pthread_mutex_destroy(&mutex_reader);
	pthread_mutex_destroy(&mutex_breaker);
	pthread_mutex_destroy(&mutex_breaker_hold);
	pthread_mutex_destroy(&mutex_manager);
	pthread_cond_destroy(&done);
	pthread_cond_destroy(&read_pass);
	pthread_cond_destroy(&proc_pass);
	pthread_cond_destroy(&changed_num_threads);
	pthread_cond_destroy(&hold_breaker);
	pthread_rwlock_destroy(&pass_lock);
	pthread_rwlock_destroy(&c_proc_lock);
	pthread_rwlock_destroy(&c_read_lock);
	pthread_exit((void*) 0);
}