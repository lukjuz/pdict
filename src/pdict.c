/* 
Reading passwords from /etc/shadow and multithread hash comparison
compilation: gcc -lcrypt -pthread -Ofast -o pdict pdict.c
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
#include <pwd.h>			/* getpwuid, getpwnam */
#include <grp.h>			/* getgrnam */
#include <signal.h>			/* signal */

#define LIM_THREADS 100 // upper limit of threads ( 1 reader, 99 comparers)

int MAX_THREADS = 100;	// maximum number of threads
int MIN_THREADS = 2;	// minimum number of threads

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
};

SHARED_DATA shared_data;
pthread_mutex_t  mtx_reader;		// mutex to signal need of another word to compare
pthread_mutex_t  mtx_comparer;		// mutex to signal accomplishment of password searching
pthread_mutex_t  mtx_comparer_hold; // mutex to signal need of change comparer's state
pthread_mutex_t  mtx_manager;		// mutex to block manager until change of comparer's state
pthread_cond_t 	 cnd_r_pass;		// condition to indicate need of next word to compare
pthread_cond_t   cnd_p_pass;		// condition to indicate readness of another word to compare
pthread_cond_t   hold_breaker;		// condition to block comparers
pthread_cond_t   changed_num_threads;// condition to block thread until accomplishment of comparer state changes
pthread_cond_t   done;				// condition to block thread until accomplishment of password searching
pthread_rwlock_t pass_lock;			// lock for shared:password
pthread_rwlock_t c_proc_lock;		// lock for shared:pass_proced_c
pthread_rwlock_t c_read_lock;		// lock for shared:pass_read_c
pthread_rwlock_t settings_lock; 	// lock for shared:verbose, shared:min_max_threads

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

void *password_comparer(void *thread_arg) { // hash generator and comparer
	struct thread_data *t_data;
	struct crypt_data *c_data = malloc(sizeof(struct crypt_data));
	c_data->initialized = 0;
	int comp_len, i;
	ssize_t read = 0;
	char *password, *result;
	pid_t tid = syscall(SYS_gettid);
	t_data = (struct thread_data *) thread_arg;
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

int strncmp(const char *s1, const char *s2, size_t n) { // compare two strings of known length
	if (!n) return 0;
	while (--n && *s1 && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *(unsigned char *) s1 - *(unsigned char *) s2;
}

void int_handler(int signum) { // SIGINT handler - graceful exit
	pthread_rwlock_wrlock(&pass_lock);
	shared_data.password = ""; // zatrzymanie watkow
	pthread_rwlock_unlock(&pass_lock);
	pthread_mutex_lock(&mtx_reader);
	pthread_cond_signal(&cnd_r_pass); // wyslij info do readera
	pthread_cond_broadcast(&cnd_p_pass); // wyslij info do wszystkich comparerow	
	pthread_mutex_unlock (&mtx_reader);
	pthread_mutex_lock(&mtx_comparer_hold);
	pthread_cond_broadcast(&hold_breaker); // obudz wszystkie comparery
	pthread_mutex_unlock(&mtx_comparer_hold);
}

void tstp_handler(int signum) { // SIGTSTP handler - showing context menu
	int input;
	int i = 0, opt = 0, saved_verb, num;
	pthread_rwlock_wrlock(&settings_lock);	
	saved_verb = shared_data.verbose;
	shared_data.verbose = 0;
	pthread_rwlock_unlock(&settings_lock);
	printf("\nMain: options:\n");
	printf("  1 - stop application\n");
	printf("  2 - silent mode\n");
	printf("  3 - verbose mode\n");
	printf("  4 - full verbose mode\n");
	printf("  5 - debug mode\n");
	printf("  6 - set minumum number of worker threads (actual: %d)\n", MIN_THREADS-1);
	printf("  7 - set maximum number of worker threads (actual: %d)\n", MAX_THREADS-1);
	printf("  8 - continue\n");
	printf("\nPrompt: ");
	scanf("%d%*c", &input);
	i = (int) input;
	switch (i) {
		case 1: // 1 //49
			printf("\nMain: stopping!\n");
			int_handler(SIGINT);
			break;
		case 2: // 2
			printf("\nMain: switching to silent mode!\n");
			break;
		case 3: // 3
			printf("\nMain: switching to verbose mode!\n");
			opt = 1;
			break;
		case 4: // 4
			printf("\nMain: switching to full verbose mode!\n");
			opt = 2;
			break;
		case 5: // 5
			printf("\nMain: switching to debug mode!\n");
			opt = 3;
			break;
		case 6: // 5
			printf("\nMain: new minimum number of workers?");
			opt = 4;
			printf("\nPrompt: ");
			scanf("%d%*c", &num);
			if (num > -1 && num < LIM_THREADS && num <= MAX_THREADS) {
				MIN_THREADS = num + 1;
				printf("\nMain: setting minimum number of worker threads!\n");
			} else 
				printf("\nMain: wrong number - continuing as it was!\n");
			break;
		case 7: // 5
			printf("\nMain: new maximum number of workers?");
			opt = 5;
			printf("\nPrompt: ");
			scanf("%d%*c", &num);
			if (num > -1 && num < LIM_THREADS && num >= MIN_THREADS-1) {
				MAX_THREADS = num + 1;
				printf("\nMain: setting maximum number of worker threads!\n");
			} else 
				printf("\nMain: wrong number - continuing as it was!\n");
			break;
		default:
			opt = 6;
			printf("\nMain: continuing as it was!\n");
			break;
	}
	if (opt > 3) {
		pthread_rwlock_wrlock(&settings_lock);
		shared_data.verbose = saved_verb;
		pthread_rwlock_unlock(&settings_lock);
	} else {
		pthread_rwlock_wrlock(&settings_lock);
		shared_data.verbose = opt;
		pthread_rwlock_unlock(&settings_lock);
	}
}

void print_usage(char* name) {
	printf("\n Usage:\n");
	printf("  %s <user><--dict PATH><login>[options]\n\n", name);
	printf("   --dict <PATH_TO_DICTIONARY> \tpass location of dictionary\n");
	printf("   -mint \t\t\tminimum number of threads\n");
	printf("   -maxt \t\t\tmaximum number of threads\n");
	printf("   -v \t\t\t\tverbose - print progress info\n");
	printf("   -fv \t\t\t\tfull verbose - print progress info,\n\t\t\t\tthread's state changes\n");
	printf("   -debug \t\t\tdebug - print progress info, thread's info\n\n");
	printf(" Example:\n %s --dict /home/admin/dictionary.txt -v -mint 4 -maxt 5 userlogin\n\n", name);
}

int main(int argc, char *argv[]) {
	pthread_attr_t attr;
	pthread_t t_manager;
	int i, rc = 0, verbose = 0;	
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
			} else if (strncmp(argv[i], "-mint", 5) == 0) { // mega verbose, spam od wszystkich watkow (debug)
				rc = atoi(argv[++i]);				
				if (rc > -1 && rc < LIM_THREADS && rc <= MAX_THREADS)
					MIN_THREADS = rc + 1;
				else
					printf("\nMain: '-mint' - unaceptable value - ignoring parameter\n");
			} else if (strncmp(argv[i], "-maxt", 5) == 0) { // mega verbose, spam od wszystkich watkow (debug)
				rc = atoi(argv[++i]);		
				if (rc > -1 && rc < LIM_THREADS && rc >= MIN_THREADS-1)				
					MAX_THREADS =  rc + 1;
				else
					printf("\nMain: '-maxt' - unaceptable value - ignoring parameter\n");
			} else if (strncmp(argv[i], "--help", 7) == 0) {
				print_usage(argv[0]);
				pthread_exit(NULL);
			} else if (strncmp(argv[i], "--usage", 7) == 0) {
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
	signal(SIGTSTP, tstp_handler);
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_mutex_init(&mtx_comparer, NULL);
	pthread_cond_init (&done, NULL);	
	struct timeval start, stop, res;
	gettimeofday(&start, NULL);
	if (verbose > 1) printf("Main(%ld): creating manager thread\n", syscall(SYS_gettid));
	struct thread_data *m_data = (struct thread_data*) malloc(sizeof(struct thread_data));
	shared_data.verbose = verbose;
	m_data->spassword = spassword;
	m_data->verbose = verbose;
	rc = pthread_create(&t_manager, &attr, thread_manager, (void *)m_data);
	if (rc) {
		printf("ERROR; return code from pthread_create() is %d\n", rc);
		return -1;
	}
	pthread_mutex_lock(&mtx_comparer);
	pthread_cond_wait(&done, &mtx_comparer); /* Wait on the other threads */
	pthread_mutex_unlock(&mtx_comparer);
	gettimeofday(&stop, NULL);
	printf("\nLogin:\t\t%s\n",  slogin);
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
	pthread_mutex_destroy(&mtx_reader);
	pthread_mutex_destroy(&mtx_comparer);
	pthread_mutex_destroy(&mtx_comparer_hold);
	pthread_mutex_destroy(&mtx_manager);
	pthread_cond_destroy(&done);
	pthread_cond_destroy(&cnd_r_pass);
	pthread_cond_destroy(&cnd_p_pass);
	pthread_cond_destroy(&changed_num_threads);
	pthread_cond_destroy(&hold_breaker);
	pthread_rwlock_destroy(&pass_lock);
	pthread_rwlock_destroy(&c_proc_lock);
	pthread_rwlock_destroy(&c_read_lock);
	pthread_rwlock_destroy(&settings_lock);
	pthread_exit((void*) 0);
}
