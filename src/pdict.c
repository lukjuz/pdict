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
#include <shadow.h> 		/* getspnam */
#include <pwd.h>			/* getpwuid, getpwnam */
#include <grp.h>			/* getgrnam */
#include <signal.h>			/* signal */

#include "thread_data.h"
#include "manager.h"

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
		save_uid = getuid();
		i = seteuid((uid_t) 0);
		setuid((uid_t) 0);
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
