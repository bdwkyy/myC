/**
 * Copyright (C) York Yang
 * 功能：
 * 		1. 作为守护进程运行
 * 		2. 保证同时只有一个实例在运行（ps方式）
 * 		3. 提供命令行参数（基于信号）
 * 		5. 常见信号的使用 (todo)
 *	编译：gcc pocsig.c -o pocsig
 */

#include <stdio.h>                                                                                                                
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/stat.h>

/* 向管道传入 linux 命令 */
#define PIPECMD_COUNT "ps -ef | grep pocsig | grep -v grep | wc -l" 
#define PIPECMD_PID "ps -ef | grep pocsig | grep -v grep | awk '{print $2}'" 

#define POC_VER "v1.0"
#define POC_OK 0
#define POC_ERR 1
static int   poc_show_help;
static int   poc_show_version;
static char  *poc_signal;

int poc_process_count();
int poc_init_signals();
int poc_signal_process(char *sig);
int poc_get_options(int argc, char *const *argv);
int poc_os_signal_process(char *name, int pid);
void poc_signal_handler(int signo);
void init_daemon();

#define poc_signal_helper(n)     SIG##n
#define poc_signal_value(n)      poc_signal_helper(n)

#define poc_value_helper(n)   #n
#define poc_value(n)          poc_value_helper(n)


#define POC_TERMINATE_SIGNAL   TERM
#define POC_LOGON_SIGNAL       USR1
#define POC_LOGOFF_SIGNAL      USR2

typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo);
} poc_signal_t;

poc_signal_t  signals[] = {
    { poc_signal_value(POC_LOGON_SIGNAL),
      "SIG" poc_value(POC_LOGON_SIGNAL),
      "logon",
      poc_signal_handler },

    { poc_signal_value(POC_LOGOFF_SIGNAL),
      "SIG" poc_value(POC_LOGOFF_SIGNAL),
      "logoff",
      poc_signal_handler },

    { poc_signal_value(POC_TERMINATE_SIGNAL),
      "SIG" poc_value(POC_TERMINATE_SIGNAL),
      "stop",
      poc_signal_handler }
};

void init_daemon()
{
int pid;
int i;
pid=fork();
if(pid<0)
    exit(1); 
else if(pid>0) 
    exit(0);	
setsid(); 
pid=fork();
if(pid>0)
    exit(0); 
else if(pid<0)
    exit(1);

for(i=0;i<NOFILE;i++)
    close(i);
chdir("/"); 

umask(0);
return;
}

int poc_process_count()
{
FILE* fp;
int count;
char buf[32];
char command[128];
sprintf(command, PIPECMD_COUNT);
if((fp = popen(command,"r")) == NULL){
	printf("popen failed\n");
	return POC_ERR;
}
/*从管道读取数据*/
if( (fgets(buf,32,fp))!= NULL )
{
count = atoi(buf);
printf("get count:%d\n",count);
pclose(fp);
return count;
}

pclose(fp);
    return POC_OK;
}

int poc_process_pid(int *pid)
{
FILE* fp;
char buf[32];
char command[128];
sprintf(command, PIPECMD_PID);
if((fp = popen(command,"r")) == NULL){
	printf("popen failed\n");
pclose(fp);
	return POC_ERR;
}
/*从管道读取数据*/
if( (fgets(buf,32,fp))!= NULL )
{
*pid = atoi(buf);
}else {
	printf("pipe get failed\n");
	return POC_ERR;
}

pclose(fp);
    return POC_OK;
}


int poc_get_options(int argc, char *const *argv){
	char  *p;
    int   i;

    for (i = 1; i < argc; i++) {
        p = (char *) argv[i];

        if (*p++ != '-') {
            printf("invalid option: %s", argv[i]);
            return POC_ERR;
        }

        while (*p) {
            switch (*p++) {
			case '?':
            case 'h':
                poc_show_version = 1;
                poc_show_help = 1;
                break;
			case 'v':
                poc_show_version = 1;
                break;
            case 's':
                if (*p) {
                    poc_signal = (char *) p;

                } else if (argv[++i]) {
                    poc_signal = argv[i];

                } else {
                    printf("option \"-s\" requires parameter");
                    return POC_ERR;
                }

                if (strcmp(poc_signal, "stop") == 0
                    || strcmp(poc_signal, "logon") == 0
                    || strcmp(poc_signal, "logoff") == 0
                    )
                {
                    goto next;
                }

                printf("invalid option: \"-s %s\"", poc_signal);
                return POC_ERR;				
			}
		}
		 next:
        continue;
	}
	return POC_OK;
}

int poc_os_signal_process(char *name, int pid)
{
    poc_signal_t  *sig;
    for (sig = signals; sig->signo != 0; sig++) {
        if (strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return POC_OK;
            }

          printf("kill(%d, %d) failed", pid, sig->signo);
        }
    }
    return POC_ERR;
}


int poc_signal_process(char *sig)
{
	int pid;
	if (0 < poc_process_pid(&pid))
	{
		return POC_ERR;
	}
	return poc_os_signal_process(sig, pid);
}

int poc_init_signals()
{
    poc_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
           printf("sigaction(%s) failed", sig->signame);

            return POC_ERR;
        }
    }
    return POC_OK;
}

void poc_signal_handler(int signo){
	char *action;
    poc_signal_t    *sig;

	    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
	
	   switch (signo) {

        case poc_signal_value(POC_TERMINATE_SIGNAL):
        case SIGINT:
            /* poc_terminate = 1; */
			action = ",stop";
			printf("get signal stop\n");
            break;

        case poc_signal_value(POC_LOGON_SIGNAL):
				/* elog_set_output_enabled(true); */
				action = ",logon";
				printf("get signal logon\n");
            break;

        case poc_signal_value(POC_LOGOFF_SIGNAL):
            	/* elog_set_output_enabled(false); */
				action = ",logoff";
				printf("get signal logoff\n");
            break;
	   }
	   printf("signal %d (%s) received%s", signo, sig->signame, action);
}
int main(int argc, char **argv)
{
	/* 如果需要看log，把下面行注释，让程序在前台运行 */
	init_daemon();
    if (poc_get_options(argc, argv) != 0) {
        return POC_ERR;
    }
	if (poc_show_version) {
		printf("pocclient version:%s\n",POC_VER);
		if(poc_show_help){
			printf("Usage:pocclient [-?h] [-s signal] \n -s signal : send signal to a master process: stop,logon,logoff \n");
		}
		return POC_OK;
	}

	if (poc_signal) {
        return poc_signal_process(poc_signal);
    }
	if (poc_init_signals() != POC_OK) {
        return POC_ERR;
    }
	/* 这里为什么用 1 作为标准来比较？这里的1捕捉的是进程 PIPECMD_COUNT里的 pocsig */
	if (1 < poc_process_count())
	{
		printf("pocsig is alreay running\n");
		return POC_ERR;
	}
    while(1)
	{
		sleep(10);
		printf("this is master:%d\n",getpid());
	}
	
	return POC_OK;
}
