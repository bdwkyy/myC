/**
 * Copyright (C) York Yang
 * 功能：
 * 		1. 作为守护进程运行
 * 		2. 保证同时只有一个实例在运行（文件锁方式）
 * 		3. 提供命令行参数（基于信号）
 * 		5. 常见信号的使用（todo）
 *	编译：gcc pocsig2.c -o pocsig2
 */

#include <stdio.h>                                                                                                                
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>

#include<sys/param.h>


/* pid 文件 */
#define LOCKFILE "/var/run/pocsig2.pid"
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#define POC_VER "v1.0"
#define POC_OK 0
#define POC_ERR 1
static int   poc_show_help;
static int   poc_show_version;
static char  *poc_signal;

void init_daemon();
int already_running();
int poc_init_signals();
int poc_signal_process(char *sig);
int poc_get_options(int argc, char *const *argv);
int poc_os_signal_process(char *name, int pid);
void poc_signal_handler(int signo);
int poc_get_pid();
int check_running();


/* 信号结构体 */
typedef struct {
    int     signo;					/* 信号对应的编码(系统规定好的) */
    char   *signame;				/* 为信号起个名 */
    char   *name;					/* 信号对应的参数名(命令行参数) */
    void  (*handler)(int signo);	/* 处理信号的回调函数 */
} poc_signal_t;

/* 初始化信号数组 */
poc_signal_t  signals[] = {
    { SIGUSR1,
      "SIGUSR1-Logon",
      "logon",
      poc_signal_handler },

    { SIGUSR2,
      "SIGUSR1-Logoff",
      "logoff",
      poc_signal_handler },

    { SIGTERM,
      "SIGTERM-stop",
      "stop",
      poc_signal_handler }
};


/**
 * 	功能：检测程序是否正运行,若没有运行，则创建pid文件
 * 	@return: 
 * 		POC_OK - 没有运行
 * 		POC_ERR - 正在运行
*/
int already_running(void)
{
	int fd;
	char buf[16];
	fd = open(LOCKFILE,O_RDWR|O_CREAT,LOCKMODE);
	if(fd < 0){
		printf("can't open %s\n",LOCKFILE);
		return POC_ERR;
	}
	/* 使用 "F_TLOCK" 参数，检测并获取锁 */
	if (lockf(fd, F_TLOCK, 0)<0){
		if(errno == EACCES || errno == EAGAIN){
			close(fd);
			printf("can't lock1 %s\n",LOCKFILE);
			return POC_ERR;
		}
		printf("can't lock2 %s\n",LOCKFILE);
		return POC_ERR;
	}
	/* 将pid 写入文件 */
	ftruncate(fd,0);
	sprintf(buf,"%ld",(long)getpid());
	write(fd,buf,strlen(buf)+1);
	return POC_OK;
}

/**
 * 	功能：从pid文件获取正运行的进程的pid
 * 	@return:
 * 		pid - 功能返回pid号
 * 		POC_ERR - 失败返回 POC_ERR
 */
int poc_get_pid()
{
	int fd;
	int n;
	char buf[16];
	fd = open(LOCKFILE,O_RDWR|O_CREAT,LOCKMODE);
	if(fd < 0){
		printf("can't open %s\n",LOCKFILE);
		return POC_ERR;
	}
	/* 使用 "F_TEST" 参数检测pid文件是否上锁，若有锁，则说明进程正在运行，然后对pid文件进行读取 */
	if (lockf(fd, F_TEST, 0)<0){
		n = read(fd,buf,16);
		printf("readbuf size:%d,%s\n",n,buf);
		if(0 > n)
		{
			printf("eeeeeeeee\n");
			return POC_ERR;
		}
	return atoi(buf);
	}
}

/*
 * 	功能：解析命令行参数，根据不同的参数设置相应的标志位
 */
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

/* 功能：向目标进程发送信号 */
int poc_signal_process(char *name)
{
	int pid;
	poc_signal_t  *sig;
		/* 从/var/run/pocsig.pid 读取 进程号 */
	pid = poc_get_pid();
	printf("getpid:%d\n",pid);
	if ( pid == POC_ERR)
	{
		return POC_ERR;
	}
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

/*
 * 	功能：注册信号
 */
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

/*
 * 	功能: 信号处理函数
 */
void poc_signal_handler(int signo){
	char *action;
    poc_signal_t    *sig;

	    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
	
	   switch (signo) {

        case SIGTERM:
        case SIGINT:
            /* poc_terminate = 1; */
			action = ",stop";
			printf("get signal stop\n");
            break;

        case SIGUSR1:
				/* elog_set_output_enabled(true); */
				action = ",logon";
				printf("get signal logon\n");
            break;

        case SIGUSR2:
            	/* elog_set_output_enabled(false); */
				action = ",logoff";
				printf("get signal logoff\n");
            break;
	   }
	   printf("signal %d (%s) received%s", signo, sig->signame, action);
}

/**
 * 进程初始化
 */
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

for(i=0;i<NOFILE;i++)
    close(i);
chdir("/"); 

umask(0);
return;
}

/*	功能：检测程序是否正运行
 *	@return 
 *		POC_ERR - 正在运行
 *		POC_OK - 没有运行
 */
int check_running()
{
	int fd;
	char buf[16];
	fd = open(LOCKFILE,O_RDWR|O_CREAT,LOCKMODE);
	if(fd < 0){
		return POC_ERR;
	}
	if (lockf(fd, F_TEST, 0)<0){
			close(fd);
			return POC_ERR;
	}
	close(fd);
	return POC_OK;
}

int main(int argc, char **argv)
{
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

	/* poc_pid = getpid(); */
	if (poc_signal) {
        return poc_signal_process(poc_signal);
    }
	if(check_running())
	{
		printf("pocSig alreay running\n");
		return POC_ERR;
		
	}
	/* 要看log的话，可先注释掉下面行，让程序在前台运行 */
	init_daemon();
	if (poc_init_signals() != POC_OK)
	{
        return POC_ERR;
    }
	if (already_running() != POC_OK)
	{
		printf("pocSig alreay running\n");
		return POC_ERR;
	}
	
    while(1)
	{
		sleep(10);
		printf("this is master:%d\n",getpid());
	}
	
	return POC_OK;
}
