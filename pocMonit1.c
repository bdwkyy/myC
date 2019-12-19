/**
 * *	Copyright (C) York Yang
 * *	功能：监控一个程序的运行，如果被监控的程序停止运行，该程序负责将其启动
 * */
#include<unistd.h>
#include<signal.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/param.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<time.h>
#include<sys/wait.h>
#include<fcntl.h>
#include<limits.h>
#define BUFSZ 64
#define PIPECMD "ps -ef | grep nsqd | grep -v grep | wc -l" 
#define POCBIN "/usr/local/nsq/bin/nsqd --config=/usr/local/nsq/conf/nsqd.cfg"
#define LOGFILE "/var/log/pocmonit.log"


/**
 * *	进程初始化
 * */
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

/**
 * *	管道打开失败
 * */
void err_quit(char *msg)
{
perror(msg);
exit(EXIT_FAILURE);
}

/**
 * *	检测被监控程序是否运行
 * *	@return 被监控程序的进程个数
 * */
int does_service_work()
{
FILE* fp;
int count;
char buf[BUFSZ];
char command[128];
sprintf(command, PIPECMD);
if((fp = popen(command,"r")) == NULL)
err_quit("popen");
/*从管道读取数据*/
if( (fgets(buf,BUFSZ,fp))!= NULL )
{
count = atoi(buf);
}

pclose(fp);
    return count;
}
void does_server_log()
{
	FILE *fp;
    time_t now;
	struct tm *tm_now;
	time(&now);
	tm_now = localtime(&now) ;
	fp=fopen(LOGFILE,"a");
	if(fp>=0)
	{
		/* 转换为本地时间输出 */
		fprintf(fp,"process does not exist, restart it! now time: %d-%d-%d %d:%d:%d\n",tm_now->tm_year+1900, tm_now->tm_mon+1, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);  
		fclose(fp);
	}
	return;
}

void main()
{

    int count;
    init_daemon();
    while(1)
    {
        sleep(10); 
		count = does_service_work();
		if(count<=0)
		{
			does_server_log();
			system(POCBIN);
		}
    }
    return;
}
