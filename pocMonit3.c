/*
	Copyright (C) York Yang
	功能 ：监控一个程序的运行，如果被监控的程序停止运行，该程序负责将其启动
*/

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
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

#define BINFILE "/disk3/pocsig"
#define LOCKFILE "/var/run/pocsig.pid"
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define FILEMODE (S_IXUSR|S_IXGRP|S_IXOTH)

/*	错误使用示范
	char *argv[] = {"/data/pocclient","",NULL};
*/
char *argv[] = {BINFILE,NULL};
char *envp[]={0,NULL};


/**
 *  * 进程初始化
 *   */
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


/*
 *  * @return: 0-未运行 1-运行
 *   */
int check_running(void)
{
	int fd;
	char buf[16];
	fd = open(LOCKFILE,O_RDWR|O_CREAT,LOCKMODE);
	if(fd < 0){
		printf("can't open %s\n",LOCKFILE);
		return 1;
	}
	if (lockf(fd, F_TEST, 0)<0){
			close(fd);
			printf("can't lock1 %s\n",LOCKFILE);
			return 1;
	}
	return 0;
}
/*
	功能：检测执行文件存在及其执行权限
	@return 
		1 - 执行文件不存在
		0 - 执行文件存在
*/
int check_binfile(void)
{
	if(access(BINFILE,F_OK)<0)
	{
		printf("binfile no exist\n");
		return 1;
	}
	if(access(BINFILE,X_OK)<0)
	{
		printf("binfile no chmod\n");
		/* chmod(BINFILE,S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH); */
		chmod(BINFILE,FILEMODE);
	}
	return 0;
}
void main()
{
    init_daemon(); 
    while(1)
    {
		printf("once more\n");
        sleep(10);
		if(check_binfile() != 0)
		{
			return;
		}
            if(!check_running())
            {
				printf("pocsig2-2 not running\n");
				int pid;
				int i;
				pid = fork();
				if (0 == pid)
				{

					pid=fork();
					if(pid>0)
						exit(0);
					else if(pid<0)
						exit(1);
					for(i=0;i<NOFILE;i++)
						close(i);
					if(execve(BINFILE,argv,envp) < 0)	// 需要判断一下，否则若执行失败会创建出很多pocMonit进程
						exit(1);
				}
				else if (0 < pid )
				{
					if(waitpid(pid,NULL,0) != pid)
					{
						exit(0);
					} else
					{
						printf("sun exit,father continue\n");
						continue;
					}
				}
				else
				{
					printf("fork err\n");
					exit(1);
				}
			}
    }
    return;
}
