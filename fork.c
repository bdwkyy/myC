#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
int main(){
        pid_t pid;
        if((pid = fork()) < 0){
                perror("fork err");
        } else if(pid == 0) {
                if((pid = fork()) < 0){
                        perror("fork err");
                } else if(pid == 0){
                        sleep(2);
                        printf("second child,parent pid = %d\n",getppid());
                        exit(0);
                } else if(pid > 0){
                        exit(0);
                }
        } else {
                if(waitpid(pid,NULL,0) != pid)
                        perror("waitpid");
                exit(0);
        }
}
/*
        等 2s
        second child,parent pid = 1
*/
