#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int probe(int port, int index) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = {.sin_len=sizeof(to), .sin_family=AF_INET, .sin_port=htons(port)};
    inet_pton(AF_INET,"10.77.0.99", &to.sin_addr);
    char data[256], reply[256];
    int size=snprintf(data,sizeof(data),"{\"pid\":%d,\"ppid\":%d,\"sid\":%d,\"index\":%d}",getpid(),getppid(),getsid(0),index);
    int sent=(int)sendto(fd,data,size,0,(struct sockaddr*)&to,sizeof(to));
    struct pollfd item={.fd=fd,.events=POLLIN};
    int ready=poll(&item,1,800), received=ready>0?(int)recv(fd,reply,sizeof(reply),0):-1;
    int success=received==size && memcmp(data,reply,size)==0;
    printf("{\"pid\":%d,\"ppid\":%d,\"sid\":%d,\"index\":%d,\"sent\":%d,\"reply\":%s}\n",getpid(),getppid(),getsid(0),index,sent,success?"true":"false");
    close(fd); return success?0:1;
}
int main(int argc,char **argv) {
    if(argc!=4)return 2;
    setbuf(stdout,NULL);
    int port=atoi(argv[2]),count=atoi(argv[3]);
    if(!strcmp(argv[1],"send"))return probe(port,count);
    if(!strcmp(argv[1],"burst") || !strcmp(argv[1],"exec")) {
        for(int i=0;i<count;i++) {
            pid_t child=fork(); if(child<0)return 3;
            if(!child) {
                if(!strcmp(argv[1],"exec")) { char index[24]; snprintf(index,sizeof(index),"%d",i); execl(argv[0],argv[0],"send",argv[2],index,NULL); _exit(4); }
                _exit(probe(port,i));
            }
            int status;waitpid(child,&status,0);
        }
        return 0;
    }
    // Double fork, then wait for actual reparenting. Parent does not announce
    // child PIDs to the Provider; session lookup must classify their flows.
    int lifetime[2]; if(pipe(lifetime))return 5;
    pid_t child=fork(); if(child<0)return 6;
    if(!child) {
        close(lifetime[0]);
        if(fork())_exit(0);
        pid_t old=getppid();
        for(int n=0;n<100 && getppid()==old;n++)usleep(10000);
        if(!strcmp(argv[1],"setsid") && setsid()<0)_exit(7);
        int status=probe(port,0);close(lifetime[1]);_exit(status);
    }
    close(lifetime[1]);int status;waitpid(child,&status,0);
    char value;read(lifetime[0],&value,1);close(lifetime[0]);return 0;
}
