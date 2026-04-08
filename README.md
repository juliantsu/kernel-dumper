# kernel-dumper
create a kernel dump from usermode

## build: 
- nasm -f win64 Main.asm -o Main.obj
- gcc Main.obj -o Main.exe -lntdll
