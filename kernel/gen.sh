musl-gcc exp.c -o exp -w -static
cp exp core/
cd core
find . | cpio -o -H newc | gzip > ../rootfs.cpio
