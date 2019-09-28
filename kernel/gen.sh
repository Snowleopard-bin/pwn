gcc exp.c -o exp -w -static
echo "gcc success"
cp exp core/
cd core
find . | cpio -o -H newc | gzip > ../rootfs.cpio
echo "finish"
