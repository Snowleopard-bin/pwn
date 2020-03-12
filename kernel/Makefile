#Mkefile 2.6
name :=my
obj-m :=$(name).o
KERNEL :=/lib/modules/$(shell uname -r)/build
PWD :=$(shell pwd)
modules :
	$(MAKE) -C $(KERNEL) M=$(PWD) modules
	rm $(name).mod* $(name).o modules.order Module.symvers
.PHONEY:clean
clean :
	rm -f *.o

