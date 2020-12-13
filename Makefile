obj-m := inet_bind_mod.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall bind_socket.c -o bind_socket
clean:
	rm -rf .*.cmd .*.mk *.ko *.o *.order  *.symvers *.mod.c .tmp_versions
	rm -rf bind_socket inet_bind_mod.mod
