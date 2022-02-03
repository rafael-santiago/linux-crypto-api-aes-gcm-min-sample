#
#                                Copyright (C) 2022 by Rafael Santiago
#
# This is a free software. You can redistribute it and/or modify under
# the terms of the GNU General Public License version 2.
#
obj-m += aes-gcm-min-sample.o

aes-gcm-min-sample-objs += aes_gcm.o

ccflags-y := -I$(PWD)

ldflags-y :=

all: build

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
