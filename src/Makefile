obj-m += azihsm.o
azihsm-y += azihsm_main.o
azihsm-y += azihsm_ctrl.o
azihsm-y += azihsm_ctrl_cmd.o
azihsm-y += azihsm_ioq.o
azihsm-y += azihsm_ioq_pool.o
azihsm-y += azihsm_hsm.o
azihsm-y += azihsm_hsm_dev.o
azihsm-y += azihsm_hsm_cmd.o
azihsm-y += azihsm_aes.o
azihsm-y += azihsm_aes_dev.o
azihsm-y += azihsm_aes_cmd.o
azihsm-y += azihsm_dma_io.o
azihsm-y += azihsm_abort.o
azihsm-y += azihsm_ioq_util.o
azihsm-y += azihsm_mgmt_dev.o
azihsm-y += azihsm_ioq_perf.o

ccflags-y += -Werror

SRC := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c *.mod
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
