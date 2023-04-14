NAME := extract_lsb_secrets

DEPLOY_ROM := ../data/ideapad.rom
DEPLOY_DIR := 0
DEPLOY_ENTRY := 1

CROSS_COMPILE=arm-none-eabi-
CFLAGS=-Os -I../include -I../Lib/include -std=gnu99 -fomit-frame-pointer -nostartfiles -ffreestanding -Wextra -Werror -mno-unaligned-access -mthumb -march=armv7-a

all : $(NAME).elf $(NAME).raw $(NAME).rom

clean:
	bash -c "rm -f *.o $(NAME).{elf,raw,entry,rom}"

%.o: %.S
	$(CROSS_COMPILE)gcc $(CFLAGS) -c -o $@ $^

%.o: %.c
	$(CROSS_COMPILE)gcc $(CFLAGS) -c -o $@ $^

$(NAME).entry: $(NAME).raw
	# Copy entry header from original entry
	psptool -X -d$(DEPLOY_DIR) -e$(DEPLOY_ENTRY) $(DEPLOY_ROM) > $@
	dd if=$< bs=1 seek=256 conv=notrunc of=$@

$(NAME).rom: $(NAME).entry $(DEPLOY_ROM)
	psptool -R -d$(DEPLOY_DIR) -e$(DEPLOY_ENTRY) -s $< -o $@ $(DEPLOY_ROM)

$(NAME).elf : linker.ld _start.o main.o
	$(CROSS_COMPILE)ld -T $^ -o $@

$(NAME).raw: $(NAME).elf
	$(CROSS_COMPILE)objcopy -O binary $^ $@
