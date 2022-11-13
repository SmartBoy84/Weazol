#needed for ld to work
APP:=amfi_launcher
FILE:=*.c
ENT:=

TOOLCHAIN=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin
SDK=$(THEOS)/SDKs/iPhoneOS14.5.sdk

INCLUDE=-I. -L.
ARCH=-target arm64e-apple-ios14.4 -arch arm64e
CUSTOM=-isysroot $(SDK) -framework Foundation -framework CoreFoundation
#-I. -Iinclude -Linclude -L.

IP:=le-carote
ADDR:=root@$(IP)
PORT:=44
UPLOAD_DIR:=/binpack

# end of configurable variables
green=\033[0;32m
red=\033[0;31m
blue=\033[0;34m
end=\033[0m
arrow=$(red)=> $(end)
MUTE= 2>/dev/null; true

RERUN=$(MAKE) --no-print-directory

FLAGS=$(INCLUDE) $(ARCH) $(CUSTOM)

all: build sign
do: build sign upload

build:
	@echo "$(arrow)$(green)Compiling ${FILE} to ${APP}$(end)"
	@$(TOOLCHAIN)/clang ${FLAGS} ${FILE} -o ${APP}

sign:
	@echo "$(arrow)$(green)Signing ${APP}$(red)"
	@chmod +x ${APP}
	@ldid -S$(ENT) $(APP)
	@$(TOOLCHAIN)/trustcache create $(APP).tc $(APP)

upload:
	@echo "$(arrow)$(green)Uploading ${APP}$(end)"
	-@ssh -p $(PORT) $(ADDR) "rm $(UPLOAD_DIR)/$(APP)"
	@scp -P $(PORT) ${APP} ${APP}.tc ${ADDR}:${UPLOAD_DIR}

run:
	@if ! ssh -p $(PORT) $(ADDR) "stat $(UPLOAD_DIR)/$(APP)" >/dev/null; then (echo "$(arrow)$(red)Build the app first!$(end)"; $(RERUN); $(RERUN) upload); fi

	@echo "$(arrow)$(green)Running ${APP}$(red)"
	ssh -p $(PORT) $(ADDR) "$(UPLOAD_DIR)/${APP}"

clean:
	@echo "$(arrow)$(green)Cleaning up!$(end)"
	@rm ${APP}
