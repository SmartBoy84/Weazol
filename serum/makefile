APP:=pspboi
APP_FILE:=main.c src/*.c -Iinclude -I. -L. -Iheaders -Lheaders
ENT:=ent.plist
APP_FLAG:=

DYLIB_FOLDER:=payload

DYLD_DYLIB:=interpose_vamos.dylib
DYLD_DYLIB_FOLDER:=payload/dyld_payload
DYLD_DYLIB_FILE:=${DYLIB_FOLDER}/*.c ${DYLD_DYLIB_FOLDER}/*.c src/*.c -I${DYLIB_FOLDER} -I${DYLD_DYLIB_FOLDER} -Iinclude -Linclude -I. -L. -Iheaders -Lheaders
DYLD_DYLIB_FLAG:=-arch arm64e -dynamiclib -framework Foundation -DCOMMONCRYPTO

FISHOOK_DYLIB:=fishook_vamos.dylib
FISHOOK_DYLIB_FOLDER:=payload/fishook_payload
FISHOOK_DYLIB_FILE:=${DYLIB_FOLDER}/*.c ${FISHOOK_DYLIB_FOLDER}/*.c src/*.c -I${DYLIB_FOLDER} -I${FISHOOK_DYLIB_FOLDER} -Iinclude -Linclude -I. -L. -Iheaders -Lheaders
FISHOOK_DYLIB_FLAG:=-arch arm64e -dynamiclib -framework Foundation -DCOMMONCRYPTO

INCLUDE:=
TOOLCHAIN:=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/aarch64-apple-darwin-clang
ARCH=-target arm64e-apple-ios14.4 -arch arm64e
CUSTOM=-isysroot "$(THEOS)/sdks/iPhoneOS14.5.sdk" -DCOMMONCRYPTO
#-I. -Iinclude -Linclude -L.

IP:=le-carote
ADDR:=root@$(IP)
PORT:=44
UPLOAD_DIR:=/binpack
TRUST_BIN:=/binpack/trust

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
do: build sign upload clean

build:
	@echo "$(arrow)$(green)Compiling...$(end)"
	@${CC} ${FLAGS} ${APP_FILE} -o ${APP}
	@${CC} ${FLAGS} ${DYLD_DYLIB_FILE} ${DYLD_DYLIB_FLAG} -o ${DYLD_DYLIB}
	@${CC} ${FLAGS} ${FISHOOK_DYLIB_FILE} ${FISHOOK_DYLIB_FLAG} -o ${FISHOOK_DYLIB}

sign:
	@echo "$(arrow)$(green)Signing...$(red)"
	@chmod +x ${APP}
	@ldid -S$(ENT) $(APP)
	@ldid -S$(ENT) $(FISHOOK_DYLIB)
	@ldid -S$(ENT) $(DYLD_DYLIB)

upload:
	@echo "$(arrow)$(green)Uploading ${APP}$(end)"
	-@ssh -p $(PORT) $(ADDR) "rm $(UPLOAD_DIR)/$(APP) $(UPLOAD_DIR)/$(DYLD_DYLIB) $(UPLOAD_DIR)/$(FISHOOK_DYLIB)"
	@scp -P $(PORT) ${APP} $(FISHOOK_DYLIB) $(DYLD_DYLIB) ${ADDR}:${UPLOAD_DIR}

run:
	@echo "$(arrow)$(green)Running ${APP}$(red)"
	-ssh -p $(PORT) $(ADDR) "$(TRUST_BIN) $(UPLOAD_DIR)/$(APP)"
	ssh -p $(PORT) $(ADDR) "$(UPLOAD_DIR)/${APP}"

clean:
	@echo "$(arrow)$(green)Cleaning up!$(end)"
	@rm ${APP} $(DYLD_DYLIB) $(FISHOOK_DYLIB)
