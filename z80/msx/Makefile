ifeq ($(strip $(N80)),)
N80=N80
endif

export N80_ARGS=--no-show-banner --verbosity 0 --output-file-case lower

ifeq ($(strip $(LK80)),)
LK80=LK80
endif

export LK80_ARGS=--no-show-banner --verbosity 0 --output-file-case lower --output-format bin

define assemble
	@printf "\n\033[0;36mAssembling %s\033[0m\n\n" $(1)
	@$(N80) $(1) $(2)
endef

RELFILES := ../aes.rel ../aes-gcm.rel ../client_hello.rel ../hkdf.rel ../hmac.rel ../p256.rel ../record_encryption.rel ../record_receiver.rel ../server_hello.rel ../sha256.rel ../tls_connection.rel unapi.rel
TOOLS := tlscon.com

all: $(TOOLS)

tlscon: tlscon.com

tlscon.com: $(RELFILES) tlscon.rel
	@$(LK80) -vb 3 --output-file tlscon.com --code 0100h tlscon.rel --code 1d00h aes.rel aes-gcm.rel tls_connection.rel unapi.rel server_hello.rel client_hello.rel hkdf.rel hmac.rel record_encryption.rel record_receiver.rel sha256.rel p256.rel

.SECONDEXPANSION:
$(RELFILES): ../tls_connection_constants.asm $$(patsubst %.rel,%.asm,$$@)
	$(call assemble,$(patsubst %.rel,%.asm,$@))

tlscon.rel: tlscon.asm
	$(call assemble,tlscon.asm)
