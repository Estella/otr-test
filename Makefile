CFLAGS = -Wall -Wextra -Werror -I~/build/libotr/src
LDFLAGS = -lreadline -lpthread -lgcrypt -lotr #-Wl,-rpath ~/build/libotr/src/.libs/ -lotr

all: libotr

clean:
	rm -f libotr
