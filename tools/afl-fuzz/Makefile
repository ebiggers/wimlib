SRC := $(wildcard */*.c)
EXE := $(SRC:.c=)

LDLIBS := -lwim
LDFLAGS := -L../../.libs
CPPFLAGS := -I../../include

all:$(EXE)

clean:
	rm -f $(EXE)
