SOURCES += $(wildcard *.cpp) $(wildcard common/*.cpp)
CPPFLAGS += -D_FILE_OFFSET_BITS=64


FLAKYFLASH_OBJECTS := $(addprefix $(OBJDIR)/,flakyflash.o $(addprefix common/,cli.o fd.o format.o))
FLAKYFLASH := $(BINDIR)/flakyflash$(EXEC_SUFFIX)
ALL += $(FLAKYFLASH)

$(OBJDIR)/flakyflash.o : CXXFLAGS += -Wno-attributes
$(FLAKYFLASH) : $(FLAKYFLASH_OBJECTS)
	$(DO_LINK.cpp)
