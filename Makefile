CC		= gcc -Ofast
EXE		= synflood

ifneq ($(shell uname -s),Darwin)
	CC += -pthread
endif

$(EXE): synflood

clean: 
	rm $(EXE) *.o
