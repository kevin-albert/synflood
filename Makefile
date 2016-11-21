CC		= gcc -Ofast
EXE		= synflood

ifneq ($(shell uname -s),Darwin)
	CC += -pthread
endif

$(EXE): synflood.o 

clean: 
	rm $(EXE) *.o
