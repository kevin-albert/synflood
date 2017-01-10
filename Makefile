CC		= gcc -Ofast
EXE		= synflood

$(EXE): synflood

clean: 
	rm $(EXE) *.o
