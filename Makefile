all: htdissect.exe

htdissect.exe: htdissect.obj
	link /nologo htdissect.obj

htdissect.obj: htdissect.cpp
	cl /nologo /Wall /Fo htdissect.obj htdissect.cpp

clean:
	del htdissect.exe htdissect.obj 2> nul
