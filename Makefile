cc=cl
link=link
cflags=/c /nologo /Wall
# cflags=/c /nologo
linkflags=/nologo

all: htdissect.exe

htdissect.exe: htdissect.obj dasm.obj
	$(link) $(linkflags) htdissect.obj dasm.obj

htdissect.obj: htdissect.cpp dasm.h
#	cl $(cflags) /Fo:htdissect.obj htdissect.cpp

dasm.obj: dasm.c dasm.h
#  cl $(cflags) /Fo:dasm.obj dasm.c

.cpp.obj:
	$(cc) $(cflags) $*.cpp

.c.obj:
	$(cc) $(cflags) $*.c

clean:
	del htdissect.exe htdissect.obj 2> nul
