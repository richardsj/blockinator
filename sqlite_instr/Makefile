CC=gcc

all: instr.sqlext

instr.sqlext: sqlite_instr.c
	$(CC) -shared -fPIC -Isqlite3 -o instr.sqlext sqlite_instr.c
