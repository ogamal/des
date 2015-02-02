CC = gcc

NAME = des
EXEC = $(NAME).out
HEADERS = tables.h

all: $(EXEC)

clean:
	rm -f $(EXEC)

$(EXEC): $(NAME).c $(HEADERS)
	$(CC) $(NAME).c -o $(EXEC)

