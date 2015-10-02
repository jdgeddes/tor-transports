CC = gcc 
CFLAGS = -fPIC -Wall -Wextra -O2 -g 
LDFLAGS = -shared -ldl -lrt -lm
RM = rm -f  
LIBS = libxtcp_template.so libxtcp_utp.so

SRCS = xtcp_util.c xtcp_template.c xtcp_utp.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${LIBS}

libxtcp_template.so: xtcp_template.o xtcp_util.o
	$(CC) ${LDFLAGS} -o $@ $^ 

libxtcp_utp.so: xtcp_utp.o xtcp_util.o
	cd ./libs/libutp/ && make && cp libutp.so ../../
	$(CC) ${LDFLAGS} -o $@ $^ -L./libs/libutp -lutp -ldl

$(SRCS:.c=.d):%.d:%.c
		$(CC) $(CFLAGS) -MM $< >$@

.PHONY: clean
clean:
	-${RM} ${LIBS} ${OBJS} $(SRCS:.c=.d) $(SRCS:.c=.o)
