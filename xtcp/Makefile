CC = gcc 
CFLAGS = -fPIC -Wall -Wextra -O2 -g `pkg-config --cflags glib-2.0` -I${HOME}/.local/include/
LDFLAGS = -L${HOME}/.local/lib/ -shared -ldl -lrt -lm `pkg-config --libs glib-2.0` 
RM = rm -f  
LIBS = libxtcp_template.so libxtcp_utp.so libxtcp_lkl.so

SRCS = xtcp_util.c xtcp_template.c xtcp_utp.c xtcp_lkl.c xlate.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${LIBS}

libxtcp_template.so: xtcp_template.o xtcp_util.o
	$(CC) ${LDFLAGS} -o $@ $^ ${LDFLAGS}

libxtcp_utp.so: xtcp_utp.o xtcp_util.o
	cd ./libs/libutp/ && make && cp libutp.* ${HOME}/.local/lib/
	$(CC) ${LDFLAGS} -o $@ $^ -L${HOME}/.local/lib/ -lutp ${LDFLAGS}

libxtcp_lkl.so: xtcp_lkl.o xtcp_util.o xlate.o
	$(CC) ${LDFLAGS} -o $@ $^ -L${HOME}/.local/lib/  -llkl ${LDFLAGS}

$(SRCS:.c=.d):%.d:%.c
		$(CC) $(CFLAGS) -MM $< >$@

.PHONY: clean
clean:
	-${RM} ${LIBS} ${OBJS} $(SRCS:.c=.d) $(SRCS:.c=.o)
