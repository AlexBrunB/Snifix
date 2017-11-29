CC			=	g++

CPPFLAGS	=	-W -Wall -Wextra -Werror -std=c++17 -g3
CPPFLAGS	+=	-I./include

RM			=	rm -f

NAME_SNIFIX	=	snifix

SRCS_REPO	=	./srcs/

SRCS_SNIFIX	=	$(SRCS_REPO)ARP.cpp				\
				$(SRCS_REPO)Filter.cpp			\
				$(SRCS_REPO)ICMP.cpp			\
				$(SRCS_REPO)main.cpp			\
				$(SRCS_REPO)Packet.cpp			\
				$(SRCS_REPO)PacketFactory.cpp	\
				$(SRCS_REPO)Record.cpp			\
				$(SRCS_REPO)SniFix.cpp			\
				$(SRCS_REPO)Socket.cpp			\
				$(SRCS_REPO)TCP.cpp				\
				$(SRCS_REPO)UDP.cpp				\
				$(SRCS_REPO)Visualize.cpp		\
				$(SRCS_REPO)SignalHandler.cpp		\
				$(SRCS_REPO)HTTP.cpp			\
				$(SRCS_REPO)ForgingTCP.cpp

OBJS_SNIFIX	=	$(SRCS_SNIFIX:.cpp=.o)

all:			snifix

#snifix:		$(NAME_SNIFIX)

$(NAME_SNIFIX):	$(OBJS_SNIFIX)
				$(CC) $(CPPFLAGS) $(OBJS_SNIFIX) -o $(NAME_SNIFIX) -lncurses -lpcap

clean:
				$(RM) $(OBJS_SNIFIX)
				$(RM) $(OBJS_SNIFIX)

fclean:			clean
				$(RM) $(NAME_SNIFIX)
				$(RM) $(NAME_SNIFIX)

re:				fclean all

.PHONY:			all snifix clean fclean re
