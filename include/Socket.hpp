#ifndef                 __SOCKET_HPP__
# define                __SOCKET_HPP__

# include               <cstdint>
# include               <iostream>
# include               <unistd.h>
# include               <sys/types.h>
# include               <sys/socket.h>
# include               <arpa/inet.h>
# include               <netinet/ip.h>
# include               <netinet/if_ether.h>
# include               <string>
# include               "PacketFactory.hpp"

namespace               snfx
{
    const int           sock_err    = -1;
    const int           max_buff    = 65536;

    class               Socket
    {
        public:
                        Socket();
                virtual ~Socket();
                bool    init();
                unsigned char    *getData();
                int     getSizebuff() const;
                bool    close_sock();
        private:
                struct sockaddr_in  s_src;
                struct sockaddr_in  s_dst;
                struct sockaddr     s_addr;
                struct in_addr      s_in;
                std::unique_ptr<unsigned char[]> buffer;
                socklen_t           s_addr_size;
                int                 sizebuff;
                int                 raw_sock;
    };
};

#endif                  //__SOCKET_HPP__