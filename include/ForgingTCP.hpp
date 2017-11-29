#ifndef     __FORGING_HPP__
# define    __FORGING_HPP__

# include   <memory>
# include   <cstdio>
# include   <cstring>
# include   <string>
# include   <cstdlib>
# include   <iostream>
# include   <netinet/tcp.h>
# include   <netinet/ip.h>
# include   <arpa/inet.h>
# include   <unistd.h>
# include   <vector>

typedef struct  contentPacket_s
{
    std::string content;
    std::string src_addr;
    std::string dst_addr;
    int         src_port;
    int         dst_port;
    int         id_packet;
}               contentPacket_t;

typedef struct  fHeaderTCP_s
{
    u_int32_t   src_addr;
    u_int32_t   dst_addr;
    u_int8_t    placeholder;
    u_int8_t    protocol;
    u_int16_t   tcp_length;
}               fHeaderTCP_t;

namespace   snfx
{
    class   ForgingTCP
    {
        public:
            ForgingTCP();
            virtual ~ForgingTCP() {};
            unsigned short calcChecksum(unsigned short *data, int size);
            bool    makePacket(contentPacket_t  &contentPacket);
            bool    sendPacket();
        private:
            std::string content;
            std::string src_addr;
            std::string dst_addr;
            int         src_port;
            int         dst_port;
            int         id_packet;
            bool    initPacket();
            void    fillIph();
            void    fillTcph();
            void    fillPsh();
            int     raw_sock;
            std::unique_ptr<char[]> datagram;
            std::unique_ptr<char[]> src_ip;
            std::unique_ptr<char[]> pseudogram;
            char    *data;
            struct iphdr    *iph;
            struct tcphdr   *tcph;
            struct sockaddr_in  sin;
            fHeaderTCP_t    psh;
            int     psize;
            int     one;
            const int   *val;
    };
};

#endif      //__FORGING_HPP__