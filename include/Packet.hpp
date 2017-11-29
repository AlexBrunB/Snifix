#ifndef                 __PACKET_HPP__
# define                __PACKET_HPP__

# include               <cstdint>
# include               <iostream>
# include               <string>
# include               <memory>
# include               <sstream>
# include               <cstring>
# include               <netinet/if_ether.h>
# include               <netinet/in.h>
# include               <netinet/ip.h>
# include               <arpa/inet.h>

namespace               snfx
{
    class               Packet
    {
        public:
            explicit    Packet(unsigned char *_data);
            virtual     ~Packet() = 0;
            std::string &getSrcMAC();
            std::string &getDstMAC();
            std::string &getSrcIP();
            std::string &getDstIP();
            uint64_t    getIpVersion() const;
            uint64_t    getLenHeader(const std::string &_type) const;
            uint64_t    getTTL() const;
            uint64_t    getLenPacket() const;
            uint64_t    getChecksum() const;
            uint64_t    getIdPacket() const;
            virtual std::string &getProtocol() = 0;
            unsigned char *getData();
            unsigned short  getIphdrlen() const;
            struct ethhdr   *getEthhdr() const;
            struct iphdr    *getIphdr() const;
        protected:
            std::string src_mac;
            std::string dst_mac;
            std::string src_ip;
            std::string dst_ip;
            uint64_t    ip_version;
            uint64_t    len_head_dwords;
            uint64_t    len_head_bytes;
            uint64_t    ttl;
            uint64_t    len_packet;
            uint64_t    checksum;
            uint64_t    id_packet;
            unsigned char   *data;
            struct ethhdr   *eth;
            struct iphdr    *iph;
            unsigned short iphdrlen;
            struct sockaddr_in  s_src;
            struct sockaddr_in  s_dst;
    };
};

#endif                  //__PACKET_HPP__