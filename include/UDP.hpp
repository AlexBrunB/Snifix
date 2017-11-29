#ifndef     __UDP_HPP__
# define    __UDP_HPP__

# include   <string>
# include   <netinet/udp.h>
# include   "Packet.hpp"

namespace   snfx
{
    class   UDP : public Packet
    {
        public:
                    UDP();
                    UDP(unsigned char *_data);
            virtual ~UDP() {};
            struct udphdr   *getUdph() const;
            std::string &getProtocol();
            uint64_t    getSrcPort() const;
            uint64_t    getDstPort() const;
            uint64_t    getUdpLength() const;
            uint64_t    getUdpChecksum() const;
        private:
            struct udphdr   *udph;
            std::string protocol;
            uint64_t    src_port;
            uint64_t    dst_port;
            uint64_t    udp_length;
            uint64_t    udp_checksum;
    };
};

#endif      //__UDP_HPP__