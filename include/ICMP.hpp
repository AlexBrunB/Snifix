#ifndef     __ICMP_HPP__
# define    __ICMP_HPP__

# include   <string>
# include   <netinet/ip_icmp.h>
# include   "Packet.hpp"

namespace   snfx
{
    class   ICMP : public Packet
    {
        public:
                ICMP();
                ICMP(unsigned char *_data);
            virtual ~ICMP() {};
            struct icmphdr  *getIcmph() const;
            std::string     &getProtocol();
            std::string     &getResponse();
            uint64_t        getType() const;
            uint64_t        getCode() const;
            uint64_t        getICMPChecksum() const;
        private:
            struct icmphdr  *icmph;
            std::string     protocol;
            std::string     response;
            uint64_t    type;
            uint64_t    code;
            uint64_t    icmp_checksum;
    };
};

#endif      //__ICMP_HPP__