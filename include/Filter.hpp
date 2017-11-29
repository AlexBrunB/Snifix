#ifndef     __FILTER_HPP__
# define    __FILTER_HPP__

# include   <memory>
# include   <unordered_map>
# include   <vector>
# include   <string>
# include   <iostream>
# include   "TCP.hpp"
# include   "UDP.hpp"

namespace   snfx
{
    class   Filter
    {
        public:
            Filter(const int ac, char **av);
            virtual ~Filter() {};
            void    printParam();
            void    printFilter();
            void    loadFilter();
            bool    activeFilter();
            bool    checkPacket(Packet *packet);
            bool    isFilterSrcIp(const std::string &src_ip);
            bool    isFilterDstIp(const std::string &dst_ip);
            bool    isFilterSrcMac(const std::string &src_mac);
            bool    isFilterDstMac(const std::string &dst_mac);
            bool    isFilterProtocol(const std::string &protocol);
            bool    isFilterPort(Packet *packet);
            int     isGoodCast(Packet *packet);
        private:
            std::unique_ptr<std::vector<std::string>>   param;
            std::unique_ptr<std::unordered_map<std::string, std::string>>       filter;
            int     nbFilter;
            struct  tcphdr  *tpch;
            struct  udphdr  *udph;
    };
};

#endif      //__FILTER_HPP__