#ifndef     __SNIFIX_HPP__
# define    __SNIFIX_HPP__

# include   <memory>
# include   <csignal>
# include   <iostream>
# include   "Socket.hpp"
# include   "Visualize.hpp"
# include   "Packet.hpp"
# include   "SignalHandler.hpp"
# include   "Filter.hpp"
# include   "Record.hpp"
# include   "ForgingTCP.hpp"

namespace   snfx
{

    class   SniFix : public SignalHandler
    {
        public:
            SniFix(const int ac, char **av);
            virtual ~SniFix();
            bool    init();
            bool    run();
        private:
            std::unique_ptr<Socket>     socket;
            std::unique_ptr<Visualize>  visual;
            std::unique_ptr<Packet>     packet;
            std::unique_ptr<Filter>     filter;
            std::unique_ptr<Record>     record;
            std::unique_ptr<ForgingTCP> forgingtcp;
            std::unique_ptr<std::vector<Packet *>>  network_packet;
            struct iphdr                *iph;
            contentPacket_t             contentPacket;
    };
};

#endif      //__SNIFIX_HPP__