#ifndef     __VISUALIZE_HPP__
# define    __VISUALIZE_HPP__

# include   <vector>
# include   <memory>
# include   <sstream>
# include   <unordered_map>
# include   <ncurses.h>
# include   <menu.h>
# include   "Packet.hpp"
# include   "ARP.hpp"
# include   "ICMP.hpp"
# include   "TCP.hpp"
# include   "UDP.hpp"
# include   "HTTP.hpp"

namespace   snfx
{
    class   Visualize
    {
        typedef void    (snfx::Visualize::*pfPacket)(Packet *, const int);
        public:
            Visualize();
            virtual ~Visualize() {};
            void    init();
            void    end();
            void    showOnePacket(Packet *packet, const int size);
            void    showPacket(std::vector<Packet> &packets, const int size);
            void    showARP(Packet *packet, const int size);
            void    showICMP(Packet *packet, const int size);
            void    showTCP(Packet *packet, const int size);
            void    showUDP(Packet *packet, const int size);
	    void    showHTTP(Packet *packet, const int size);
            void    printHeader(Packet *packet);
            void    printData(unsigned char *data, const int size) const;
            WINDOW  *makeWindow(WINDOW *win_ref, int height, int width, int start_x, int start_y);
            WINDOW  *makeWindowPacket(WINDOW *win_ref, int start_y);
            void    writeText(WINDOW *win, const std::string &str);
        private:
            std::unique_ptr<std::unordered_map<std::string, pfPacket>>  proto;
            std::unique_ptr<WINDOW> win_traffic;
            std::unique_ptr<MENU>   packet_list;
    };
};

#endif      //__VISUALIZE_HPP__
