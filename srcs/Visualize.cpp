#include    "Visualize.hpp"

snfx::Visualize::Visualize() :
    proto(std::make_unique<std::unordered_map<std::string, pfPacket>>()),
    win_traffic(std::make_unique<WINDOW>())
{
    proto.get()->insert(std::make_pair<std::string, pfPacket>(
        "ARP",
        &snfx::Visualize::showARP
    ));
    proto.get()->insert(std::make_pair<std::string, pfPacket>(
        "ICMP",
        &snfx::Visualize::showICMP
    ));
    proto.get()->insert(std::make_pair<std::string, pfPacket>(
        "TCP",
        &snfx::Visualize::showTCP
    ));
    proto.get()->insert(std::make_pair<std::string, pfPacket>(
	"HTTP",
	&snfx::Visualize::showHTTP
    ));
    proto.get()->insert(std::make_pair<std::string, pfPacket>(
        "UDP",
        &snfx::Visualize::showUDP
    ));
}

void    snfx::Visualize::init()
{
    initscr();
    start_color();
    init_pair(1, COLOR_BLUE, COLOR_BLACK);
    init_pair(2, COLOR_RED, COLOR_WHITE);
    *win_traffic = *makeWindow(stdscr, LINES / 4, COLS, 0, 0);
    wbkgd(win_traffic.get(), COLOR_PAIR(1));
    scrollok(win_traffic.get(), TRUE);
    WINDOW *details = makeWindow(stdscr, LINES / 2, COLS, LINES / 4, 0);
    wbkgd(details, COLOR_PAIR(2));
}

void    snfx::Visualize::end()
{
    endwin();
}

void    snfx::Visualize::showOnePacket(Packet *packet, const int size)
{
    /*int offset = (offset_packet == 0) ? 0 : (LINES / 18) * offset_packet + 1;
    WINDOW *win = makeWindowPacket(win_traffic.get(), offset);
    packet_gui.get()->push_back(win);
    std::stringstream   ss;
    ss  << " N ° " << offset_packet
        << "\t\tSource : " << packet->getSrcIP()
        << "\tDestination : " << packet->getDstIP()
        << "\t\tLength (" << packet->getLenPacket()
        << ")\tProtocol : " << packet->getProtocol() << std::endl;
    writeText(win_traffic.get(), ss.str());
    offset_packet++;
    wscrl(win_traffic.get(), -3);
    wrefresh(win_traffic.get());*/
    printHeader(packet);
    for (auto i = proto.get()->begin(); i != proto.get()->end(); i++)
    {
        if (packet->getProtocol().compare((*i).first) == 0)
            (*this.*i->second)(packet, size);
    }
}

void    snfx::Visualize::showPacket(std::vector<Packet> &packets, const int size)
{
    for (auto &i : packets)
        showOnePacket(&i, size);
}

void    snfx::Visualize::showARP(Packet *packet, const int size)
{
    try
    {
        ARP *arp = dynamic_cast<ARP *>(packet);
        std::cout << "Header ARP" << std::endl
        << "|-> Hardware type : " << arp->getHardwareType() << std::endl
        << "|-> Protocol type : " << arp->getProtocolType() << std::endl
        << "|-> Hardware size : " << arp->getHardwareLength() << std::endl
        << "|-> Protocol size : " << arp->getProtocolLength() << std::endl
        << "|-> Opcode        : " << arp->getARPcode() << std::endl
        << "*****************************************" << std::endl
        << "+---------------- DUMP DATA ------------+" << std::endl
        << "|-> IP Header =>" << std::endl;
        printData(arp->getData(), arp->getIphdrlen());
        std::cout << "|-> ARP Header =>" << std::endl;
        printData(arp->getData() + arp->getIphdrlen(), sizeof(arp->getArph()));
        std::cout << "|-> Data Payload =>" << std::endl;
        int header_size = sizeof(struct ethhdr) + arp->getIphdrlen() + sizeof(arp->getArph());
        printData(arp->getData() + header_size, size - header_size);
    } catch (std::bad_cast &e)
    {
        std::cerr << e.what() << std::endl;
    }
}

void    snfx::Visualize::showICMP(Packet *packet, const int size)
{
    try
    {
        ICMP *icmp = dynamic_cast<ICMP *>(packet);
        std::cout << "Header ICMP" << std::endl
        << "|-> Type : " << icmp->getType() << std::endl
        << "|-> Response: " << icmp->getResponse() << std::endl
        << "|-> Code : " << icmp->getCode() << std::endl
        << "|-> Checksum : " << icmp->getICMPChecksum() << std::endl
        << "*****************************************" << std::endl
        << "+---------------- DUMP DATA ------------+" << std::endl
        << "|-> IP Header =>" << std::endl;
        printData(icmp->getData(), icmp->getIphdrlen());
        std::cout << "|-> UDP Header =>" << std::endl;
        printData(icmp->getData() + icmp->getIphdrlen(), sizeof(icmp->getIcmph()));
        std::cout << "|-> Data Payload =>" << std::endl;
        int header_size = sizeof(struct ethhdr) + icmp->getIphdrlen() + sizeof(icmp->getIcmph());
        printData(icmp->getData() + header_size, size - header_size);
    } catch (std::bad_cast &e)
    {
        std::cerr << e.what() << std::endl;
    }
}

void    snfx::Visualize::showTCP(Packet *packet, const int size)
{
    try
    {
        TCP *tcp = dynamic_cast<TCP *>(packet);
        std::cout << "Header TCP =>" << std::endl
        << "|-> Src Port : " << tcp->getSrcPort() << std::endl
        << "|-> Dst Port : " << tcp->getDstPort() << std::endl
        << "|-> SEQ Num : " << tcp->getSeqNumber() << std::endl
        << "|-> ACK Num : " << tcp->getAckNumber() << std::endl
        << "|-> Length Header : DWORDS(" << tcp->getLenTCPHeader("dwords")
        << ") or BYTES(" << tcp->getLenTCPHeader("bytes") << ")" << std::endl
        << "|-> Urgent Flag : " << tcp->getUrgentFlag() << std::endl
        << "|-> ACK Flag : " << tcp->getAckFlag() << std::endl
        << "|-> PSH Flag : " << tcp->getPshFlag() << std::endl
        << "|-> RST Flag : " << tcp->getRstFlag() << std::endl
        << "|-> SYN Flag : " << tcp->getSynFlag() << std::endl
        << "|-> Fin Flag : " << tcp->getFinFlag() << std::endl
        << "|-> Window : " << tcp->getWindow() << std::endl
        << "|-> Checksum : " << tcp->getTCPChecksum() << std::endl
        << "|-> Urgent Pointer : " << tcp->getUrgentPointer() << std::endl
        << "*****************************************" << std::endl
        << "+---------------- DUMP DATA ------------+" << std::endl
        << "|-> IP Header =>" << std::endl;
        printData(tcp->getData(), tcp->getIphdrlen());
        std::cout << "|-> TCP Header =>" << std::endl;
        printData(tcp->getData() + tcp->getIphdrlen(), tcp->getTcph()->doff * 4);
        std::cout << "|-> Data Payload =>" << std::endl;
        int header_size = sizeof(struct ethhdr) + tcp->getIphdrlen() + tcp->getTcph()->doff * 4;
        printData(tcp->getData() + header_size, size - header_size);
    } catch (std::bad_cast &e)
    {
        std::cerr << e.what() << std::endl;
    }
}

void    snfx::Visualize::showUDP(Packet *packet, const int size)
{
    try
    {
        UDP *udp = dynamic_cast<UDP *>(packet);
        std::cout << "Header UDP =>" << std::endl
        << "|-> Src Port : " << udp->getSrcPort() << std::endl
        << "|-> Dst Port : " << udp->getDstPort() << std::endl
        << "|-> UDP Length : " << udp->getUdpLength() << std::endl
        << "|-> UDP Checksum : " << udp->getUdpChecksum() << std::endl
        << "*****************************************" << std::endl
        << "+---------------- DUMP DATA ------------+" << std::endl
        << "|-> IP Header =>" << std::endl;
        printData(udp->getData(), udp->getIphdrlen());
        std::cout << "|-> UDP Header =>" << std::endl;
        printData(udp->getData() + udp->getIphdrlen(), sizeof(udp->getUdph()));
        std::cout << "|-> Data Payload =>" << std::endl;
        int header_size = sizeof(struct ethhdr) + udp->getIphdrlen() + sizeof(udp->getUdph());
        printData(udp->getData() + header_size, size - header_size);
    } catch (std::bad_cast &e)
    {
        std::cerr << e.what() << std::endl;
    }
}

void    snfx::Visualize::showHTTP(Packet *packet, const int size)
{
    try
    {
        showTCP(packet, size);
        HTTP *http = dynamic_cast<HTTP *>(packet);
        std::cout << "Header HTTP =>" << std::endl
		  << "|-> " << http->getFirstLine() << std::endl
		  << "|--> Type : " << http->getInfo() << std::endl
		  << "|--> Version : " << http->getVersion() << std::endl;
	if (!http->getInfo().compare("Response"))
	  {
	    std::cout << "|--> Status : " << http->getStatus() << std::endl
		      << "|--> Response : " << http->getResponsePhrase() << std::endl;
	  }
	else
	  {
	    std::cout << "|--> Method : " << http->getMethod() << std::endl
		      << "|--> Uri : " << http->getUri() << std::endl
		      << "|-> Host : " << http->getHost() << std::endl
		      << "|-> User-Agent : " << http->getUserAgent() << std::endl;
	  }
	std::cout << "|-> Connection : " << http->getConnection() << std::endl
		  << "|-> Http Header length : " << http->getHttpHeaderLength() << std::endl;
	/*if (!http->getContent().empty())
	  {
	    std::cout << "|-> Content : " << std::endl
		      << http->getContent() << std::endl;
	  }*/
    } catch (std::bad_cast &e)
    {
        std::cerr << e.what() << std::endl;
    }
}

void    snfx::Visualize::printHeader(Packet *packet)
{
    std::stringstream   ss;
    ss << "Header =>" << std::endl
    << "|-> Protocol : " << packet->getProtocol() << std::endl
    << "|-> IP Version : " << packet->getIpVersion() << std::endl
    << "|-> Length Header : DWORDS(" << packet->getLenHeader("dwords")
    << ") or BYTES(" << packet->getLenHeader("bytes") << ")" << std::endl
    << "|-> TTL : " << packet->getTTL() << std::endl
    << "|-> Length Packet : " << packet->getLenPacket() << std::endl
    << "|-> Checksum : " << packet->getChecksum() << std::endl
    << "|-> ID Packet : " << packet->getIdPacket() << std::endl
    << "|-> Src MAC : " << packet->getSrcMAC() << std::endl
    << "|-> Dst MAC : " << packet->getDstMAC() << std::endl
    << "|-> Src IP : " << packet->getSrcIP() << std::endl
    << "|-> Dst IP : " << packet->getDstIP() << std::endl;
    std::cout << ss.str() << std::endl;
   // writeText(win_traffic.get(), ss.str());
}

void    snfx::Visualize::printData(unsigned char *data, const int Size) const
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)
        {
            printf("\t");
            for(j=i-16 ; j<i ; j++)
            {
                if((unsigned char)data[j]>=32 && (unsigned char)data[j]<=128)
                    printf("%c",(unsigned char)data[j]);
                 
                else printf(".");
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   ");
            }
             
            printf("\t");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if((unsigned char)data[j]>=32 && (unsigned char)data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
                }
            }
             
            printf("\n");
        }
    }
}

WINDOW  *snfx::Visualize::makeWindow(WINDOW *win_ref,
    int height, int width, int start_x, int start_y)
{
    WINDOW  *win;

    win = subwin(win_ref, height, width, start_x, start_y);
    box(win, ACS_VLINE, ACS_HLINE);
    wrefresh(win);
    return (win);
}

WINDOW  *snfx::Visualize::makeWindowPacket(WINDOW *win_ref, int start_y)
{
    WINDOW  *win;

    (void)start_y;
    win = subwin(win_ref, LINES / 18, COLS, 1, 1);
    box(win, ACS_VLINE, ACS_HLINE);
    wrefresh(win);
    return (win);
}

void    snfx::Visualize::writeText(WINDOW *win, const std::string &str)
{
    wprintw(win, str.c_str());
    box(win, ACS_VLINE, ACS_HLINE);
    wrefresh(win);
}
