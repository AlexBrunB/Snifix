#include "SniFix.hpp"

snfx::SniFix::SniFix(const int ac, char **av) :
    socket(std::make_unique<snfx::Socket>()),
    visual(std::make_unique<snfx::Visualize>()),
    packet(nullptr),
    filter(std::make_unique<snfx::Filter>(ac, av)),
    record(std::make_unique<snfx::Record>("out.pcap")),
    forgingtcp(std::make_unique<snfx::ForgingTCP>()),
    network_packet(std::make_unique<std::vector<snfx::Packet *>>())
{
    contentPacket.content = "Hello World\n";
    contentPacket.src_addr = "127.0.0.1";
    contentPacket.dst_addr = "127.0.0.1";
    contentPacket.id_packet = 54321;
    contentPacket.src_port = 5656;
    contentPacket.dst_port = 4444;
}

snfx::SniFix::~SniFix()
{

}

bool        snfx::SniFix::init()
{
    //filter.get()->printParam();
    filter.get()->loadFilter();
    //filter.get()->printFilter();
    record.get()->writeGlobalHeader();
    if (socket.get()->init())
        return (true);
    return (false);
}

bool        snfx::SniFix::run()
{
    unsigned char    *data;

   while (!getExitSignal())
    {
        if (forgingtcp.get()->makePacket(contentPacket))
            //forgingtcp.get()->sendPacket();
        data = nullptr;
        if ((data = socket.get()->getData()) != nullptr)
        {
            iph = (struct iphdr *)(data + sizeof(struct ethhdr));
            packet = snfx::PacketFactory::makePacket(
                (uint64_t)iph->protocol,
                data
            );
            if (packet != nullptr)
            {
                network_packet.get()->push_back(packet.get());
                if (filter.get()->activeFilter())
                {
                    if (filter.get()->checkPacket(packet.get()))
                    {
                        visual.get()->showOnePacket(packet.get(), socket.get()->getSizebuff());
                        record.get()->writePacketData(packet.get(), socket.get()->getSizebuff());
                    }
                }
                else
                {
                    visual.get()->showOnePacket(packet.get(), socket.get()->getSizebuff());
                    record.get()->writePacketData(packet.get(), socket.get()->getSizebuff());
                }
            }
        }
        else
            std::cout << "data null" << std::endl;
    }
    
    socket.get()->close_sock();
    return (true);
}