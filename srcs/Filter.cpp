#include    "Filter.hpp"

snfx::Filter::Filter(const int ac, char **av) :
    param(std::make_unique<std::vector<std::string>>()),
    filter(std::make_unique<std::unordered_map<
            std::string, std::string
    >>()),
    nbFilter(0)
{
    int i;

    i = 0;
    while (i < ac)
    {
        param.get()->push_back(std::string(av[i]));
        i++;
    }
    filter.get()->insert(std::make_pair<std::string, std::string>(
        "-src-ip", ""
    ));
    filter.get()->insert(std::make_pair<std::string, std::string>(
        "-dst-ip", ""
    ));
    filter.get()->insert(std::make_pair<std::string, std::string>(
        "-src-mac", ""
    ));
    filter.get()->insert(std::make_pair<std::string, std::string>(
        "-dst-mac", ""
    ));
    filter.get()->insert(std::make_pair<std::string, std::string>(
        "-proto", ""
    ));
    filter.get()->insert(std::make_pair<std::string, std::string>(
        "-port", ""
    ));
}

void    snfx::Filter::printParam()
{
    for (auto it = param.get()->begin(); it != param.get()->end(); it++)
        std::cout << *(it) << std::endl;
}

void    snfx::Filter::printFilter()
{
    std::cout << "+++++++++++++++++++++++++++++++++++++" << std::endl;
    for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
        std::cout << (*it).first << " : " << (*it).second << std::endl;
    std::cout << "-------------------------------------" << std::endl;
}

void    snfx::Filter::loadFilter()
{
    for (auto i = param.get()->begin(); i != param.get()->end(); i++)
    {
        for (auto j = filter.get()->begin(); j != filter.get()->end(); j++)
        {
            if ((*i).compare((*j).first) == 0)
            {
                if ((i+1) != param.get()->end() && (*(i+1))[0] != '-')
                    (*j).second = *(i+1);
            }
        }
    }
}

bool    snfx::Filter::activeFilter()
{
    nbFilter = 0;
    for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
    {
        if (!(*it).second.empty())
            nbFilter++;
    }
    return ((nbFilter > 0) ? true : false);
}

bool    snfx::Filter::checkPacket(Packet *packet)
{
    int check;

    check = 0;
    if (isFilterSrcIp(packet->getSrcIP()))
        check++;
    if (isFilterDstIp(packet->getDstIP()))
        check++;
    if (isFilterSrcMac(packet->getSrcMAC()))
        check++;
    if (isFilterDstMac(packet->getDstMAC()))
        check++;
    if (isFilterProtocol(packet->getProtocol()))
        check++;
    //if (isFilterPort(packet))
      //  check++;
    return ((nbFilter == check) ? true : false);
}

bool    snfx::Filter::isFilterSrcIp(const std::string &src_ip)
{
    for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
    {
        if ((*it).first.compare("-src-ip") == 0 &&
            (*it).second.compare(src_ip) == 0)
            return (true);
    }
    return (false);
}

bool    snfx::Filter::isFilterDstIp(const std::string &dst_ip)
{
    for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
    {
        if ((*it).first.compare("-dst-ip") == 0 &&
            (*it).second.compare(dst_ip) == 0)
            return (true);
    }
    return (false);
}

bool    snfx::Filter::isFilterSrcMac(const std::string &src_mac)
{
    for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
    {
        if ((*it).first.compare("-src-mac") == 0 &&
            (*it).second.compare(src_mac) == 0)
            return (true);
    }
    return (false);
}

bool    snfx::Filter::isFilterDstMac(const std::string &dst_mac)
{
    for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
    {
        if ((*it).first.compare("-dst-mac") == 0 &&
            (*it).second.compare(dst_mac) == 0)
            return (true);
    }
    return (false);
}

bool    snfx::Filter::isFilterProtocol(const std::string &protocol)
{
    for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
    {
        if ((*it).first.compare("-proto") == 0 &&
            (*it).second.compare(protocol) == 0)
            return (true);
    }
    return (false);
}

bool    snfx::Filter::isFilterPort(Packet *packet)
{
    int port;
    std::cout << packet << std::endl;
    port = 0;
    switch (isGoodCast(packet))
    {
        case 1:
            {
                try
                {
                    TCP *tcp = dynamic_cast<TCP *>(packet);
                    std::cout << tcp << std::endl;
                    port = tcp->getDstPort();
                } catch (std::bad_cast &e) {
                    std::cout << e.what() << std::endl;
                }
                break;
            }
        case 2:
            {
                try
                {
                    TCP *tcp = dynamic_cast<TCP *>(packet);
                    port = tcp->getDstPort();
                } catch (std::bad_cast &e) {
                    std::cout << e.what() << std::endl;
                }
                break;
            }
        default:
            break;
    }
    if (port != 0)
    {
        for (auto it = filter.get()->begin(); it != filter.get()->end(); it++)
        {
            if ((*it).first.compare("-port") == 0)
            {
                int  p = (int)(std::atoi((*it).second.c_str()));
                return ((port == p) ? true : false);
            }
        }
    }
    return (false);
}

int     snfx::Filter::isGoodCast(Packet *packet)
{
    try
    {
        TCP *tcp = dynamic_cast<TCP *>(packet);
        (void)tcp;
        return (1);
    } catch (std::bad_cast &e)
    {
        try
        {
            UDP *udp = dynamic_cast<UDP *>(packet);
            (void)udp;
            return (2);
        } catch (std::bad_cast &e)
        {
            return (-1);
        }
    }
    return (0);
}