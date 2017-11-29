#include "Socket.hpp"

snfx::Socket::Socket() :
    buffer(nullptr),
    s_addr_size(0),
    sizebuff(0),
    raw_sock(0)
{
}

snfx::Socket::~Socket()
{

}

bool    snfx::Socket::init()
{
    buffer = std::make_unique<unsigned char[]>(snfx::max_buff + 1);
    if (buffer == nullptr)
    {
        std::cerr << "Malloc failure" << std::endl;
        return (false);
    }
    if ((raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == snfx::sock_err)
    {
        std::cerr << "Socket error" << std::endl;
        return (false);
    }
    return (true);
}

unsigned char                *snfx::Socket::getData()
{
    std::memset(buffer.get(), 0, 0);
    s_addr_size = sizeof(s_addr);
    sizebuff = recvfrom(raw_sock, buffer.get(), snfx::max_buff, 0, &s_addr, &s_addr_size);
    if (sizebuff < 0)
    {
        std::cerr << "recvfrom error" << std::endl;
        return (nullptr);
    }
    return (buffer.get());
}

bool                snfx::Socket::close_sock()
{
    if (close(raw_sock) != snfx::sock_err)
        return (true);
    return (false);
}

int                 snfx::Socket::getSizebuff() const
{
    return (this->sizebuff);
}