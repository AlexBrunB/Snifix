#include <iostream>
#include "SniFix.hpp"

void		    usage(char **av)
{
	int i;

	i = 0;
	while (av[i] != '\0')
	{
		std::string tmp(av[i]);
		if (tmp == "-h")
		{
			std::cout << av[0] << " [-src-ip] <src_ip> " <<
			" [-dst-ip] <dst_ip> [-src-mac] <src_mac> [-dst-mac] <dst_mac> " <<
			" [-proto] <proto> [-port] <port> " << std::endl;
			exit(EXIT_SUCCESS);
		}
		i++;
	}
}

int                 main(int ac, char **av)
{
    snfx::SniFix    snifix(ac, av);

	usage(av);
    try
    {
        snifix.setupSignalHandlers();
        if (!snifix.init())
        {
            std::cout << "Initialisation socket [KO]" << std::endl;
            return (EXIT_FAILURE);
        }
        std::cout << "Initialisation socket [OK]" << std::endl;
        snifix.run();
    } catch (snfx::SignalException &e)
    {
        std::cout << e.what() << std::endl;
    }
    return (EXIT_SUCCESS);
}
