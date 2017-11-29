#include    "SignalHandler.hpp"

bool    snfx::SignalHandler::exitSignal = false;

snfx::SignalHandler::SignalHandler()
{

}

snfx::SignalHandler::~SignalHandler()
{

}

bool    snfx::SignalHandler::getExitSignal()
{
    return (exitSignal);
}

void    snfx::SignalHandler::setExitSignal(const bool _flag)
{
    exitSignal = _flag;
}

void    snfx::SignalHandler::exitSignalHandler(int _ignored)
{
    (void)_ignored;
    exitSignal = true;
}

void    snfx::SignalHandler::setupSignalHandlers()
{
    if (std::signal(SIGINT, SignalHandler::exitSignalHandler) == SIG_ERR)
    {
        throw SignalException(" Error settings up signal handlers");
    }
}