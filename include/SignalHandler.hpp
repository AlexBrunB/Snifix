#ifndef     __SIGNALHANDLER_HPP__
# define    __SIGNALHANDLER_HPP__

# include   <stdexcept>
# include   <errno.h>
# include   <csignal>
# include   <iostream>

namespace   snfx
{
    class   SignalException : public std::runtime_error
    {
        public:
            SignalException(const std::string &message) :
                std::runtime_error(message) {}
    };

    class   SignalHandler
    {
        public:
            SignalHandler();
            virtual ~SignalHandler();

            static bool getExitSignal();
            static void setExitSignal(const bool _flag);
            static void exitSignalHandler(int _ignored);
            void        setupSignalHandlers();
        protected:
            static bool exitSignal;
    };
};

#endif      //__SIGNALHANDLER_HPP__