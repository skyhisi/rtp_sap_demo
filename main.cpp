/*
 Copyright (c) 2023 Silas Parker

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <iostream>
#include <string>
#include <cstdint>

#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

#include "announcement_handler.hpp"
#include "session_manager.hpp"


namespace po = boost::program_options;
namespace asio = boost::asio;

static bool parse_arguments(int argc, char** argv, po::variables_map& po_vars)
{
    po::options_description po_desc("RTP SAP Playback");
    po_desc.add_options()
        ("help,h", "Help message")
        ("announce_addr", po::value<std::string>()->default_value("224.2.127.254"), "SAP announcement address")
        ("announce_port", po::value<uint16_t>()->default_value(9875), "SAP announcement port")
        ("verbose,v", "Verbose logging")
    ;

    po::store(po::parse_command_line(argc, argv, po_desc), po_vars);
    po::notify(po_vars);

    if (po_vars.count("help")) {
        std::cerr << po_desc << std::endl;
        return false;
    }
    return true;
}


int main(int argc, char** argv)
{
    po::variables_map po_vars;
    if (!parse_arguments(argc, argv, po_vars))
        return 1;

    const auto log_level = po_vars.count("verbose") ? boost::log::trivial::debug : boost::log::trivial::info;
    boost::log::add_common_attributes();
    boost::log::add_console_log(
        std::cout,
        boost::log::keywords::filter = boost::log::trivial::severity >= log_level,
        boost::log::keywords::format = "[%TimeStamp%][%Severity%] %Message%"
    );

    asio::ip::address announce_addr = asio::ip::make_address(po_vars["announce_addr"].as<std::string>());
    if (!announce_addr.is_multicast())
    {
        BOOST_LOG_TRIVIAL(error) << "SAP announcement address must be multicast (got: " << announce_addr << ")";
        return 1;
    }

    asio::io_context io_context;
    {
        session_manager sess_mgr(io_context);
        announcement_handler announcement_hdlr(
            sess_mgr,
            io_context,
            announce_addr,
            po_vars["announce_port"].as<uint16_t>());

        boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
        boost::asio::deadline_timer stop_timer(io_context);
        signals.async_wait([&](const boost::system::error_code& error,int signal){
            (void)error; (void)signal;
            std::cout << std::endl;
            BOOST_LOG_TRIVIAL(info) << "Closing";
            announcement_hdlr.close();
            sess_mgr.close();
            stop_timer.expires_from_now(boost::posix_time::seconds(1));
            stop_timer.async_wait([&io_context](const boost::system::error_code& error){
                (void)error;
                BOOST_LOG_TRIVIAL(info) << "Stopping";
                io_context.stop();
            });
        });

        BOOST_LOG_TRIVIAL(info) << "Running";
        io_context.run();
    }
    BOOST_LOG_TRIVIAL(info) << "Stopped";

    return 0;
}

