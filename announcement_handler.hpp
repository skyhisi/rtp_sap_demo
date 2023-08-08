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

#ifndef ANNOUNCEMENT_HANDLER_HPP
#define ANNOUNCEMENT_HANDLER_HPP

#include <array>
#include <span>

#include <boost/asio.hpp>

namespace asio = boost::asio;

class session_manager;


class announcement_handler
{
    public:
        announcement_handler(
            session_manager& sess_mgr,
            asio::io_context& context,
            asio::ip::address announce_addr,
            uint16_t announce_port
        );
        ~announcement_handler();

        void close();

    private:
        session_manager& m_session_manager;
        asio::io_context& m_context;
        asio::ip::address m_announce_addr;
        uint16_t m_announce_port;
        asio::ip::udp::socket m_socket;
        std::array<uint8_t, 1500> m_recv_buffer;
        asio::ip::udp::endpoint m_remote_endpoint;

        void start_receive();
        void handle(const boost::system::error_code& error, std::size_t bytes_transferred);
        void parse(const std::span<uint8_t>& packet);
        asio::ip::address parse_source_address(const std::span<uint8_t>& addr_data);

};


#endif /* ANNOUNCEMENT_HANDLER_HPP */
