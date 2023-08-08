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

#include "announcement_handler.hpp"

#include <boost/log/trivial.hpp>

#include "session_manager.hpp"

#define SAP_HDR_SIZE (4)
#define IPV4_SIZE (4)
#define IPV6_SIZE (16)
#define MIN_PAYLOAD_SIZE (4)


const static std::string SDP_initial("v=0");


announcement_handler::announcement_handler(
    session_manager& sess_mgr,
    asio::io_context& context,
    asio::ip::address announce_addr,
    uint16_t announce_port
):
    m_session_manager(sess_mgr),
    m_context(context),
    m_announce_addr(announce_addr),
    m_announce_port(announce_port),
    m_socket(context),
    m_recv_buffer()
{
    asio::ip::udp::endpoint announce_endpoint(announce_addr, announce_port);

    m_socket.open(announce_endpoint.protocol());
    m_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    m_socket.bind(announce_endpoint);
    m_socket.set_option(asio::ip::multicast::join_group(announce_addr));

    start_receive();
}

announcement_handler::~announcement_handler()
{
    close();
}

void announcement_handler::close()
{
    if (m_socket.is_open())
    {
        m_socket.cancel();
        m_socket.set_option(asio::ip::multicast::leave_group(m_announce_addr));
        m_socket.close();
    }
}


void announcement_handler::start_receive()
{
    m_socket.async_receive_from(
        asio::buffer(m_recv_buffer),
        m_remote_endpoint,
        [this](const boost::system::error_code& err, std::size_t size){handle(err, size);}
    );
}


void announcement_handler::handle(const boost::system::error_code& error, std::size_t size)
{
    if (error)
    {
        BOOST_LOG_TRIVIAL(error) << "Failed to receive packet: " << error;
    }
    else
    {
        parse(std::span<uint8_t,std::dynamic_extent>{m_recv_buffer.data(), size});
        start_receive();
    }
}

// https://www.rfc-editor.org/rfc/rfc2974
void announcement_handler::parse(const std::span<uint8_t>& packet)
{
    if (packet.size() < SAP_HDR_SIZE + IPV4_SIZE + MIN_PAYLOAD_SIZE)
    {
        BOOST_LOG_TRIVIAL(error) << "Packet too small, expected at least 8, got: " << packet.size();
        return;
    }

    uint8_t ver_flags = packet[0];
    uint8_t ver = (ver_flags >> 5) & 0x07;
    if (ver != 1)
    {
        BOOST_LOG_TRIVIAL(error) << "Unexpected SAP version, expected 1, got: " << ver;
        return;
    }

    bool source_ipv6 = (ver_flags & 0x10);
    bool deletion = (ver_flags & 0x04);
    bool encryption = (ver_flags & 0x02);
    bool compressed = (ver_flags & 0x01);

    if (source_ipv6 && packet.size() < SAP_HDR_SIZE + IPV6_SIZE + MIN_PAYLOAD_SIZE)
    {
        BOOST_LOG_TRIVIAL(error) << "Packet too small, expected at least 20, got: " << packet.size();
        return;
    }

    if (encryption)
    {
        BOOST_LOG_TRIVIAL(error) << "Encrypted SAP packets not supported";
        return;
    }
    if (compressed)
    {
        BOOST_LOG_TRIVIAL(error) << "Compressed SAP packets not supported";
        return;
    }

    uint8_t auth_len = packet[1];
    if (auth_len != 0)
    {
        BOOST_LOG_TRIVIAL(error) << "Authentication not supported";
        return;
    }

    uint16_t message_id = (packet[2] << 8) + packet[3];

    std::span<uint8_t> addr_data = source_ipv6 ? packet.subspan(4, 16) : packet.subspan(4, 4);

    asio::ip::address source_addr = parse_source_address(addr_data);

    std::span<uint8_t> payload_data = source_ipv6 ? packet.subspan(20) : packet.subspan(8);

    // If doesn't start with v=0, then has a payload type to parse out
    std::string payload_type; // = "application/sdp";
    if (!std::equal(SDP_initial.begin(), SDP_initial.end(), payload_data.begin()))
    {
        auto payload_type_null_terminator = std::find(std::begin(payload_data), std::end(payload_data), 0u);
        if (payload_type_null_terminator != std::end(payload_data))
        {
            payload_type.assign(std::begin(payload_data), payload_type_null_terminator);
            payload_data = payload_data.subspan((payload_type_null_terminator - payload_data.begin()) + 1);
        }
    }

    const char* session_type_str = deletion ? "deletion" : "announcement";
    BOOST_LOG_TRIVIAL(info)
        << "SAP session " << session_type_str
        << " packet from " << source_addr
        << " with message ID " << message_id
        << " payload type " << payload_type;

    std::string payload_str(std::begin(payload_data), std::end(payload_data));
    BOOST_LOG_TRIVIAL(info) << payload_str;

    //session_description sd(source_addr, message_id, payload_str);

    if (deletion)
    {
        m_session_manager.remove_session(source_addr, message_id);
    }
    else
    {
        m_session_manager.add_session(source_addr, message_id, payload_str);
    }
}

asio::ip::address announcement_handler::parse_source_address(const std::span<uint8_t>& addr_data)
{
    if (addr_data.size() == IPV6_SIZE) // ipv6
    {
        asio::ip::address_v6::bytes_type addr_bytes;
        std::copy(std::begin(addr_data), std::end(addr_data), addr_bytes.data());
        return asio::ip::address_v6(addr_bytes);
    }
    else if (addr_data.size() == IPV4_SIZE) // ipv4
    {
        asio::ip::address_v4::bytes_type addr_bytes;
        std::copy(std::begin(addr_data), std::end(addr_data), addr_bytes.data());
        return asio::ip::address_v4(addr_bytes);
    }
    else
    {
        return asio::ip::address();
    }
}
