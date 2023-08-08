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

#ifndef SESSION_MANAGER_HPP
#define SESSION_MANAGER_HPP

#include <unordered_map>

#include <boost/container_hash/hash.hpp>
#include <boost/asio.hpp>


#include "session_description.hpp"
#include "save_stream.hpp"

namespace asio = boost::asio;


struct session_key
{
    boost::asio::ip::address source_ip;
    uint16_t session_hash;
};

inline bool operator==(const session_key& a, const session_key& b)
{
    return a.source_ip == b.source_ip && a.session_hash == b.session_hash;
}

template <>
struct std::hash<session_key>
{
    std::size_t operator()(const session_key& value) const noexcept
    {
        std::size_t hash = 0;
        boost::hash_combine(hash, std::hash<boost::asio::ip::address>{}(value.source_ip));
        boost::hash_combine(hash, std::hash<uint16_t>{}(value.session_hash));
        return hash;
    }
};


class session_manager
{
    public:
        session_manager(asio::io_context& context);

        void add_session(
            const boost::asio::ip::address& source_addr,
            uint16_t session_hash,
            const std::string& payload_str);

        void remove_session(
            const boost::asio::ip::address& source_addr,
            uint16_t session_hash);

        void close();

    private:
        struct session_value
        {
            session_description session_desc;
            save_stream stream_saver;

            session_value(session_description&& session_desc_, save_stream&& stream_saver_):
                session_desc(std::move(session_desc_)),
                stream_saver(std::move(stream_saver_))
            {}
        };
        typedef std::unordered_map<session_key,session_value> session_map_t;
        asio::io_context& m_context;
        session_map_t m_session_map;
};


#endif /* SESSION_MANAGER_HPP */
