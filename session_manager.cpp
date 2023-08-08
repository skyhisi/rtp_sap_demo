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

#include "session_manager.hpp"

#include <charconv>

session_manager::session_manager(asio::io_context& context):
    m_context(context),
    m_session_map()
{}

void session_manager::add_session(
    const boost::asio::ip::address& source_addr,
    uint16_t session_hash,
    const std::string& payload_str)
{
    const session_key key{source_addr, session_hash};

    // Only parse the payload if it doesn't already exist
    if (!m_session_map.contains(key))
    {
        session_description session_desc(source_addr, session_hash, payload_str);
        save_stream saver(m_context, session_desc, 0);
        // m_session_map[key] = session_value(
        //     std::move(session_desc),
        //     std::move(saver)
        // );
        m_session_map.emplace(key, session_value(
            std::move(session_desc),
            std::move(saver)
        ));
    }
}

void session_manager::remove_session(
    const boost::asio::ip::address& source_addr,
    uint16_t session_hash)
{
    const session_key key{source_addr, session_hash};
    auto it = m_session_map.find(key);
    it->second.stream_saver.close([this, key](){
        m_session_map.erase(key);
    });
}

void session_manager::close()
{
    for (auto& kv : m_session_map)
    {
        auto& key = kv.first;
        kv.second.stream_saver.close([this, key](){
            m_session_map.erase(key);
        });
    }
    //m_session_map.clear();
}
