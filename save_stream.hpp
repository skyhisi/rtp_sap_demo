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

#ifndef SAVE_STREAM_HPP
#define SAVE_STREAM_HPP

#include <array>
#include <fstream>
#include <boost/asio.hpp>

#include "session_description.hpp"

namespace asio = boost::asio;


class save_stream
{
    public:
        save_stream(
            asio::io_context& context,
            const session_description& session_desc,
            unsigned session_idx);
        save_stream(const save_stream&) = delete;
        save_stream(save_stream&& other);
        ~save_stream();

        void close(std::function<void()> callback = std::function<void()>());

    private:
        struct save_stream_data;
        std::unique_ptr<save_stream_data> m_data;
};

#endif /* SAVE_STREAM_HPP */
