/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "protocolHandler.hpp"

#include <iostream>
#include <optional>
#include <string>

#include <logging/logging.hpp>
#include <profile/profile.hpp>

namespace engineserver
{
bool ProtocolHandler::hasHeader()
{
    if (m_buff.size() == sizeof(int))
    {
        // TODO: make this safe
        memcpy(&m_pending, m_buff.data(), sizeof(int));
        // TODO: Max message size config option
        if (m_pending > 1 << 20)
        {
            throw std::runtime_error("Invalid message. Size probably wrong");
        }
        return true;
    }
    return false;
}

std::optional<std::vector<std::string>>
ProtocolHandler::process(const char* data, const size_t length)
{
    std::vector<std::string> events;

    for (size_t i = 0; i < length; i++)
    {
        switch (m_stage)
        {
            // header
            case 0:
                m_buff.push_back(data[i]);
                try
                {
                    if (hasHeader())
                    {
                        m_stage = 1;
                    }
                }
                catch (...)
                {
                    // TODO: improve this try-catch
                    return std::nullopt;
                }
                break;

            // payload
            case 1:
                m_buff.push_back(data[i]);
                m_pending--;
                if (m_pending == 0)
                {
                    try
                    {
                        // TODO: Are we moving the buffer? we should
                        events.push_back(std::string(
                            m_buff.begin() + sizeof(int), m_buff.end()));
                        m_buff.clear();
                    }
                    catch (std::exception& e)
                    {
                        WAZUH_LOG_ERROR("{}", e.what());
                        return std::nullopt;
                    }
                    m_stage = 0;
                }
                break;

            default:
                WAZUH_LOG_ERROR("Invalid stage value.");
                return std::nullopt;
        }
    }

    return std::optional<std::vector<std::string>>(std::move(events));
}
} // namespace engineserver
