/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STRING_UTILS_H_
#define _STRING_UTILS_H

#include <iostream>
#include <vector>
#include <string>
#include <sstream>

namespace utils::string {

    /**
     * @brief Split a string into a vector of strings
     *
     * @param str String to be split
     * @param delimiter Delimiter to split the string
     * @return std::vector<std::string>
     */
    std::vector<std::string> split(std::string rawValue, char delimiter);

    /**
     * @brief Convert a ipv4 string to a uint32_t
     *
     * @param ip String to be converted (format x.x.x.x)
     * @return uint32_t ipv4
     * @throws std::invalid_argument if the ip is not valid
     */
    uint32_t IPv4ToUInt(const std::string ip);

    /**
     * @brief convert a mask IPv4 string to a uint32_t
     *
     * @param mask network mask format x.x.x.x or x (i.e. 255.0.0.0 its equivalent to 8)
     * @return uint32_t mask
     * @throws std::invalid_argument if the mask is not valid
     */
    uint32_t IPv4MaskUInt(const std::string mask);

    // TODO: implement
    /**
     * @brief Convert a ipv6 string to a uint128_t
     * @param ip String to be converted
     * @return uint128_t ipv6
     */
    // uint128_t IPv6ToUInt(const std::string ip);


}

#endif // _OP_BUILDER_HELPER_FILTER_H