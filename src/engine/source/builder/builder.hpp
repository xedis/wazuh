/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDER_H
#define _BUILDER_H

#include <unordered_map>

#include "builderTypes.hpp"

namespace catalog
{
struct EnvironmentDefinition;
}

namespace builder
{
/**
 * @brief Defines environment as subject
 *
 */
struct Environment
{
    // TODO: handle debug sink subscriptions lifetime

    std::string name;
    std::unordered_map<std::string, rxcpp::observable<std::string>> traceSinks;
    rxcpp::subjects::subject<internals::types::Event> subject;

    /**
     * @brief Subscribe to asset trace sink
     *
     * @param assetName
     * @param subscriberOnNext
     */
    void subscribeTraceSink(std::string assetName,
                            std::function<void(std::string)> subscriberOnNext)
    {
        if (traceSinks.count(assetName) > 0)
        {
            traceSinks[assetName].subscribe(subscriberOnNext);
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Error subscribing trace sink, environment [{}] does not "
                "contain asset [{}]",
                name,
                assetName));
        }
    }

    /**
     * @brief Subscribe to all assets debug sinks
     *
     * @param subscriberOnNext
     */
    void
    subscribeAllTraceSinks(std::function<void(std::string)> subscriberOnNext)
    {
        for (auto sink : traceSinks)
        {
            sink.second.subscribe(subscriberOnNext);
        }
    }
};

using EnvironmentRef = std::shared_ptr<Environment>;

/**
 * @brief The builder class is the responsible to transform and environment
 * definition into a graph of RXCPP operations.
 *
 * @tparam Catalog type of the catalog for dependency injection.
 */

/**
 * @brief Return an struct with the lifter for the given enviroment name and
 * with all assets debug sinks.
 *
 * @param name Environment name to build/lift
 * @return envBuilder
 */
EnvironmentRef buildEnvironment(catalog::EnvironmentDefinition const& envDefinition);

} // namespace builder
#endif // _BUILDER_H
