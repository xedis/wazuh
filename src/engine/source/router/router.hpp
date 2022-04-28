/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_H
#define _ROUTER_H

#include <string>
#include <unordered_map>

//TODO still exposing rxcpp
#include <rxcpp/rx.hpp>

namespace json
{
struct Document;
}

// TODO there's probably a better home for this without having to include the
// whole json header
using JsonDocRef = std::shared_ptr<json::Document>;

namespace builder
{
struct Environment;
}

namespace catalog
{
struct Catalog;
}

namespace router
{

/**
 * @brief Represents a route and manages subscription
 *
 */
struct Route
{
    std::string name;
    std::string to;
    std::function<bool(JsonDocRef)> filterFn;
    rxcpp::composite_subscription subscription;

    ~Route()
    {
        // TODO investigate if the destructor for composite_subscription already
        // takes care of this
        if (!subscription.get_weak().expired() && subscription.is_subscribed())
        {
            subscription.unsubscribe();
        }
    }
};

/**
 * @brief Router
 *
 * The Router manages the environments which are ready to be enabled, ie.
 * receive events from the server. Particularily, it can:
 *  - Create a new environment from its Catalog definition by calling the
 * Builder
 *  - Route events received to an environment which is able to accept it
 *  - Enable an environment so it can accept events
 *  - Disable an environment so it can stop accepting events
 *
 * In case there is no environment enabled, the  router will drop the
 * events, freeing all resources associated to them.
 *
 * An environment is a set of decoders, rules, filters and outputs which are set
 * up to work together and a filter to decide which events to accept.
 *
 * @tparam Builder injected builder type to build environments
 */
//TODO maybe consider a pimpl implementation to hide all the dependencies?
class Router
{
private:
    std::unordered_map<std::string, std::shared_ptr<builder::Environment>>
        m_environments;
    std::unordered_map<std::string, Route> m_routes;
    rxcpp::subjects::subject<std::shared_ptr<json::Document>> m_subj;
    rxcpp::subscriber<std::shared_ptr<json::Document>> m_input;
    // TODO this
    const catalog::Catalog& m_catalog;

public:
    /**
     * @brief Construct a new Router object
     *
     * @param builder Injected Builder object
     */
    Router(catalog::Catalog const& catalog);
    ~Router();

    /**
     * @brief Add a route
     *
     * @param environment Where events are forwarded
     * @param route Name of the route
     * @param filterFunction Filter function to select forwarded envent
     */
    void add(
        const std::string& routeName,
        const std::string& envName,
        const std::function<bool(JsonDocRef)> filterFunction = [](const auto)
        { return true; });

    /**
     * @brief Delete route
     *
     * @param route Name of the route to be deleted
     */
    void remove(const std::string& route);

    void routeEvent(std::string const& event);

    /**
     * @brief Subscribe to specified trace sink.
     *
     * @param environment
     * @param asset
     * @param subscriberOnNext
     */
    void subscribeTraceSink(std::string environment,
                            std::string asset,
                            std::function<void(std::string)> subscriberOnNext);

    /**
     * @brief Subscribes to all trace sinks for specified environment
     *
     * @param environment
     * @param subscriberOnNext
     */
    void
    subscribeAllTraceSinks(std::string environment,
                           std::function<void(std::string)> subscriberOnNext);
};
} // namespace router
#endif // _ROUTER_H
