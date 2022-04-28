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

#include <algorithm>
#include <string>
#include <type_traits>
#include <unordered_map>

#include <fmt/format.h>
#include <rxcpp/rx.hpp>

#include "json.hpp"
#include <builder.hpp>
// TODO revise catalog dep
#include <catalog.hpp>

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
    std::function<bool(std::shared_ptr<json::Document>)> filterFn;
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
class Router
{
private:
    using ServerOutputObs = rxcpp::observable<rxcpp::observable<std::string>>;

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
    Router(catalog::Catalog const& catalog) noexcept
        : m_catalog {catalog}
        , m_input {m_subj.get_subscriber()}
    {
    }

    /**
     * @brief Add a route
     *
     * @param environment Where events are forwarded
     * @param route Name of the route
     * @param filterFunction Filter function to select forwarded envent
     */
    void add(
        const std::string& route,
        const std::string& environmentName,
        const std::function<bool(std::shared_ptr<json::Document>)>
            filterFunction = [](const auto) { return true; })
    {
        // Assert route with same name not exists
        if (m_routes.count(route) > 0)
        {
            throw std::invalid_argument("Error, route " + route +
                                        " is already in use");
        }

        auto envIt = m_environments.find(environmentName);
        if (envIt == m_environments.end())
        {
            auto envDef = m_catalog.getEnvironmentDefinition(environmentName);
            auto env = builder::buildEnvironment(envDef);
            env.lifter(env.subject.get_observable());
            envIt = m_environments
                        .insert({environmentName,
                                 std::make_shared<builder::Environment>(env)})
                        .first;
        }

        // Route filtered events to enviroment, Router subject implements
        // multicasting (we need to call get_observable for each filter added)
        auto subscription =
            m_subj.get_observable()
                .filter(filterFunction)
                .subscribe(envIt->second->subject.get_subscriber());

        m_routes[route] = {route, environmentName, filterFunction, subscription};
    }

    /**
     * @brief Delete route
     *
     * @param route Name of the route to be deleted
     */
    void remove(const std::string& route)
    {
        auto r = m_routes.find(route);
        if (r == m_routes.end())
        {
            throw std::invalid_argument(
                "Error, route " + route +
                " can not be deleted because is not registered");
        }

        m_routes.erase(r->second.to);
        m_environments.erase(r->second.to);
    }

    /**
     * @brief Obtain Router subscriber to inject events.
     *
     * @return const rxcpp::subscriber<json::Document>&
     */
    const rxcpp::subscriber<std::shared_ptr<json::Document>>& input() const
    {
        return m_input;
    }

    /**
     * @brief Subscribe to specified trace sink.
     *
     * @param environment
     * @param asset
     * @param subscriberOnNext
     */
    void subscribeTraceSink(std::string environment,
                            std::string asset,
                            std::function<void(std::string)> subscriberOnNext)
    {
        if (m_environments.count(environment) > 0)
        {
            m_environments[environment]->subscribeTraceSink(asset,
                                                            subscriberOnNext);
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Error subscribing trace sink, enviroment [{}] does not exists",
                environment));
        }
    }

    /**
     * @brief Subscribes to all trace sinks for specified environment
     *
     * @param environment
     * @param subscriberOnNext
     */
    void
    subscribeAllTraceSinks(std::string environment,
                           std::function<void(std::string)> subscriberOnNext)
    {
        if (m_environments.count(environment) > 0)
        {
            m_environments[environment]->subscribeAllTraceSinks(
                subscriberOnNext);
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Error subscribing trace sink, enviroment [{}] does not exists",
                environment));
        }
    }
};

} // namespace router

#endif // _ROUTER_H
