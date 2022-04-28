/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "router.hpp"

#include <fmt/format.h>
#include <rxcpp/rx.hpp>

#include <builder.hpp>
#include <catalog.hpp>
#include <json.hpp>

// TODO check if there's a better home for this
static JsonDocRef parse(const std::string& event)
{
    auto doc = std::make_shared<json::Document>();
    doc->m_doc.SetObject();
    rapidjson::Document::AllocatorType& allocator = doc->getAllocator();

    auto queuePos = event.find(":");
    try
    {
        int queue = std::stoi(event.substr(0, queuePos));
        doc->m_doc.AddMember("queue", queue, allocator);
    }
    // std::out_of_range and std::invalid_argument
    catch (...)
    {
        std::throw_with_nested(std::invalid_argument("Error parsing queue id"));
    }

    auto locPos = event.find(":", queuePos + 1);
    try
    {
        rapidjson::Value loc;
        std::string location = event.substr(queuePos, locPos);
        loc.SetString(location.c_str(), location.length(), allocator);
        doc->m_doc.AddMember("location", loc, allocator);
    }
    catch (std::out_of_range& e)
    {
        std::throw_with_nested(
            ("Error parsing location using token sep :" + event));
    }

    try
    {
        rapidjson::Value msg;
        std::string message = event.substr(locPos + 1, std::string::npos);
        msg.SetString(message.c_str(), message.length(), allocator);
        doc->m_doc.AddMember("message", msg, allocator);
    }
    catch (std::out_of_range& e)
    {
        std::throw_with_nested(
            ("Error parsing location using token sep :" + event));
    }

    return doc;
}

namespace router
{

Router::Router(catalog::Catalog const& catalog)
    : m_catalog {catalog}
    , m_input {m_subj.get_subscriber()}
{
}

Router::~Router()
{
    m_input.on_completed();
}

void Router::add(const std::string& routeName,
                 const std::string& envName,
                 const std::function<bool(JsonDocRef)> filterFn)
{
    // Assert route with same name not exists
    if (m_routes.count(routeName) > 0)
    {
        throw std::invalid_argument("Error, route " + routeName +
                                    " is already in use");
    }

    auto envIt = m_environments.find(envName);
    if (envIt == m_environments.end())
    {
        auto envDef = m_catalog.getEnvironmentDefinition(envName);
        envIt =
            m_environments.insert({envName, builder::buildEnvironment(envDef)})
                .first;
    }

    // Route filtered events to enviroment, Router subject implements
    // multicasting (we need to call get_observable for each filter added)
    auto subscription = m_subj.get_observable().filter(filterFn).subscribe(
        envIt->second->subject.get_subscriber());

    m_routes[routeName] = {routeName, envName, filterFn, subscription};
}

void Router::remove(const std::string& route)
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

void Router::routeEvent(std::string const& event)
{
    // TODO could the parsing of the event be the first step/node in the graph
    // instead?
    return m_input.on_next(parse(event));
}

void Router::subscribeTraceSink(
    std::string environment,
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

void Router::subscribeAllTraceSinks(
    std::string environment, std::function<void(std::string)> subscriberOnNext)
{
    if (m_environments.count(environment) > 0)
    {
        m_environments[environment]->subscribeAllTraceSinks(subscriberOnNext);
    }
    else
    {
        throw std::runtime_error(fmt::format(
            "Error subscribing trace sink, enviroment [{}] does not exists",
            environment));
    }
}
} // namespace router
