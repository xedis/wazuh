#include "builder.hpp"

#include <functional>
#include <stdexcept>
#include <vector>

#include "builderTypes.hpp"
#include "builders/assetBuilderDecoder.hpp"
#include "builders/assetBuilderFilter.hpp"
#include "builders/assetBuilderOutput.hpp"
#include "builders/assetBuilderRule.hpp"
#include "graph.hpp"
#include "registry.hpp"
#include <catalog.hpp>
#include <logging/logging.hpp>

namespace builder
{
struct SubGraph
{
    // TODO a char* is fine for now
    const char* in;
    const char* out;
    internals::Graph graph;
};
/**
 * @brief An environment might have decoders, rules, filters and outputs,
 * but only an output is mandatory. All of them are arranged into a graph.
 * Each graph leaf is connected with the root of the next tree.
 *
 * If the environment has other stages, they're ignored. The order of the
 *  tree is:
 *  server · router · decoders · ---------------> · outputs
 *                             \---> · rules · --/
 *
 * Filters can be connected to decoders and rules leaves, to discard some
 * events. They cannot attach themselves between two decoders or two rules.
 *
 * @param name name of the environment
 * @return Graph_t execution graph
 */
static internals::Graph buildGraph(catalog::EnvironmentDefinition const& def)
{
    std::vector<SubGraph> subGraphs;
    internals::Graph decoders;
    internals::Graph rules;
    internals::Graph outputs;
    internals::Graph filters;

    for (auto const& asset : def.assetList)
    {
        switch (asset.type)
        {
            case catalog::AssetType::Decoder:
            {
                decoders.addNode(
                    internals::builders::assetBuilderDecoder(asset.content));
                break;
            }
            case catalog::AssetType::Rule:
            {
                // TODO: proper implement that rules are the first choice.
                // As it is a set ordered by name, to check rules before
                // outputs an A has been added to the name
                rules.addNode(
                    internals::builders::assetBuilderRule(asset.content));
                break;
            }
            case catalog::AssetType::Output:
            {
                outputs.addNode(
                    internals::builders::assetBuilderOutput(asset.content));
                break;
            }
            case catalog::AssetType::Filter:
            {
                filters.addNode(
                    internals::builders::assetBuilderFilter(asset.content));
                break;
            }
            default:
            {
                // TODO error
                throw;
            }
        }
    }

    subGraphs.push_back({"INPUT_DECODER", "OUTPUT_DECODER", decoders});
    subGraphs.push_back({"INPUT_RULE", "OUTPUT_RULE", rules});
    subGraphs.push_back({"INPUT_OUTPUT", "OUTPUT_OUTPUT", outputs});

    // Join and connect subgraphs, handle first outside loop
    if (subGraphs.empty())
    {
        throw std::runtime_error(
            "Error building graph, at least one subgraph must be defined");
    }

    // TODO here we create and throw away a lot of allocations by creating a
    // bunch of graphs because the join function creates a bunch of duplication
    internals::Graph ret;
    std::string prevOutput;
    for (auto& sg : subGraphs)
    {
        sg.graph.addParentEdges(sg.in, sg.out);
        ret = ret.join(sg.graph, prevOutput, sg.in);
        prevOutput = sg.out;
    }

    ret = ret.inject(filters);

    // Multiple outputs are manual
    // TODO: hardcoded
    if (!decoders.empty() && !rules.empty() && !outputs.empty())
    {
        ret.addEdge("OUTPUT_DECODER", "INPUT_OUTPUT");
        ret.m_nodes["INPUT_OUTPUT"].m_parents.insert("OUTPUT_DECODER");
    }

    return ret;
}

// Recursive visitor function to call all connectable lifters and
// build the whole rxcpp pipeline
static void buildRxcppPipeline(internals::Graph& graph,
                        internals::types::Observable source,
                        std::string const& root,
                        internals::types::Observable& out)
{
    // Only must be executed one, graph input
    auto nd = graph.m_nodes.find(root);
    if (nd == graph.m_nodes.end())
    {
        // TODO error
        return;
    }

    if (nd->second.m_inputs.size() == 0)
    {
        nd->second.addInput(source);
    }

    auto edg = graph.m_edges.find(root);
    if (edg == graph.m_edges.end())
    {
        // TODO Error?
        return;
    }

    internals::types::Observable obs;
    if (edg->second.size() > 1)
    {
        obs = graph.m_nodes[root].connect().publish().ref_count();
    }
    else
    {
        obs = graph.m_nodes[root].connect();
    }

    // Add obs as an input to the childs
    for (auto& n : edg->second)
    {
        graph.m_nodes[n].addInput(obs);
        if (graph.m_nodes[n].m_inputs.size() ==
            graph.m_nodes[n].m_parents.size())
            buildRxcppPipeline(graph, obs, n, out);
    }

    // Only executed one, graph output
    if (edg->second.size() == 0)
    {
        out = obs;
    }
};

Environment buildEnvironment(catalog::EnvironmentDefinition const& def)
{
    auto graph = buildGraph(def);

    Environment ret {def.name};
    graph.visit([&](auto node)
                { ret.traceSinks[node.m_name] = node.m_tracer.m_out; });

    ret.lifter =
        [graph = std::move(graph)](internals::types::Observable o) mutable
    {
        internals::types::Observable out;
        buildRxcppPipeline(graph, o, "INPUT_DECODER", out);
        return out;
    };

    return ret;
}
} // namespace builder
