#ifndef _GRAPH_H
#define _GRAPH_H

#include <functional>
#include <set>
#include <unordered_map>

#include "builderTypes.hpp"

namespace builder::internals
{
/**
 * @brief Implements the graph and its algorithms. Used as a helper to build
 * the RXCPP observable graph based on our assets definitions.
 *
 * It can contain almost any value. We use it with Connectables.
 *
 * @tparam Value type of the value it will contain.
 */
class Graph
{
public:
    /**
     * @brief Map of connectables, with connectable name as key and connectable
     * as value
     *
     */
    std::unordered_map<std::string, types::ConnectableT> m_nodes;

    /**
     * @brief graph edes are represented by the connection between a
     * Connectable name and its set of Connectable child names.
     */
    std::unordered_map<std::string, std::set<std::string>> m_edges;

    /**
     * @brief Adds a value to the graph, and initializes its child set
     * as empty.
     *
     * @param a Value
     */
    void addNode(types::ConnectableT const& conn)
    {
        if (m_nodes.count(conn.m_name) != 0)
        {
            throw std::invalid_argument("Connectable " + conn.m_name +
                                        " is already in the graph");
        }
        if (m_edges.count(conn.m_name) != 0)
        {
            throw std::invalid_argument("Connectable " + conn.m_name +
                                        " is already in the graph edges");
        }

        m_nodes[conn.m_name] = conn;
        m_edges[conn.m_name] = {};
    }

    /**
     * @brief Adds all edges described by Connectable's parents and stablishes
     * input and output of the graph, all connectables that don't have parents
     * are connected to root, all connectables that don't have childs are
     * connected to end.
     *
     * @param root Name of connectable root for this graph
     * @param end  Name of output connectable for this graph
     */
    void addParentEdges(std::string const& root, std::string const& end)
    {
        addNode({root});
        addNode({end});
        for (auto& [name, node] : m_nodes)
        {
            if (name == root || name == end)
            {
                continue;
            }

            if (node.m_parents.empty())
            {
                node.m_parents.insert(root);
                addEdge(root, name);
            }
            else
            {
                for (auto& parent : node.m_parents)
                {
                    addEdge(parent, name);
                }
            }
        }

        // Add leaves to end
        for (auto& [name, edge] : m_edges)
        {
            if (name == root || name == end)
            {
                continue;
            }

            if (edge.empty())
            {
                m_nodes[end].m_parents.insert(name);
                addEdge(name, end);
            }
        }
    }

    /**
     * @brief Joins other graph under this graph, concretly `otherInputNode`
     * under `thisOutputNode`.
     *
     * Does not modify neither graph, returns a new one.
     *
     * @param other
     * @param thisOutputNode
     * @param otherInputNode
     * @return Graph
     */
    Graph join(const Graph& other,
               std::string const& thisOutputNode,
               std::string const& otherInputNode) const
    {
        // TODO this is probably a bit hacky
        if (this == &other)
        {
            return *this;
        }

        if (m_nodes.empty() && m_edges.empty())
        {
            return other;
        }

        if (m_nodes.count(thisOutputNode) == 0)
        {
            throw std::invalid_argument("Connectable " + thisOutputNode +
                                        " is not in the graph");
        }
        if (other.m_nodes.count(otherInputNode) == 0)
        {
            throw std::invalid_argument("Connectable " + otherInputNode +
                                        " is not in the graph to be joined");
        }

        // TODO: joining a subgraph that has a node with same name as this graph
        // would lead to wrong graph structure.
        auto auxObs {m_nodes};
        auto auxEdges {m_edges};
        auto otherNodes {other.m_nodes};
        auto otherEdges {other.m_edges};

        Graph ret;
        ret.m_nodes.merge(auxObs);
        ret.m_nodes.merge(otherNodes);
        ret.m_edges.merge(auxEdges);
        ret.m_edges.merge(otherEdges);
        ret.addEdge(thisOutputNode, otherInputNode);
        ret.m_nodes[otherInputNode].m_parents.insert(thisOutputNode);

        return ret;
    }

    /**
     * @brief Injects other graph nodes on this graph, edges on other graph are
     * ignored.
     *
     * Does not modify neither graph, returns a new one.
     *
     * @param other
     * @return Graph
     */
    Graph inject(const Graph& other) const
    {
        auto auxObs {m_nodes};
        auto auxEdges {m_edges};

        Graph ret;
        ret.m_nodes.merge(auxObs);
        ret.m_edges.merge(auxEdges);

        for (auto& [name, node] : other.m_nodes)
        {
            ret.addNode(node);
            for (auto& p : node.m_parents)
            {
                ret.injectEdge(p, name);
            }
        }

        return ret;
    }

    /**
     * @brief Injects value b between a and its childs, so b becomes the parent
     * of a's childs and the only child of a.
     *
     * @param a parent to inject into
     * @param b node to become the only child of a
     */
    void injectEdge(std::string const& a, std::string const& b)
    {
        if (m_nodes.count(a) == 0)
        {
            throw std::invalid_argument("Connectable " + a +
                                        " is not in the graph");
        }
        if (m_nodes.count(b) == 0)
        {
            throw std::invalid_argument("Connectable " + b +
                                        " is not in the graph");
        }

        for (auto& child : m_edges[a])
        {
            auto& nd = m_nodes[child];
            nd.m_parents.erase(a);
            nd.m_parents.insert(b);
        }

        m_edges[b].merge(m_edges[a]);
        m_edges[a] = {b};
    }

    /**
     * @brief Removes b from the child set of a.
     *
     * @param a Value
     * @param b Value
     */
    void removeEdge(std::string const& a, std::string const& b)
    {
        if (m_nodes.count(a) == 0)
        {
            throw std::invalid_argument("Connectable " + a +
                                        " is not in the graph");
        }
        if (m_nodes.count(b) == 0)
        {
            throw std::invalid_argument("Connectable " + b +
                                        " is not in the graph");
        }

        if (m_edges[a].count(b) == 0)
        {
            throw std::invalid_argument("Connectable " + b +
                                        " is not child of " + a);
        }

        m_edges[a].erase(b);
    }

    /**
     * @brief Add b to the child set of a.
     *
     * @param a
     * @param b
     */
    void addEdge(std::string const& a, std::string const& b)
    {
        if (m_nodes.count(a) == 0)
        {
            throw std::invalid_argument(
                fmt::format("Connectable [{}] is not in the graph", a));
        }
        if (m_nodes.count(b) == 0)
        {
            throw std::invalid_argument(
                fmt::format("Connectable [{}] is not in the graph", b));
        }

        // TODO: Maybe we just try to insert and not throw
        if (!m_edges[a].insert(b).second)
        {
            throw std::invalid_argument(fmt::format(
                "Connectable [{}] is already a child of [{}]", a, b));
        }
    }

    /**
     * @brief visit all nodes of the graph only once. The visitor function
     * will receive a pair with the value and a set of its childs.
     *
     * @param fn
     */
    template<typename Visitor>
    void visit(Visitor fn)
    {
        static_assert(std::is_invocable_v<Visitor, types::ConnectableT>,
                      "Calling visit with a non-compatible callable");
        for (auto& n : m_nodes)
        {
            fn(n.second);
        }
    }

    /**
     * @brief Visit all graph leaves, which are the nodes with empty child sets.
     *
     * @param fn visitor function will receive only a Value
     */
    template<typename Visitor>
    void leaves(Visitor fn) const
    {
        static_assert(std::is_invocable_v<Visitor, types::ConnectableT>,
                      "Calling visit with a non-compatible callable");
        for (auto& n : m_edges)
        {
            if (n.second.size() == 0)
                fn(n.first);
        }
    }

    /**
     * @brief Returnss a stringstream with a graphviz representation of this
     * graph.
     *
     * @return std::stringstream
     */
    std::string print() const
    {
        std::string diagraph = "digraph G {\n";
        for (auto& n : m_edges)
        {
            if (n.second.size() > 0)
            {
                for (auto& c : n.second)
                {
                    diagraph += fmt::format("\"{}\"->\"{}\";\n", n.first, c);
                }
            }
            else
            {
                diagraph += fmt::format("\"{}\" -> void;\n", n.first);
            }
        }
        diagraph += "}\n";
        return diagraph;
    }

    /**
     * @brief Same as m_node operator [].
     *
     * @param node
     * @return types::ConnectableT&
     */
    types::ConnectableT& operator[](std::string const& node)
    {
        return m_nodes[node];
    }

    bool empty() const
    {
        return m_nodes.empty() && m_edges.empty();
    }
};
} // namespace builder::internals

#endif // _GRAPH_H
