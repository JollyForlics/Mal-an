import angr
from angrutils import plot_cfg
import cle
import matplotlib.pyplot as plt
import networkx as nx
import sys

def print_program_graph(project: angr.Project, fileName: str):
    main: cle.Symbol | None = project.loader.main_object.get_symbol("main");
    if main == None:
        sys.exit(-2);

    cfg: angr.analyses.CFGEmulated = project.analyses.CFGEmulated();
    plot_cfg(cfg, fileName);

def print_function_call_graph(call_graph: nx.DiGraph, cfg: angr.analyses.CFGEmulated):
    labels = {}
    for addrress in call_graph.nodes():
        if addrress in cfg.kb.functions:
            labels[addrress] = cfg.kb.functions[addrress].name
        else:
            labels[addrress] = f"Unknown_{hex(addrress)}"
    position: dict = nx.spring_layout(call_graph)
    nx.draw_networkx_nodes(call_graph, position, node_size=1000, node_color="#3498db")
    nx.draw_networkx_edges(call_graph, position, arrowstyle="-|>", arrowsize=20, edge_color="gray")
    nx.draw_networkx_labels(call_graph, position, labels, font_size=10, font_color="black")
    plt.title("Function Call Graph (CFG Analysis)", size=15)
    plt.show()

syscall_sequence = []

def log_syscalls(state):
    print("Logging syscall")
    print(f"State: {state}")
    syscall_name = state.inspect.syscall_name
    syscall_sequence.append(syscall_name)

def print_syscall_graph(graph: nx.DiGraph):
    position: dict = nx.spring_layout(graph)
    nx.draw_networkx_nodes(graph, position, node_size=1000, node_color="#3498db")
    nx.draw_networkx_edges(graph, position, arrowstyle="-|>", arrowsize=20, edge_color="gray")
    nx.draw_networkx_labels(graph, position, font_size=10, font_color="black")
    plt.title("syscall graph", size=15)
    plt.show()

def get_syscall_graph(file: str):
    project = angr.Project(file, load_options={'auto_load_libs': True})
    intial_state: angr.SimState = project.factory.entry_state()
    intial_state.inspect.b('syscall', action=log_syscalls)
    simulated: angr.SimulationManager = project.factory.simgr(intial_state)
    simulated.run()

    syscall_graph = nx.DiGraph()

    for syscall in syscall_sequence:
        if not syscall_graph.has_node(syscall):
            syscall_graph.add_node(syscall)

    for i in range(0, len(syscall_sequence) - 1):
        u = syscall_sequence[i]
        v = syscall_sequence[i + 1]

        if syscall_graph.has_edge(u, v):
            syscall_graph[u][v]["weight"] += 1
        else:
            syscall_graph.add_edge(u, v, weight=1)

    return(syscall_graph)

def get_function_call_graph(cfg: angr.analyses.CFGEmulated):
    call_graph: nx.DiGraph = cfg.kb.functions.callgraph
    return(call_graph)

def static_analysis(file1: str, file2: str, opts: list[str]):
    f1: angr.Project = angr.Project(file1, load_options={'auto_load_libs': False})
    f2: angr.Project = angr.Project(file2, load_options={'auto_load_libs': False})

    cfg1: angr.analyses.CFGEmulated = f1.analyses.CFGEmulated()
    cfg2: angr.analyses.CFGEmulated = f2.analyses.CFGEmulated()

    fcg1: nx.DiGraph = get_function_call_graph(cfg1)
    fcg2: nx.DiGraph = get_function_call_graph(cfg2)

    sc1: nx.DiGraph = get_syscall_graph(file1)
    sc2: nx.DiGraph = get_syscall_graph(file2)

    print(nx.is_isomorphic(cfg1.model.graph, cfg2.model.graph))
    print(nx.is_isomorphic(fcg1, fcg2))
    print(nx.is_isomorphic(sc1, sc2))

    if ('cfg' in opts):
        print_program_graph(f1, "cfg-f1")
        print_program_graph(f2, "cfg-f2")
    if ('fcs' in opts):
        print_function_call_graph(fcg1, cfg1)
        print_function_call_graph(fcg2, cfg2)
    if ('syscall' in opts):
        print_syscall_graph(sc1)
        print_syscall_graph(sc2)



def main():
    if (len(sys.argv) <= 3):
        print("Usage: ./mal-ana file2 file2")
        sys.exit(-2)
    static_analysis(sys.argv[1], sys.argv[2], sys.argv[3:])
        
if __name__ == "__main__":
    main();
