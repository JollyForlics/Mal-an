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
    for addr in call_graph.nodes():
        if addr in cfg.kb.functions:
            labels[addr] = cfg.kb.functions[addr].name
        else:
            labels[addr] = f"Unknown_{hex(addr)}"
    pos = nx.spring_layout(call_graph)
    nx.draw_networkx_nodes(call_graph, pos, node_size=1000, node_color="#3498db")
    nx.draw_networkx_edges(call_graph, pos, arrowstyle="-|>", arrowsize=20, edge_color="gray")
    nx.draw_networkx_labels(call_graph, pos, labels, font_size=10, font_color="black")
    plt.title("Function Call Graph (CFG Analysis)", size=15)
    plt.show()

def get_function_call_graph(cfg: angr.analyses.CFGEmulated):
    call_graph: nx.DiGraph = cfg.kb.functions.callgraph
    print_function_call_graph(call_graph, cfg);
    return(call_graph)

def static_analysis(file1: str, file2: str):
    f1: angr.Project = angr.Project(file1, load_options={'auto_load_libs': False})
    f2: angr.Project = angr.Project(file2, load_options={'auto_load_libs': False})

    cfg1: angr.analyses.CFGEmulated = f1.analyses.CFGEmulated()
    cfg2: angr.analyses.CFGEmulated = f2.analyses.CFGEmulated()

    fcg1 = get_function_call_graph(cfg1)
    fcg2 = get_function_call_graph(cfg2)

    print(nx.is_isomorphic(cfg1.model.graph, cfg2.model.graph))
    print(nx.is_isomorphic(fcg1, fcg2))

def main():
    if (len(sys.argv) != 3):
        print("Usage: ./mal-ana file2 file2")
        sys.exit(-2)
    static_analysis(sys.argv[1], sys.argv[2])
        
if __name__ == "__main__":
    main();
