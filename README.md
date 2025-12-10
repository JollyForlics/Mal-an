# Malware Variant Comparsion Tool

A basic python script for COMP323 project for graph theory.

> [!WARNING]
> This is not a optimal way to perform malware variant detection. For that you want to use markov chains or GNN. This is exercise was only done for the project. Though this my detect some malware-variant, this method is too strict to be majorily useful in production.


Currently it uses isomorphism. I tried graph edit distance but that took to much time.

# Dependecies

1. `angr`: For making CFG, FCG.
2. `angrutils`: For visualizing CFG.
3. `networkx`: For the graph
4. `matplotlib`: For plotting graph

```python
python mal-an.py <file1> <file2>
```
