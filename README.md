# DICE

This accompanies the paper, Adversarial Specification Mining.

The objective of this work is to better mine automata models of APIs. 
This is done through search-based test generation guided to produce execution traces during testing that will falsify LTL properties that was thought to hold of the API.
Through this effort to look for new traces that contradict properties previously thought to hold, we can improve the model.

We also propose a new specification mining algorithm that can leverage the diverse traces. 
More is described in the paper, but mainly, we use the insights developed by prior studies. 
Our approach can be viewed as an approach that is enhanced by and builds on 
1. The k-tails algorithm 
2. the CONTRACTOR study shows the enabledness of methods lead to states (in a state model) that are of the right abstraction and intuitively interpreted by developers
3. LTL properties can be used to guide automata inference
4. many LTL properties that show an "immediate" relationship are useful, but prior work has shown that many of the properties are always false. We improve on the formulation of these "immediate" relationships by accounting for method purity.


One set of traces produced by DICE-Tester can be found in the [traces directory](https://github.com/kanghj/DICE/tree/master/traces).

The models output are in the [outputs directory](https://github.com/kanghj/DICE/tree/master/outputs)

As for the models of Tautoko, they can be found in this [tautoko directory](https://github.com/kanghj/DICE/tree/master/tautoko)

The traces and model used for fuzzing the FTP and RTSP server are found [here](https://github.com/kanghj/DICE/tree/master/server_fuzzing/server_fuzzing).
The source code of AFLNET, which we modified, can be found [here](https://github.com/kanghj/DICE/dice-aflnet).
AFLNET was originally found at https://github.com/aflnet/aflnet and was developed by Van-Thuan Pham and Marcel Böhme and Abhik Roychoudhury
