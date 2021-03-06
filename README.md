# DICE

This accompanies the paper, Adversarial Specification Mining.

## Introduction
Objective: __better mine automata specifications/models of APIs__. 
From an initial set of execution traces, we try to fill in the gaps in the diversity of the traces.
This is done through **search-based test generation guided to produce execution traces during testing that will falsify LTL properties** that was thought to hold of the API.
We focus on LTL properties involving 2 events.
We use property templates from prior studies [4,5,6].
By finding new traces that are counterexamples to these properties, we can improve the model as the specification inference process benefits from the diverse traces.


Afterwards, we show that this process is also useful for fuzzing of protocols. By **learning automata models of a protocol's client, this allows us to explore deeper states** in a server of the protocol.

To mine specifications, we use the insights from prior studies. 

Our specification inference approach can be viewed as an approach that is enhanced by and builds on the following studes: 
1. The k-tails algorithm [1]
2. the CONTRACTOR[2] study shows the enabledness of methods lead to states (in a state model) that are of the right abstraction and intuitively interpreted by developers
3. LTL properties can be used to guide automata inference [3,4]
4. many LTL properties that show an "immediate" relationship are useful [4], but prior work has shown that many of the properties are always false [5]. We improve on the formulation of these "immediate" relationships by accounting for method purity.

[1] A. W. Biermann and J. Feldman. On the synthesis of finite state machines from samples of their behavior. IEEE Transactions on Computers, 21:592–597, 1972.

[2] G. de Caso, V. Braberman, D. Garbervetsky, and S. Uchitel. Automated abstractions for contract validation. IEEE Transactions on Software Engineering, 38(1), 2012.

[3] Lo, David, Leonardo Mariani, and Mauro Pezzè. "Automatic steering of behavioral model inference." Proceedings of the 7th Joint Meeting Of The European Software Engineering Conference and the ACM SIGSOFT symposium on The foundations of software engineering. 2009.

[4] Le, Tien-Duy B., et al. "Synergizing specification miners through model fissions and fusions (t)." 2015 30th IEEE/ACM International Conference on Automated Software Engineering (ASE). IEEE, 2015.

[5] Sun, Peng, et al. "Mining Specifications from Documentation using a Crowd." 2019 IEEE 26th International Conference on Software Analysis, Evolution and Reengineering (SANER). IEEE, 2019.

[6] Ivan Beschastnikh, Yuriy Brun, Jenny Abrahamson, Michael D Ernst, and Arvind Krishnamurthy. 2014. Using declarative specification to improve the understanding, extensibility, and comparison of model-inference algorithms. IEEE Transactions on Software Engineering 41

One set of traces produced by DICE-Tester can be found in the [traces directory](https://github.com/kanghj/DICE/tree/master/traces).

The models output are in the [outputs directory](https://github.com/kanghj/DICE/tree/master/outputs)

As for the models of Tautoko, they can be found in this [tautoko directory](https://github.com/kanghj/DICE/tree/master/tautoko)

The traces and model used for fuzzing the FTP and RTSP server are found [here](https://github.com/kanghj/DICE/tree/master/server_fuzzing/server_fuzzing).
The source code of AFLNET, which we modified, can be found [here](https://github.com/kanghj/DICE/tree/master/dice-aflnet).
AFLNET was originally found at https://github.com/aflnet/aflnet and was developed by Van-Thuan Pham and Marcel Böhme and Abhik Roychoudhury
