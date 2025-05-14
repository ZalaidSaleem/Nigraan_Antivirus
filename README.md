# Nigraan_Antivirus
AI-Assisted Antivirus

A Deep Learning framework that analyses Windows PE files to detect malicious Softwares. the project includes:
*   Sate of the art of the work done using machine learning or deep learning.
*   A new approach for detection:
    * Enhancing detection rate and reducing False positive rate
    * Proposing a technique to garantee the evolution of the model
*   Defining and implementing a framework to extract PE files representation, this includes:
    * Opcodes sequences
    * Opcodes stats
    * Bytes n-grams
    * API Calls
*   Building a training data set
    * Over 120.000 malwares
    * Over 30.000 benign software
*   Defining and implementing a Deep Learning architecture to learn on the extracted data
    * SAE: n-grams of bytes
    * RNN: sequences of opcodes
    * CNN: exe to bytes image
    * FNN: a submodule to the SAE

Check Readme in NigraanWeb 



