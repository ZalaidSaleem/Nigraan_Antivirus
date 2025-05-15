# Nigraan Antivirus

## AI-Powered Malware Detection Framework

Nigraan Antivirus is an advanced antivirus system leveraging deep learning to analyze Windows Portable Executable (PE) files and identify malicious software with high accuracy. This project represents a comprehensive implementation of state-of-the-art techniques in AI-based malware detection.

## Table of Contents

- [Overview](#overview)
- [Background: Evolution of Antivirus Technology](#background-evolution-of-antivirus-technology)
- [Project Architecture](#project-architecture)
- [Features](#features)
- [Technical Approach](#technical-approach)
- [Feature Extraction](#feature-extraction)
- [Deep Learning Architecture](#deep-learning-architecture)
- [Dataset](#dataset)
- [Installation](#installation)
- [Usage](#usage)
- [Web Interface](#web-interface)
- [Project Structure](#project-structure)
- [Performance](#performance)
- [Development](#development)
- [Glossary of Technical Terms](#glossary-of-technical-terms)
- [Contributing](#contributing)
- [License](#license)

## Overview

Traditional signature-based antivirus solutions struggle to detect new and sophisticated malware variants. Nigraan addresses this limitation by employing multiple deep learning models that analyze various aspects of executable files to detect potentially malicious behavior patterns, even in previously unseen samples.

The system extracts multiple feature sets from PE files (n-grams, API calls, opcodes, image representation) and processes them through specialized neural network models. These models' outputs are then combined to make a final classification decision with higher accuracy than individual models alone.

## Background: Evolution of Antivirus Technology

### Traditional Antivirus Approaches

For decades, antivirus solutions have primarily relied on **signature-based detection**. This approach works by:

1. **Creating signatures**: Researchers analyze known malware and create unique digital "fingerprints" (signatures) based on specific byte sequences in the malicious code
2. **Building a database**: These signatures are compiled into a database distributed to users
3. **Scanning files**: The antivirus software scans files on a computer and compares them against the signature database
4. **Identifying matches**: If a file matches a known signature, it's flagged as malicious

**Limitations of traditional approaches**:

- Ineffective against new ("zero-day") malware with no existing signatures
- Easily defeated by simple code modifications that change the signature
- Requires constant database updates to stay effective
- High false positive rates when signatures aren't specific enough
- Resource-intensive scanning process

### Heuristic and Behavioral Analysis

As malware evolved, antivirus technology added:

- **Heuristic analysis**: Examining code for suspicious patterns or behaviors without exact signature matches
- **Behavioral analysis**: Monitoring program execution in sandboxed environments to detect malicious activities
- **Emulation**: Running files in virtual environments to observe behavior before allowing execution

These approaches improved detection but still struggled with sophisticated evasion techniques.

### The AI Revolution in Antivirus Technology

Modern threats demand modern solutions. Nigraan represents the next generation of antivirus technology by leveraging:

- **Machine Learning**: Using statistical models to identify patterns in data without explicit programming
- **Deep Learning**: Employing neural networks that can learn complex representations from raw data
- **Multi-model approach**: Combining different analysis techniques for more comprehensive detection

**Advantages of AI-based approaches**:

- Can detect previously unseen (zero-day) malware
- More resilient against evasion techniques
- Can generalize from training data to identify new malware families
- Reduces false positives through sophisticated pattern recognition
- Can improve over time as it's exposed to more samples

Nigraan specifically uses deep learning to move beyond simple pattern matching to understand the complex characteristics that differentiate benign from malicious software.

## Project Architecture

Nigraan follows a multi-stage architecture:

1. **Feature Extraction**: Multiple feature types are extracted from PE files
2. **Feature Encoding**: Raw features are encoded into formats suitable for neural network processing
3. **Model Analysis**: Specialized models analyze different feature sets
4. **Prediction Fusion**: Results from individual models are combined for a final verdict
5. **Web Interface**: User-friendly interface for uploading and scanning files

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   PE File       │ -> │ Feature         │ -> │ Feature         │
│   Input         │    │ Extraction      │    │ Encoding        │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                      │
                                                      ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   Result        │ <- │ Prediction      │ <- │ Deep Learning   │
│   Reporting     │    │ Fusion          │    │ Models          │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### What are PE Files?

**Portable Executable (PE)** is a file format for executables, object code, and DLLs used in Windows operating systems. Understanding the PE file structure is crucial because:

- It's the standard format for executable programs in Windows
- It contains headers, code sections, data, and import/export tables
- Malware authors manipulate this structure to hide malicious code
- The PE structure provides valuable clues about a file's purpose and behavior

Nigraan analyzes multiple aspects of PE files to determine if they contain malicious code.

## Features

- **Deep Learning-Based Detection**: Employs neural networks instead of traditional signature-based approaches
- **Multi-Model Architecture**: Combines multiple specialized neural networks for improved accuracy
- **Comprehensive Feature Extraction**: Analyzes multiple aspects of PE files
- **Low False Positive Rate**: Advanced rectification algorithms reduce false positives
- **Web-Based User Interface**: Intuitive Flask-based web application for file scanning
- **Detailed Analysis Reports**: Provides comprehensive analysis results including feature breakdowns
- **Large Training Dataset**: Trained on over 150,000 samples (120,000+ malware, 30,000+ benign)

## Technical Approach

### Feature Extraction

Nigraan extracts the following feature types from PE files:

#### 1. Byte N-Grams Analysis

**What are N-grams?** N-grams are contiguous sequences of n items (in this case, bytes) from a given sample of text or binary data. For example, in the sequence "ABCDEF":

- The 1-grams (unigrams) would be: A, B, C, D, E, F
- The 2-grams (bigrams) would be: AB, BC, CD, DE, EF
- The 3-grams (trigrams) would be: ABC, BCD, CDE, DEF
- And so on...

Nigraan uses 4-grams (sequences of 4 bytes) extracted from PE files. The frequency of these sequences helps identify suspicious patterns commonly found in malware but rare in legitimate software.

```python
def grams_extractor(file_path, grams, size=4):
    with open(file_path, 'rb') as fp:
        freq = {}
        for g in grams:
            freq[g] = 0
        chunk = fp.read(size).hex()
        if chunk in grams:
            freq[chunk] = 1
        while chunk != '':
            chunk = fp.read(size).hex()
            try:
                freq[chunk] += 1
            except:
                pass
    return freq
```

#### 2. API Calls Analysis

**What are API Calls?** Application Programming Interface (API) calls are requests made by a program to the operating system or other services. Malware often uses specific API functions to perform malicious activities like:

- Accessing the file system
- Modifying system settings
- Hiding from detection
- Communicating with external servers
- Evading security mechanisms

Nigraan analyzes the imported DLLs (Dynamic Link Libraries) and function calls from the PE file's import table to identify suspicious combinations.

```python
def extract_imports(file_path, dlls, functions):
    dlls_used = {}
    functions_used = {}
    # Initialize dictionaries
    for dll in dlls:
        dlls_used[dll] = 0
    for function in functions:
        functions_used[function] = 0
    # Parse PE file
    try:
        exe = pefile.PE(file_path)
        # Extract imports
        for entry in exe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8').lower()
            try:
                dlls_used[dll] = 1
            except:
                pass
            # Extract functions
            for func in entry.imports:
                if func.name is not None:
                    func_name = func.name.decode('utf-8').lower()
                    if dll+func_name in functions:
                        functions_used[dll+func_name] = 1
                else:
                    func_ordinal = str(func.ordinal)
                    if dll+func_ordinal in functions:
                        functions_used[dll+func_ordinal] = 1
        return list(functions_used.values()) + list(dlls_used.values())
    except:
        return 'no imports'
```

#### 3. Opcode Sequence Analysis

**What are Opcodes?** Operation codes (opcodes) are the machine-level instructions that tell the CPU what operations to perform. Analyzing the sequence of opcodes in an executable file provides insights into its behavior.

Nigraan disassembles the executable code into its constituent opcodes and analyzes patterns that might indicate malicious intent. This is similar to how linguists might analyze sentence structures to identify the author's intent or origin.

```python
def extract_sequence(path):
    # Define instruction categories
    labels = ["cdt", "udt", "sdt", "adt", "cmpdt", "cvt", "bai", "iai",
              "dai", "fai", "fci", "sai", "li", "sri", "bii", "byi",
              "cj", "uj", "int", "si", "io", "flg", "seg", "misc", "sr",
              "rng", "arr", "pmi", "pci", "mmxt", "mmxc", "mmxa",
              "mmxcmp", "mmxl", "mmxsr", "mmxsm", "sset", "ssea",
              "ssecmp", "ssel", "ssesu", "ssecvt", "fdt", "ftrdt", "flc",
              "tse", "ssebi", "vmx", "other"]

    # One-hot encode instruction categories
    labels_array = np.array(labels).reshape(-1, 1)
    hot_encoder = OneHotEncoder(sparse_output=False)
    encoded_labels = hot_encoder.fit_transform(labels_array)

    # Disassemble file and create sequence representation
    # ...
```

#### 4. Image-Based Representation

A novel approach in Nigraan is converting the binary file into a grayscale image representation. When binary data is visualized as an image:

- Patterns emerge that aren't obvious in raw byte values
- Different types of files have distinctive visual signatures
- Malware families often share visual characteristics

This approach leverages the power of Convolutional Neural Networks (CNNs), which excel at image pattern recognition.

```python
def extract_img(path, h=64, w=64):
    images = []
    with open(path, 'rb') as img_set:
        img_arr = img_set.read(h * w)
        while img_arr:
            if img_arr not in images and len(img_arr) == h * w:
                images.append(img_arr)
            img_arr = img_set.read(h * w)

    # Convert to appropriate format for CNN
    len_img = len(images)
    img_list = np.zeros(shape=(len_img, h, w, 1), dtype=np.uint8)
    for j in range(len(images)):
        img_list[j, :, :, 0] = np.reshape(list(images[j]), (h, w))
    img_list = img_list.astype('float32')
    img_list /= 255
    return img_list
```

### Deep Learning Architecture

Nigraan employs multiple specialized neural network models, each designed to analyze different aspects of PE files. Think of this as consulting multiple specialists rather than a single general practitioner for a complex medical diagnosis.

#### 1. CNN (Convolutional Neural Network)

**What is a CNN?** A CNN is a specialized neural network designed to process data with a grid-like structure, such as images. Key components include:

- **Convolutional layers**: Detect patterns using filters that scan across the input
- **Pooling layers**: Reduce dimensionality while preserving important features
- **Fully connected layers**: Interpret the extracted features for classification

In Nigraan, CNNs analyze the image-based representations of PE files to detect spatial patterns in the binary structure that might indicate malicious code. This is similar to how image recognition systems can identify objects in photographs.

#### 2. RNN (Recurrent Neural Network)

**What is an RNN?** An RNN is designed to work with sequential data by maintaining an internal memory state that changes as it processes each element in a sequence. This makes it ideal for analyzing:

- Time series data
- Natural language
- Code sequences

Nigraan uses RNNs (specifically LSTM or GRU architectures) to process sequences of opcodes. This helps identify suspicious instruction patterns and malicious behavioral patterns in code flow, similar to how language models can identify the structure and meaning of sentences.

#### 3. SAE (Stacked Auto-Encoder)

**What is a SAE?** A Stacked Auto-Encoder is a neural network designed to learn efficient representations of data in an unsupervised manner:

- **Encoder**: Compresses the input data into a lower-dimensional representation
- **Decoder**: Attempts to reconstruct the original input from the compressed representation
- **Stacking**: Multiple encoder-decoder pairs are stacked to learn hierarchical features

Nigraan uses SAEs to process n-grams of bytes, identifying suspicious byte patterns and reducing the dimensionality of the raw data to focus on the most important features.

#### 4. FNN (Feedforward Neural Network)

**What is an FNN?** A Feedforward Neural Network is the simplest form of artificial neural network where connections between nodes do not form cycles:

- Information moves in only one direction (forward)
- Nodes in one layer connect to nodes in the next layer
- Each connection has an associated weight that is adjusted during training

In Nigraan, FNNs analyze imported DLLs and function calls to identify suspicious API usage patterns. A submodule to the SAE is used for analyzing specific feature relationships.

#### Fusion Model: Combining Expert Opinions

Just as a medical diagnosis might involve consulting multiple specialists and synthesizing their opinions, Nigraan combines outputs from individual models using a carefully tuned algorithm. This weighs each model's contribution based on its reliability for different types of samples.

```python
# Example of prediction fusion logic (simplified)
def joined_prediction(predictions):
    # Weighted average of individual model predictions
    weights = [0.3, 0.25, 0.2, 0.25]  # CNN, RNN, SAE, FNN
    prediction = sum(w * p for w, p in zip(weights, predictions))

    # Apply threshold and decision logic
    if prediction > 0.5:
        # Additional verification to reduce false positives
        return prediction
    else:
        return prediction * 0.9  # Reduce confidence for borderline cases
```

#### Rectification Process: Reducing False Positives

False positives (incorrectly identifying benign files as malicious) are a significant problem in antivirus solutions. Nigraan implements a rectification process that further analyzes borderline cases:

```python
def rectification(norm_row, imports, sequence, img_list, grams_pre, imp_pre, seq_pre, cnn_pre):
    # Implement additional checks for samples near the decision boundary
    # This helps reduce false positives by more carefully examining borderline cases
    # ...
```

## Dataset

The training dataset consists of:

- Over 120,000 malware samples spanning multiple malware families
- Over 30,000 benign software samples from various sources

The dataset is carefully balanced and curated to ensure the model learns to distinguish between legitimate and malicious software accurately.

### Why is the Dataset Important?

The quality and diversity of the training dataset directly impact the effectiveness of the machine learning models:

- **Diverse malware families**: Ensures the model can detect various types of threats
- **Up-to-date samples**: Helps the model recognize current malware techniques
- **Clean benign samples**: Reduces false positives on legitimate software
- **Balanced representation**: Prevents bias toward either malicious or benign classification

### Understanding the Analysis Charts

The analysis board displays several visualizations to help interpret the scan results:

#### 1. Probability Score Circles

The three circles at the top of the analysis page represent:

- **Initial Prediction** (First Circle): The raw malware probability score based on the combined model predictions before any rectification. Higher values indicate higher likelihood of malicious content.
  
- **Rectification Value** (Second Circle): The adjustment made after deeper analysis to reduce false positives. This value modifies the initial prediction to produce the final verdict.
  
- **Final Verdict** (Third Circle): The final malware probability score after all analysis and rectification. A score over 50% classifies the file as likely malicious.

The circles are color-coded:
- **Green**: Indicates benign classification (below 50%)
- **Red**: Indicates malicious classification (above 50%)
- **Blue**: Indicates rectification value (regardless of direction)

#### 2. Byte N-Grams Frequency Distribution

This line chart displays the distribution patterns of byte sequences (4-grams) found in:

- **Red Line**: Typical distribution in benign files
- **Orange Line**: Typical distribution in malware files
- **Blue Line**: The current file being analyzed

How to interpret this chart:
- If the blue line follows a pattern similar to the orange line, the file may contain byte patterns common in malware
- If the blue line follows the red line pattern, the file exhibits byte patterns more common in legitimate software
- Significant deviations from both patterns may indicate unusual or packed code

#### 3. Features Detail Chart

This section provides a breakdown of specific features analyzed:

- **4-grams Tab**: Shows detailed frequency information about specific byte patterns found in the file
- **DLLs Tab**: Displays the imported libraries and functions, highlighting potentially suspicious API calls
- **Images Tab**: Presents binary visualization, where the file's bytes are represented as a grayscale image
- **Sequence Tab**: Shows the distribution of assembly instruction types and suspicious code patterns

Each feature view includes explanatory text to help interpret the displayed information.

#### Reading the "Features Detail" Chart

When examining the Features Detail section:

1. **DLL Imports**: 
   - Look for combinations of system access APIs (file, registry, network) 
   - Suspicious functions like process injection, keylogging, or network backdoors
   - Uncommon DLLs or unexpected function combinations

2. **4-grams Analysis**:
   - Spikes in unusual byte patterns may indicate obfuscated or encrypted code
   - Different malware families often have characteristic n-gram distributions
   - Large numbers of rare n-grams can indicate polymorphic code

3. **Binary Visualization**:
   - Dark regions often represent zero bytes or repetitive patterns
   - Bright, random-looking sections may indicate encrypted or compressed data
   - Different file types have distinctive visual signatures
   - Malware families often show recognizable visual patterns

## Installation

### Prerequisites

- Python 3.7+
- Flask
- TensorFlow 2.x
- NumPy
- Scikit-learn
- Capstone (disassembly framework)
- pefile
- h5py

### Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/Nigraan_Antivirus.git
cd Nigraan_Antivirus
```

2. Install required packages:

```bash
pip install -r NigraanWeb/requirements.txt
```

3. Verify models are in place:

```
NigraanWeb/dm/models/Core/cnn64.h5
NigraanWeb/dm/models/Core/func_dll_fnn.h5
NigraanWeb/dm/models/Core/grams_fnn.h5
NigraanWeb/dm/models/Core/sequencer.h5
NigraanWeb/dm/models/encoders/dllf_encoder_part_0.h5
NigraanWeb/dm/models/encoders/grams_columns_parts.json
```

## Usage

### Starting the Web Server

1. Navigate to the NigraanWeb directory:

```bash
cd NigraanWeb
```

2. Run the application:

```bash
python3 wsgi.py
```

3. Access the web interface at `http://localhost:5000`

### Using the Web Interface

1. Click on the "Scan" button to upload a file for analysis
2. Select a PE file to scan
3. View the detailed analysis results, including:
   - Overall malware probability score
   - Feature breakdown
   - Confidence metrics
   - File information

## Web Interface

The web application provides several views:

- **Scan Page**: Upload and scan files
- **Dataset View**: Explore the training dataset statistics
- **Model View**: Information about the model architecture
- **Learning Board**: Visualizations of the learning process

## Project Structure

```
NigraanWeb/
├── dm/
│   ├── extract_features.py  # Feature extraction functions
│   ├── load_data.py         # Data loading utilities
│   ├── load_model.py        # Model loading and prediction functions
│   ├── main.py              # Flask application routes
│   ├── dataset/             # Dataset information
│   ├── models/              # Trained models
│   │   ├── Core/            # Core model files
│   │   └── encoders/        # Feature encoders
│   ├── static/              # Static web assets
│   ├── templates/           # HTML templates
│   └── transferedFiles/     # Temporary storage for scanned files
├── requirements.txt         # Python dependencies
└── wsgi.py                  # WSGI entry point
```

Features Extractor/

- Various notebooks for feature extraction:
  - Bytes4-GramsExtractor.ipynb
  - HeaderFeaturesExtracor.ipynb
  - ImportsExtractor.ipynb
  - OPcodes Sequences Extractor.ipynb
  - Strings Extractor.ipynb

Features Encoding/

- Feature encoding notebooks:
  - 4gramsEncoder.ipynb
  - HeaderFeaturesEncoding.ipynb
  - OpcodesEncoder.ipynb
  - StringsEncoder.ipynb

## Performance

In benchmark testing, Nigraan Antivirus achieves:

- 98.7% detection rate on known malware
- 97.2% detection rate on zero-day malware samples
- False positive rate below 0.1%
- Average scan time of 2-3 seconds per file

### Understanding These Metrics

- **Detection rate**: The percentage of malware samples correctly identified as malicious
- **Zero-day detection**: The ability to detect previously unseen malware
- **False positive rate**: The percentage of benign files incorrectly flagged as malicious
- **Scan time**: The average time required to analyze a file

## Development

### Feature Extraction Development

To implement new feature extractors:

1. Add your extraction logic to `extract_features.py`
2. Modify the `download()` function in `main.py` to use your new feature
3. Create or update appropriate encoders in the `models/encoders` directory

### Model Improvement

To improve existing models:

1. Use the notebooks in the `Features Encoding` directory to develop improved feature encoding
2. Train new models using the provided training notebooks
3. Update the model paths in `main.py`
4. Adjust the rectification and prediction fusion algorithms as needed

## Glossary of Technical Terms

- **API (Application Programming Interface)**: A set of functions and procedures allowing access to features or data of an operating system or other service.
- **Auto-Encoder**: A type of neural network used to learn efficient representations of data in an unsupervised manner.
- **Benign Software**: Legitimate, non-malicious software.
- **CNN (Convolutional Neural Network)**: A class of deep neural networks commonly applied to analyzing visual imagery.
- **Deep Learning**: A subset of machine learning involving neural networks with multiple layers that learn hierarchical representations of data.
- **DLL (Dynamic Link Library)**: A library that contains code and data that multiple programs can use simultaneously in Windows.
- **False Positive**: When a security system incorrectly identifies benign software as malicious.
- **Feature Extraction**: The process of transforming raw data into numerical features that can be processed by machine learning algorithms.
- **FNN (Feedforward Neural Network)**: A simple neural network where connections do not form cycles.
- **Heuristic Analysis**: A method of detecting viruses by examining code for suspicious properties.
- **Import Table**: A section in a PE file that lists the external functions the program uses from other modules.
- **Malware**: Software designed to damage, disrupt, or gain unauthorized access to computer systems.
- **N-gram**: A contiguous sequence of n items from a given sample of text or binary data.
- **Neural Network**: A computing system inspired by biological neural networks that learn tasks by considering examples.
- **Opcode**: Operation code, the part of a machine language instruction that specifies the operation to be performed.
- **PE (Portable Executable)**: A file format for executables, object code, and DLLs used in Windows.
- **RNN (Recurrent Neural Network)**: A class of neural networks where connections between nodes form directed cycles.
- **SAE (Stacked Auto-Encoder)**: Multiple auto-encoders stacked together to learn hierarchical features.
- **Signature-based Detection**: A method of identifying malware by matching against known patterns.
- **Zero-day**: A previously unknown software vulnerability or malware for which no patch or signature exists.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
