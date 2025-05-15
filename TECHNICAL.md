# Nigraan Antivirus: Technical Deep Dive

This document provides a comprehensive technical overview of the Nigraan Antivirus project, explaining the inner workings of the system, the machine learning models used, the feature extraction techniques, and the complete workflow from file upload to analysis results.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [System Workflow](#system-workflow)
3. [Feature Extraction Techniques](#feature-extraction-techniques)
   - [Byte N-Gram Analysis](#byte-n-gram-analysis)
   - [API Call Analysis](#api-call-analysis)
   - [Opcode Sequence Analysis](#opcode-sequence-analysis)
   - [Image-Based Representation](#image-based-representation)
4. [Deep Learning Models](#deep-learning-models)
   - [CNN for Image Analysis](#cnn-for-image-analysis)
   - [RNN for Opcode Sequences](#rnn-for-opcode-sequences)
   - [SAE for N-Gram Analysis](#sae-for-n-gram-analysis)
   - [FNN for API Calls](#fnn-for-api-calls)
5. [Model Fusion and Decision Making](#model-fusion-and-decision-making)
6. [Web Application Implementation](#web-application-implementation)
7. [Performance Optimization](#performance-optimization)
8. [Future Enhancements](#future-enhancements)

## Architecture Overview

Nigraan Antivirus employs a multi-layered architecture that combines feature extraction, deep learning, and decision-making components to analyze Windows PE (Portable Executable) files for potential malware. The system is designed to be both accurate and efficient, with a focus on reducing false positives.

### High-Level Components

1. **Web Interface**: Flask-based web application that allows users to upload files for analysis
2. **Feature Extraction Engine**: Extracts multiple feature types from PE files
3. **Deep Learning Models**: Multiple specialized neural networks for analyzing different feature types
4. **Fusion System**: Combines outputs from individual models
5. **Rectification Module**: Performs additional analysis on borderline cases to reduce false positives
6. **Results Visualization**: Interactive dashboard for displaying analysis results

### Data Flow

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

## System Workflow

The complete workflow of Nigraan Antivirus can be broken down into the following steps:

### 1. File Upload

The process begins when a user uploads a PE file through the web interface. The file is saved temporarily with a random identifier to prevent naming conflicts.

```python
@app.route('/scan/download', methods=['GET', 'POST'])
def download():
    start = timeit.timeit()
    file_name = request.files['file']
    seed = np.random.randint(1000000)
    file_name.save(os.path.join('./dm/transferedFiles', str(seed)))
    file_size = os.stat(os.path.join('./dm/transferedFiles', str(seed))).st_size
    
    # Feature extraction begins here...
```

### 2. Multi-feature Extraction

Once the file is saved, the system extracts multiple feature types concurrently:

#### a. Byte 4-gram Extraction

```python
# Load 4-gram columns from JSON
with open("./dm/models/encoders/grams_columns_parts.json") as gcp:
    columns_lst = json.load(gcp)
    
columns = []
for cl in columns_lst:
    columns += cl

# Extract 4-gram frequencies
freq = grams_extractor(os.path.join('./dm/transferedFiles', str(seed)), columns)
grams_freq = grams_rf(freq)
row = grams_row(grams_freq, columns)
norm_row_ = normalized_row(row)
norm_row = []
for nr in norm_row_:
    norm_row.append(nr[0])
```

#### b. Import Extraction

```python
# Extract DLL and function imports
with open(os.path.join(original_path, 'dlls.csv'), 'r') as dlls:
    csv_reader = csv.reader(dlls)
    col_dlls = next(csv_reader)
    del col_dlls[0]
    del col_dlls[-1]

with open(os.path.join(original_path, 'functions.csv'), 'r') as func:
    csv_reader = csv.reader(func)
    col_func = next(csv_reader)
    del col_func[0]
    del col_func[-1]

file_path = os.path.join('./dm/transferedFiles', str(seed))
imports = extract_imports(file_path, col_dlls, col_func)
```

#### c. Opcode Sequence Extraction

```python
# Extract opcode sequences for disassembly analysis
sequence = extract_sequence(file_path)
```

#### d. Image Representation Extraction

```python
# Convert file to image representation
img_list = extract_img(file_path)
```

### 3. Feature Encoding

The extracted features are encoded into formats suitable for input to neural networks:

```python
# Load column parts for feature encoding
with open(os.path.join('./dm/models/encoders', 'grams_columns_parts.json'), 'r') as gcp:
    columns_parts = json.load(gcp)

# Encode imports for neural network input
encoded_imports = evaluate_df_encoder(imports, models)
```

### 4. Model Prediction

Each specialized model analyzes its corresponding feature set:

```python
# Run models on their respective features
cnn_pre = models[0].predict(img_list)  # CNN model for image analysis
seq_pre = models[3].predict(sequence)  # RNN model for opcode sequences
grams_pre = [[0.]]  # SAE model for n-grams (commented out in the code)
imp_pre = models[1].predict(encoded_imports)  # FNN model for imports
```

### 5. Prediction Fusion and Rectification

The outputs from individual models are combined, and additional analysis is performed on borderline cases:

```python
# Combine predictions from all models
pre_prediction = joined_prediction([np.mean(cnn_pre), np.mean(seq_pre), grams_pre[0][0], imp_pre[0][0]])

# Apply rectification to reduce false positives
rect = rectification(norm_row, imports, sequence, img_list, grams_pre, imp_pre, seq_pre, cnn_pre)

# Calculate final prediction
final_prediction = pre_prediction + rect
```

### 6. Results Processing and Storage

The analysis results are stored for display in the web interface:

```python
# Store analysis results
analysis['pre_prediction'] = float(pre_prediction)
analysis['rectification'] = rect
analysis['rectified'] = pre_prediction + rect
analysis['grams'] = [x for x in norm_row]
analysis['imports'] = str(imports_json(file_path))
analysis['file_size'] = file_size / 1000
analysis['time'] = (end - start)

# Calculate file hash for identification
sha256_hash = hashlib.sha256()
with open(os.path.join('./dm/transferedFiles', str(seed)), "rb") as f:
    for byte_block in iter(lambda: f.read(16384), b""):
        sha256_hash.update(byte_block)
analysis['hash'] = sha256_hash.hexdigest()

# Save analysis to file
with open('./dm/models/analysis.json', 'w') as ana:
    json.dump(analysis, ana)
```

### 7. Results Display

The web interface renders the results in an interactive dashboard:

```python
@app.route('/scan/results', methods=['GET', 'POST'])
def send_results():
    global analysis
    if analysis != {}:
        return analysis
    else:
        with open('./dm/models/analysis.json', 'r') as ana:
            analysis = json.load(ana)
        return analysis
```

## Feature Extraction Techniques

Nigraan's multi-feature approach allows it to analyze PE files from different perspectives, capturing various aspects of potentially malicious behavior.

### Byte N-Gram Analysis

N-gram analysis treats the PE file as a sequence of bytes and extracts patterns of consecutive bytes (4-byte sequences in this case). The frequency distribution of these n-grams helps identify suspicious patterns that are common in malware but rare in legitimate software.

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

The n-gram frequencies are then normalized to account for varying file sizes:

```python
def grams_rf(freq):
    summ = 0
    for g in freq:
        summ += freq[g]
    if summ == 0:
        return freq
    for g in freq:
        freq[g] = freq[g] / summ
    return freq
```

### API Call Analysis

Malware often uses specific combinations of API calls to perform malicious activities. Nigraan analyzes the imported DLLs and function calls from the PE file's import table to identify suspicious combinations.

```python
def extract_imports(file_path, dlls, functions):
    dlls_used = {}
    functions_used = {}
    for dll in dlls:
        dlls_used[dll] = 0
    for function in functions:
        functions_used[function] = 0
    try:
        exe = pefile.PE(file_path)
    except Exception as e:
        print(f"PE parsing error: {str(e)}")
        return 'parsing error'
    
    # Check if the import directory exists
    if not hasattr(exe, 'DIRECTORY_ENTRY_IMPORT'):
        try:
            # Try to parse imports if they exist but weren't parsed automatically
            exe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        except Exception as e:
            print(f"No import directory found: {str(e)}")
            # If the file genuinely has no imports, return empty lists
            return list(functions_used.values()) + list(dlls_used.values())
    
    try:
        # Make sure DIRECTORY_ENTRY_IMPORT exists after trying to parse it
        if hasattr(exe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in exe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8').lower()
                try:
                    dlls_used[dll] = 1
                except Exception as e:
                    print(f"DLL not in list: {dll}")
                    pass
                
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
    except Exception as e:
        print(f"Error extracting imports: {str(e)}")
        # Instead of returning 'no imports', return the empty list we initialized
        # This will allow the program to continue even if there are no imports
        return list(functions_used.values()) + list(dlls_used.values())
```

For detailed analysis in the web interface, a more comprehensive extraction is performed:

```python
def imports_json(file_path):
    imports = {}
    try:
        exe = pefile.PE(file_path)
    except Exception as e:
        print(f"imports_json PE parsing error: {str(e)}")
        return 'parsing error'
        
    # Extract all imports into a structured JSON format
    # ...
    
    return imports
```

### Opcode Sequence Analysis

Opcode sequence analysis involves disassembling the executable code into its constituent machine instructions and analyzing the patterns of instruction types that might indicate malicious intent.

```python
def extract_sequence(path):
    # Define categories of instructions
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

    # Create mapping from labels to encoded vectors
    encode_dict = {}
    for l, e in zip(labels, encoded_labels):
        encode_dict[l] = e

    # Disassemble the file and extract instruction sequences
    sequence = quick_disassemble(path)
    
    # Process the sequence into the format required by RNN
    # ...
    
    return data_array
```

The disassembly process uses the Capstone framework to decode machine instructions:

```python
def quick_disassemble(path, depth=128000):
    try:
        exe = pefile.PE(path)
        gr = fine_disassemble(exe, depth)
        return gr
    except Exception as e:
        print(f"quick_disassemble error: {str(e)}")
        return None
```

### Image-Based Representation

A novel approach in Nigraan is converting the binary file into a grayscale image representation. This allows the system to leverage Convolutional Neural Networks (CNNs) for detecting spatial patterns in the binary structure.

```python
def extract_img(path, h=64, w=64):
    try:
        images = []
        with open(path, 'rb') as img_set:
            img_arr = img_set.read(h * w)
            while img_arr:
                if img_arr not in images and len(img_arr) == h * w:
                    images.append(img_arr)
                img_arr = img_set.read(h * w)
        
        # Convert bytes to image representation
        len_img = len(images)
        img_list = np.zeros(shape=(len_img, h, w, 1), dtype=np.uint8)
        for j in range(len(images)):
            img_list[j, :, :, 0] = np.reshape(list(images[j]), (h, w))
        img_list = img_list.astype('float32')
        img_list /= 255
        return img_list
    except Exception as e:
        print(f"Error extracting images: {str(e)}")
        # Return fallback image
        return np.zeros(shape=(1, h, w, 1), dtype='float32')
```

## Deep Learning Models

Nigraan employs multiple specialized neural network models to analyze different aspects of PE files.

### CNN for Image Analysis

The Convolutional Neural Network (CNN) analyzes the image-based representation of PE files. This model is particularly effective at detecting spatial patterns in the binary structure that might indicate malicious code.

**Model Architecture:**
- Input: 64x64 grayscale images
- Convolutional layers with filters of different sizes
- Max pooling layers for dimensionality reduction
- Fully connected layers for classification
- Output: Malware probability score

```python
# Model is loaded from a pre-trained H5 file
cnn_model = load_model('./dm/models/Core/cnn64.h5')
```

**Prediction Process:**
```python
# Run CNN model on image representation
cnn_pre = models[0].predict(img_list)
```

### RNN for Opcode Sequences

The Recurrent Neural Network (RNN) processes sequences of opcodes to detect suspicious instruction patterns. This model is particularly effective at identifying malicious behavioral patterns in code flow.

**Model Architecture:**
- Input: Sequences of one-hot encoded instruction categories
- LSTM/GRU layers for sequence processing
- Dense layers for classification
- Output: Malware probability score

```python
# Model is loaded from a pre-trained H5 file
rnn_model = load_model('./dm/models/Core/sequencer.h5')
```

**Prediction Process:**
```python
# Run RNN model on opcode sequences
seq_pre = models[3].predict(sequence)
```

### SAE for N-Gram Analysis

The Stacked Auto-Encoder (SAE) processes n-grams of bytes to identify suspicious byte patterns in an unsupervised manner. This helps in dimensionality reduction and feature learning from raw bytes.

**Model Architecture:**
- Input: Normalized n-gram frequencies
- Multiple encoder-decoder pairs
- Bottleneck layer for compressed representation
- Classification layer for malware detection
- Output: Malware probability score

```python
# Model is loaded from a pre-trained H5 file
sae_model = load_model('./dm/models/Core/grams_fnn.h5')
```

**Prediction Process:**
```python
# In the current code, this is commented out/simplified
# grams_pre = models[2].predict(encoded_grams)
grams_pre = [[0.]]
```

### FNN for API Calls

The Feedforward Neural Network (FNN) analyzes imported DLLs and function calls to identify suspicious API usage patterns.

**Model Architecture:**
- Input: Binary vector indicating presence/absence of DLLs and functions
- Multiple fully connected layers
- Output: Malware probability score

```python
# Model is loaded from a pre-trained H5 file
fnn_model = load_model('./dm/models/Core/func_dll_fnn.h5')
```

**Prediction Process:**
```python
# Run FNN model on encoded imports
imp_pre = models[1].predict(encoded_imports)
```

## Model Fusion and Decision Making

Nigraan combines outputs from individual models using a carefully tuned algorithm that weights each model's contribution based on its reliability for different types of samples.

### Prediction Fusion

```python
def joined_prediction(predictions):
    # Example implementation (actual implementation may be more complex)
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

### Rectification Process

To reduce false positives, Nigraan implements a rectification process that further analyzes borderline cases:

```python
def rectification(norm_row, imports, sequence, img_list, grams_pre, imp_pre, seq_pre, cnn_pre):
    # Example implementation (actual implementation may be more complex)
    # This function performs additional checks on samples near the decision boundary
    # to reduce false positives
    
    # It may analyze combinations of features or specific patterns that are
    # known to cause false positives
    
    # Returns an adjustment value to be added to the initial prediction
    return adjustment_value
```

## Web Application Implementation

The web application is built using Flask, a lightweight Python web framework. It provides an intuitive interface for users to upload files for analysis and view the results.

### Main Application Structure

```python
app = Flask(__name__)
app.config['APP_NAME'] = 'Nigraan'
analysis_page = False
analysis = {}

# Load pre-trained models
core_models = './dm/models/Core'
encoders = './dm/models/encoders'

paths = ['./dm/models/Core/cnn64.h5',
         os.path.join(core_models, 'func_dll_fnn.h5'),
         os.path.join(core_models, 'grams_fnn.h5'),
         os.path.join(core_models, 'sequencer.h5'),
         os.path.join(encoders, 'dllf_encoder_part_0.h5'),
         ]

models = load_static(paths)
```

### Routes

The application defines several routes to handle different functionalities:

```python
@app.route('/')
def index():
    global analysis_page
    if analysis_page:
        return render_template('app/index.html', name='home')
    else:
        return redirect('/scan')

@app.route('/scan')
def scan():
    return render_template('app/scanpage.html')

@app.route('/dataset')
def dataset():
    with open('./dm/dataset/DescriptionFiles/DataSetHeader.json', 'r') as desc:
        dataset_desc = json.load(desc)
    return render_template('app/tables/datatables.html', description=dataset_desc)

@app.route('/model')
def model():
    return render_template('app/widgets.html')

@app.route('/learning_board')
def learning_board():
    return render_template('app/charts/charts.html')
```

### File Upload and Analysis

The `/scan/download` route handles file uploads and initiates the analysis process:

```python
@app.route('/scan/download', methods=['GET', 'POST'])
def download():
    # File upload and analysis process
    # ...
```

### Results Display

The `/scan/results` route returns the analysis results for display in the web interface:

```python
@app.route('/scan/results', methods=['GET', 'POST'])
def send_results():
    global analysis
    if analysis != {}:
        return analysis
    else:
        with open('./dm/models/analysis.json', 'r') as ana:
            analysis = json.load(ana)
        return analysis
```

## Performance Optimization

Nigraan implements several optimizations to ensure efficient analysis:

### Memory Management

Garbage collection is used to free memory after resource-intensive operations:

```python
# Free memory after encoding operations
encoded_imports = evaluate_df_encoder(imports, models)
gc.collect()
```

### Error Handling and Graceful Degradation

The system includes comprehensive error handling to deal with invalid or corrupted PE files:

```python
# Verify if the file is a valid PE file before proceeding
try:
    # Just try to open it to check if it's a PE file
    test_pe = pefile.PE(file_path)
    has_valid_pe = True
except Exception as e:
    print(f"File is not a valid PE file: {str(e)}")
    has_valid_pe = False
    
# If it's not a valid PE file, create empty imports
if not has_valid_pe:
    print("Creating empty imports list since file is not a valid PE file")
    imports = []
    for _ in col_dlls:
        imports.append(0)  # Add 0 for each DLL
    for _ in col_func:
        imports.append(0)  # Add 0 for each function
else:
    # Proceed with normal import extraction
    imports = extract_imports(file_path, col_dlls, col_func)
```

### Fallback Mechanisms

For feature extraction functions, fallback mechanisms ensure that the system continues to operate even if extraction fails:

```python
# Extract sequence with fallback for non-PE files
sequence = extract_sequence(file_path)

# If disassembly fails, return default sequence
if sequence is None:
    # Create default sequence with "other" category
    steps = 128
    vect = 49
    default_data = np.zeros((1, steps, vect), dtype='float32')
    default_data[0, 0] = encode_dict["other"]
    return default_data
```

## Future Enhancements

Several potential enhancements could further improve Nigraan's capabilities:

### Model Updating

Implement a mechanism to update models based on new samples and user feedback:

```python
def update_models(feedback_data):
    # Load existing models
    # Update models with new data
    # Save updated models
    pass
```

### Additional Feature Types

Integrate additional feature types for more comprehensive analysis:

```python
def extract_new_feature_type(file_path):
    # Extract new feature type
    # Process and normalize
    return processed_features
```

### Online Learning

Implement online learning to adapt to emerging threats:

```python
def online_learning(file_data, user_feedback):
    # Update model weights based on user feedback
    # Apply incremental learning to adjust to new patterns
    pass
```

### Explainable AI

Enhance the system with explainable AI techniques to provide more transparent insights into detection decisions:

```python
def explain_decision(prediction, features):
    # Apply SHAP or LIME to explain decision
    # Identify features with the highest contribution
    return explanation
```