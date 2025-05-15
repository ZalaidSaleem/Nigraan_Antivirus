import pandas as pd
import json
import csv
import os.path

# Use absolute paths with ./dm/ prefix
original_path = './dm/dataset/DataSetFiles/CSVFiles/original'
enc_path = './dm/dataset/DataSetFiles/CSVFiles/encoded'
headers = 'headers.csv'
grams = '4-grams.csv'
strings = 'strings.csv'
opcodes = 'opcodes.csv'
functions = 'functions.csv'
dlls = 'dlls.csv'


def read_chunk(chunk_number, chunk_size, columns, file):
    c_size = 20
    rows = {}
    chunk_number = int(chunk_number)
    chunk_size = int(chunk_size)
    columns = int(columns)
    file_path = os.path.join(original_path, file)
    
    # Check if file exists, if not return empty dataset with informative message
    if not os.path.exists(file_path):
        rows['error'] = f"File {file} not found in database"
        rows['columns'] = [f"File {file} not available - This is a placeholder message"]
        for i in range(chunk_number*chunk_size, (chunk_number+1)*chunk_size, 1):
            rows[i] = ["No data available - file not found"]
        return rows
        
    with open(file_path, 'r') as fls:
        csv_reader = csv.reader(fls)
        names = next(csv_reader)
        c_size = min(len(names), 1000)
        
        # Skip rows to reach the requested chunk
        try:
            for i in range(chunk_size*chunk_number):
                temp = next(csv_reader)
            
            # Read the requested chunk
            for i in range(chunk_number*chunk_size, (chunk_number+1)*chunk_size, 1):
                try:
                    row_data = next(csv_reader)
                    rows[i] = row_data[columns*c_size:(columns+1)*c_size]
                except StopIteration:
                    # End of file reached
                    rows[i] = ["End of data"]
                    
            rows['columns'] = names[columns*c_size:(columns+1)*c_size]
        except StopIteration:
            # Not enough rows in file
            rows['columns'] = names[columns*c_size:(columns+1)*c_size] if len(names) > columns*c_size else ["No data"]
            for i in range(chunk_number*chunk_size, (chunk_number+1)*chunk_size, 1):
                rows[i] = ["No data available - end of file reached"]
    
    return rows

def read_chunk_c(chunk_number, chunk_size, columns, file):
    rows = {}
    chunk_number = int(chunk_number)
    chunk_size = int(chunk_size)
    columns = int(columns)
    file_path = os.path.join(enc_path, file)
    
    # Check if file exists, if not return empty dataset with informative message
    if not os.path.exists(file_path):
        rows['error'] = f"File {file} not found in database"
        rows['columns'] = [f"File {file} not available - This is a placeholder message"]
        for i in range(chunk_number*chunk_size, (chunk_number+1)*chunk_size, 1):
            rows[i] = ["No data available - file not found"]
        return rows
        
    with open(file_path, 'r') as fls:
        csv_reader = csv.reader(fls)
        names = next(csv_reader)
        c_size = min(len(names), 1000)
        
        # Skip rows to reach the requested chunk
        try:
            for i in range(chunk_size*chunk_number):
                temp = next(csv_reader)
            
            # Read the requested chunk
            for i in range(chunk_number*chunk_size, (chunk_number+1)*chunk_size, 1):
                try:
                    row_data = next(csv_reader)
                    rows[i] = row_data[columns*c_size:(columns+1)*c_size]
                except StopIteration:
                    # End of file reached
                    rows[i] = ["End of data"]
                    
            rows['columns'] = names[columns*c_size:(columns+1)*c_size]
        except StopIteration:
            # Not enough rows in file
            rows['columns'] = names[columns*c_size:(columns+1)*c_size] if len(names) > columns*c_size else ["No data"]
            for i in range(chunk_number*chunk_size, (chunk_number+1)*chunk_size, 1):
                rows[i] = ["No data available - end of file reached"]
    
    return rows


