import os
import javalang
import re
import random
import string
import numpy as np
import traceback
import statistics
import matplotlib.pyplot as plt
import pandas as pd
from javaparser import *
    
#function to inspect and gather stats on a directory full of java files
def prep(filename):
    #path to directory containing the directories of cwe java files
    p2j = '/Users/garrettpartenza/Desktop/fall/expose_juliet/javafiles/'
    
    #generator for iterating through java files and extracting methods
    gen = (
    x for subdirs, dirs, files in os.walk(p2j+filename)
    for f in files if f.endswith("java") and f != "Main.java"
    for x in JavaClass(f,subdirs).__iter__()
    )
    
    filename = filename.split("_")[0]
    try:
        os.mkdir("faast/prep/"+filename)
    except:
        pass
    count=0
    classifications = []
    
    
    #iterate over method generator
    for method in gen:
        #create ast tree
        #tree = javalang.parser.Parser(javalang.tokenizer.tokenize(str(method))).parse_member_declaration()
        #if the method is vulnerable then update data dictionary with line, char, and node counts
        if "bad" in method.tokens().split("{",1)[0]:
            file = open("faast/prep/"+filename+"/"+str(count)+".txt", "w+")
            file.write(str(method))
            file.close()
            classifications.append([count, "True"])
            count+=1
            
        #if the method is safe then update data dictionary with line, char, and node counts
        elif "good" in method.tokens().split("{",1)[0] and "good (" not in method.tokens().split("{",1)[0]:
            file = open("faast/prep/"+filename+"/"+str(count)+".txt", "w+")
            file.write(str(method))
            file.close()
            classifications.append([count, "False"])
            count+=1

        
        
    df = pd.DataFrame(classifications, columns = ['Filename', 'Classification'])
    df.to_csv("faast/classifications/"+filename+".csv")

    


#path to directory containing java files
p2s = '/Users/garrettpartenza/Desktop/fall/expose_juliet/javafiles'

#iterate over java files and call inspect_source in helper.py
gen = (f for f in os.listdir(p2s) if not f.startswith('.'))
for filename in gen:
    print("Prepping CWE"+filename.split("_")[0])
    prep(filename)
