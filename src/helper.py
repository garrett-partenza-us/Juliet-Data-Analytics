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
def inspect_source(filename, sourceinfo, arrays):

    #path to directory containing the directories of cwe java files
    p2j = '/Users/garrettpartenza/Desktop/fall/expose_juliet/javafiles/'
    
    #dictionary to store lists of line, char, and node counts per method seperated by classification
    data = {'lv':[], 'ls': [], 'cv':[], 'cs': [], 'tv':[], 'ts': []}
    
    #generator for iterating through java files and extracting methods
    gen = (
    x for subdirs, dirs, files in os.walk(p2j+filename)
    for f in files if f.endswith("java") and f != "Main.java"
    for x in JavaClass(f,subdirs).__iter__()
    )
    
    #iterate over method generator
    for method in gen:
        
        #create ast tree
        tree = javalang.parser.Parser(javalang.tokenizer.tokenize(str(method))).parse_member_declaration()

        #if the method is vulnerable then update data dictionary with line, char, and node counts
        if "bad" in method.tokens().split("(", 1)[0]:
            data.update({
            'lv':data['lv']+[len(str(method).splitlines())],
            'cv':data['cv']+[len(str(method))],
            'tv':data['tv']+[len(list(tree))]
            })
            
        #if the method is safe then update data dictionary with line, char, and node counts
        elif "good" in method.tokens().split("(", 1)[0]:
            data.update({
            'ls':data['ls']+[len(str(method).splitlines())],
            'cs':data['cs']+[len(str(method))],
            'ts':data['ts']+[len(list(tree))]
            })
            
    #update sourceinfo dictionary with means
    sourceinfo.update({
    'names':sourceinfo['names']+[filename.split('.')[0]],
    'lines_vul':sourceinfo['lines_vul']+[statistics.mean(list(data['lv']))],
    'lines_safe':sourceinfo['lines_safe']+[statistics.mean(list(data['ls']))],
    'chars_safe':sourceinfo['chars_safe']+[statistics.mean(list(data['cs']))],
    'chars_vul':sourceinfo['chars_vul']+[statistics.mean(list(data['cv']))],
    'nodes_safe':sourceinfo['nodes_safe']+[statistics.mean(list(data['ts']))],
    'nodes_vul':sourceinfo['nodes_vul']+[statistics.mean(list(data['tv']))],
    })
    
    #update arrays dataframe with line count
    arrays = arrays.append({
    'File' : str(filename.split('.')[0])+'-lines' ,
    'Safe' : list(data['ls']),
    'Vulnerable' : list(data['lv'])} ,
    ignore_index=True)
    
    #update arrays dataframe with char count
    arrays = arrays.append({
    'File' : str(filename.split('.')[0])+'-chars' ,
    'Safe' : list(data['cs']),
    'Vulnerable' : list(data['cv'])} ,
    ignore_index=True)
    
    #update arrays dataframe with node count
    arrays = arrays.append({
    'File' : str(filename.split('.')[0])+'-nodes' ,
    'Safe' : list(data['ts']),
    'Vulnerable' : list(data['tv'])} ,
    ignore_index=True)

    #return the newly updated sourceinfo dictionary and arrays dataframe
    return sourceinfo, arrays
    
#function to inspect and gather stats on a directory full of java files
def inspect_op(filename, opinfo, arrays):

    #path to directory containing pickle files
    p2p = '/Users/garrettpartenza/Desktop/fall/expose_juliet/pickles/'+filename
    
    #dictionary to store lists of opcode counts per method seperated by classification
    data = {'vul':[], 'safe': []}
    
    #load pickle into pandas dataframe
    df = pd.read_pickle(p2p)
    
    #assign generatiors to data dictionary
    data['vul'] = list(len(row[1]['Bytecode']) for row in df[df['Classification']==1].iterrows())
    data['safe'] = list(len(row[1]['Bytecode']) for row in df[df['Classification']==0].iterrows())


    #update the arrays dataframe
    arrays = df.append({
    'File' : str(filename.split('.')[0])+'-opcodes' ,
    'Safe' : list(data['safe']),
    'Vulnerable' : list(data['vul'])} ,
    ignore_index=True)
    
    #update opinfo dictionary
    opinfo.update({
    'names':opinfo['names']+[filename.split('.')[0]],
    'vul':opinfo['vul']+[statistics.mean(list(data['vul']))],
    'safe':opinfo['safe']+[statistics.mean(list(data['safe']))]
    })

    #return the newly updated opinfo dictionary and arrays dataframe
    return opinfo, arrays



    
#function plots two lists of vulnerable and nonvulnerable statistical means spread across different file names
def plot(vmeans, smeans, names, mode):
    
    #create figure
    plt.figure(figsize=(10,10))
    barWidth = 0.25
    r1 = np.arange(len(vmeans))
    r2 = [x + barWidth for x in r1]
    plt.bar(r1, vmeans, color='c', width=barWidth, edgecolor='white', label='Vul')
    plt.bar(r2, smeans, color='m', width=barWidth, edgecolor='white', label='Safe')
    plt.xticks([r + barWidth for r in range(len(vmeans))], names, rotation=15, horizontalalignment='right', fontsize=7)
    plt.legend()
    
    #path to save the png figure
    p2png = '/Users/garrettpartenza/Desktop/fall/expose_juliet/pngs/'
    
    #save plot
    plt.savefig('/Users/garrettpartenza/Desktop/fall/expose_juliet/pngs/'+mode+'.png')
    
    #clear plot for next figure
    plt.clf()
