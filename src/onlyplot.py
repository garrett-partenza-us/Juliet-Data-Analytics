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

#function plots two lists of vulnerable and nonvulnerable statistical means spread across different file names
def plot(vmeans, smeans, names, mode):
    
    #create figure
    plt.figure(figsize=(10,10))
    barWidth = 0.25
    r1 = np.arange(len(vmeans))
    r2 = [x + barWidth for x in r1]
    if mode == "node":
        for i, n in enumerate(names):
            print(n)
            print(vmeans[i]-smeans[i])
            print("\n")
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
