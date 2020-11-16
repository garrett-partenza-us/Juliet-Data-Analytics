import os
import statistics
from helper import *

def main():

    #create pandas dataframe
    #columns of th dataframe are as follows...
    #file:[cwe]+[line/char/node]
    #vul:[list of count from vulnerable methods]
    #safe:[list of count from vulnerable methods]
    arrays = pd.DataFrame(columns = ['File', 'Safe', 'Vulnerable'])
    
    #path to directory containing pickle files of method bytecode
    #if you change this, you must also change p2p in helper.py
    p2p = '/Users/garrettpartenza/Desktop/fall/expose_juliet/pickles'
    
    #dictionary to store final means for opcode count
    opinfo = {'names':[], 'vul':[], 'safe':[]}
    
    print('gathering opcode info...')
    
    #iterate over pickle files and call inspect_op function in helper.py
    gen = (f for f in os.listdir(p2p) if f.endswith('.pkl') and not f.startswith('.'))
    for filename in gen:
        opinfo, arrays = inspect_op(filename, opinfo, arrays)
    plot(opinfo['vul'], opinfo['safe'], opinfo['names'], "opcode")

    
    #path to directory containing java files
    p2s = '/Users/garrettpartenza/Desktop/fall/expose_juliet/javafiles'
    
    #dictionary to store final means for line, char, and node counts
    sourceinfo = {'names':[], 'lines_vul':[], 'lines_safe':[], 'chars_vul':[], 'chars_safe':[], 'nodes_vul':[], 'nodes_safe':[]}
    
    print('gathering sourcecode info...')

    #iterate over java files and call inspect_source in helper.py
    gen = (f for f in os.listdir(p2s) if not f.startswith('.'))
    for filename in gen:
        sourceinfo, arrays = inspect_source(filename, sourceinfo, arrays)
    
    print('plotting data...')

    #plot the means by calling plot function in helper.py
    plot(sourceinfo['lines_vul'], sourceinfo['lines_safe'], sourceinfo['names'], "line")
    plot(sourceinfo['chars_vul'], sourceinfo['chars_safe'], sourceinfo['names'], "char")
    plot(sourceinfo['nodes_vul'], sourceinfo['nodes_safe'], sourceinfo['names'], "node")
    
    #path to save arrays serialized file
    psa = '/Users/garrettpartenza/Desktop/fall/expose_juliet/arrays.pkl'
    
    #save arrays dataframe to p2a
    arrays.to_pickle('/Users/garrettpartenza/Desktop/fall/expose_juliet/arrays.pkl')
    

if __name__ == "__main__":
   main()
   

