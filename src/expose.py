import os
import statistics
from helper import *

def main():
        
    #begin opcode analysis
    names = []
    ov_means = []
    os_means = []
    
    for filename in os.listdir('/Users/garrettpartenza/Desktop/fall/expose_juliet/pickles'):
        names.append((filename.split('.')[0]))
        if filename.endswith(".pkl"):
            vul, safe = inspect_op(filename)
            ov_means.append(statistics.mean(vul))
            os_means.append(statistics.mean(safe))
            
    plot(ov_means, os_means, names, "opcode")

    #begin source analysis
    names = []
    lv_means = []
    ls_means = []
    cv_means = []
    cs_means = []
    tv_means = []
    ts_means = []
    
    for file in os.listdir('/Users/garrettpartenza/Desktop/fall/expose_juliet/javafiles'):
        print(file)
        names.append(file)
        lv, ls, cv, cs, tv, ts = inspect_source(file)
        lv_means.append(statistics.mean(lv))
        ls_means.append(statistics.mean(ls))
        cv_means.append(statistics.mean(cv))
        cs_means.append(statistics.mean(cs))
        tv_means.append(statistics.mean(tv))
        ts_means.append(statistics.mean(ts))
        
    plot(lv_means, ls_means, names, "line")
    plot(cv_means, cs_means, names, "char")
    plot(tv_means, ts_means, names, "node")
    

if __name__ == "__main__":
   main()
   

