import pandas as pd
from scipy import stats
import random
import matplotlib.pyplot as plt


df = pd.read_pickle('/Users/garrettpartenza/Desktop/fall/expose_juliet/arrays.pkl')

for indx, row in df.iterrows():

    k = (stats.kruskal(row['Safe'], row['Vulnerable']))[1]
    p = stats.mannwhitneyu(row['Vulnerable'], row['Safe'])[1]
    print(row['File'], "Kurskal: ", k, "Mann: ", p)
    

