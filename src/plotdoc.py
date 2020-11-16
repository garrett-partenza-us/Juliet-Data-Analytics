#import requirements
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler
import sys


#take user specified cwe arguemnet
cwe = sys.argv[1]

#load doc2vec features
data = pd.read_csv('../features/'+cwe+'(all).csv')

colors = (0,0,0)
area = np.pi*3

#load features excluding classification column
features = np.delete(data.columns.values, 0)

#use PCA to reduce dimensions down to 2 for sake of plotting
x = data.loc[:, features].values
x = StandardScaler().fit_transform(x)
pca = PCA(n_components=2)
principalComponents = pca.fit_transform(x)

#iterate through 2D PCA and plot
#use data classifications column for color coding
for i in range(data.shape[0]):
    if data.iloc[i][0] == 0:
        plt.scatter(principalComponents[i][0], principalComponents[i][1], s=area, c='m', alpha=0.5)
    elif data.iloc[i][0] == 1:
        plt.scatter(principalComponents[i][0], principalComponents[i][1], s=area, c='c', alpha=0.5)
        
#save figure to png folder
plt.savefig('../pngs/doc2vec-'+cwe+'.png')

