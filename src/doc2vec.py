#import requirements
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
import pandas as pd
import sys
import nltk
import csv
import random
import string
from nltk.tokenize import word_tokenize
from sklearn.decomposition import PCA
import numpy as np
from sklearn.preprocessing import StandardScaler


def embed(df, cwe):

    #list of processed documents used for doc2vec training
    tokenized_doc = []

    #generator of bytecode files in dataframe
    data = (x[2:] for x in df['Bytecode'])
    
    #loop through each bytecode file in generator above
    for bytecode in data:
    
        #temporary list for story processed opcodes
        # we will append this list to tokenized docs when each bytecode file is processed
        temp = []
        
        #iterate over each opcode in bytecode file
        for opcode in bytecode:
            
            #strip and remove line numbers
            opcode = list(x.strip() for x in opcode.split(maxsplit=3)[1:])
            
            #if the opcode has a comment
            if len(opcode)==3:
            
                #remove reference number
                opcode.pop(1)
                
                #if comment needs to be obfuscated
                if ("good" in str(opcode[1])) or ("bad" in str(opcode[1])):
                    
                    #Obfuscate biased field
                    if ("Field" in str(opcode[1])):
                    
                        #replace bias with random string of random length
                        length_of_string = random.choice(range(5, 13))
                        random_string = "".join(random.choice(string.ascii_letters) for i in range(length_of_string))
                        random_string = 'Field '+random_string
                        opcode[1]=random_string
                        
                    #Obfuscate biased method
                    elif ("Method" in str(opcode[1])):
                    
                        #replace bias with random string of random length
                        length_of_string = random.choice(range(5, 13))
                        random_string = "".join(random.choice(string.ascii_letters) for i in range(length_of_string))
                        random_string = 'Method '+str(random_string)
                        opcode[1]=random_string
                        
                #remove multiple spaces, then join spaces with a dash and append to temp
                temp.append((' '.join((' '.join(opcode)).split())).replace(" ","-"))
            
            #if the opcode does not have a comment
            else:
            
                #convert list of length one to string and append to temp
                temp.append(' '.join(opcode))
                
        #append temp to tokenized doc
        tokenized_doc.append(temp)

    #tag data with unique identifier
    tagged_data = [TaggedDocument(d, [i]) for i, d in enumerate(tokenized_doc)]
    
    ## Train doc2vec model
    model = Doc2Vec(tagged_data, vector_size=100, min_count=1, workers=4, epochs = 100, dm=0)
    
    #return a trained model
    return(model)
    
def to_csv(model, type, df, cwe):
    
    #vecs will store a list of document embeddings to be written to features csv
    vecs = []
    count = 0
    classifications = df['Classification'].tolist()

    #iterate over vectors and append to vecs list with classification as header
    for docvecs in iter(model.docvecs.vectors_docs):
        docvecs = docvecs.tolist()
        docvecs.insert(0,classifications[count])
        vecs.append(docvecs)
        count+=1
        
    #create header for csv file
    #y0, y1, y2....y99
    header = ["classification"]
    for feat in range(len(vecs[0])-1):
        header.append("y"+str(feat))

    #write features to csv
    with open("../features/"+cwe+"("+type+").csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(vecs)


if __name__ == '__main__':
    
    #user defined cwe to embed
    cwe = sys.argv[1]
    
    #retrieve dataframe with bytecode
    df = pd.read_pickle('../pickles/'+cwe+'.pkl')

    #embed bytecode files using doc2vec and save the features to csv
    features = embed(df, cwe)
    to_csv(features, "all", df, cwe)

    #split features into train and test
    df = pd.read_csv("../features/"+cwe+"(all).csv")
    df[:int(df.shape[0]*0.7)].to_csv("../features/"+cwe+"(train).csv")
    df[int(df.shape[0]*0.7):].to_csv("../features/"+cwe+"(test).csv")
