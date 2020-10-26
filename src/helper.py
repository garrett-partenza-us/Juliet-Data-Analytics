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

#function that takes in javalang ast and returns number of nodes
def count_nodes(tree):
    nodecount = 0
    for node in tree:
        nodecount+=1
    return nodecount

#function that takes in java method string and returns number of lines
def count_lines(method):
    return(len(str(method).splitlines()))

#function that takes in java method string and returns number of charecters
def count_chars(method):
    return(len(str(method)))
    
#function plots two lists of vulnerable and nonvulnerable statistical means spread across different file names
def plot(vmeans, smeans, names, mode):
    #plot opcode results
    barWidth = 0.25
    r1 = np.arange(len(vmeans))
    r2 = [x + barWidth for x in r1]
    plt.bar(r1, vmeans, color='#7f6d5f', width=barWidth, edgecolor='white', label='Vul')
    plt.bar(r2, smeans, color='#557f2d', width=barWidth, edgecolor='white', label='Safe')
    plt.xticks([r + barWidth for r in range(len(vmeans))], names)
    plt.legend()
    plt.savefig('/Users/garrettpartenza/Desktop/fall/expose_juliet/pngs/'+mode+'.png')
    plt.cla()
    plt.clf()
    plt.close()
    
#function to inspect and gather stats on a directory full of java files
def inspect_source(file):

    lv = []
    ls = []
    cv = []
    cs = []
    tv = []
    ts = []
    
    for subdir, dirs, files in os.walk('/Users/garrettpartenza/Desktop/fall/expose_juliet/javafiles/'+file):
        for file in files:
            if file.endswith("java") and file != "Main.java":
                javaclass = JavaClass(file, subdir)
                for method in javaclass.__iter__():
                    tokens = javalang.tokenizer.tokenize(str(method))
                    parser = javalang.parser.Parser(tokens)
                    tree = parser.parse_member_declaration()
                    focus = method.tokens().split("(", 1)
                    if "bad" in focus[0]:
                        lv.append(count_lines(method))
                        cv.append(count_chars(method))
                        tv.append(count_nodes(tree))
                    elif "good" in focus[0]:
                        ls.append(count_lines(method))
                        cs.append(count_chars(method))
                        ts.append(count_nodes(tree))
    return lv, ls, cv, cs, tv, ts
    
#function to inspect and gather stats on a directory full of java files
def inspect_op(filename):
    df = pd.read_pickle('/Users/garrettpartenza/Desktop/fall/expose_juliet/pickles/'+filename)
    vul = []
    safe = []
    for ind, row in df.iterrows():
       if int(row['Classification']) == 0:
           safe.append(len(row['Bytecode']))
       if int(row['Classification']) == 1:
           vul.append(len(row['Bytecode']))
    return vul, safe


class JavaClass:
    def __init__(self, path, directory, analyze=False):
        self.d = directory + "/" + path
        #if not analyze:
        #    self.header = JavaClass.findHeader(self.d, analyze)
        #else:
        self.header = "unknown"
        self.src = JavaClass._extract_code(self.d)
        self.src = JavaClass._allman_to_knr(self.src)
        self.methods = JavaClass.chunker(self.src)
        self.method_names = [method.name for method in self.methods]

    # __iter__: iterate through the methods in the JavaClass.
    def __iter__(self):
        return iter(self.methods)
    # not in use, was used temp to find class headers
    def findHeader(path, is_analysis):
        line = ""
        try:
            j_file = open(path, "r")

            line = j_file.readline()
            flag = True
            counter = 0
            while flag:
                if line.find("/") == -1:
                    if line.find("*") == -1:
                        if "class" in line or "interface" in line:
                            flag = False
                if not flag:
                    break
                line = j_file.readline()
                counter += 1
                if counter > 100000:
                    print("file exceeded findHeader threshold, could not find class header:", str(path))
                    quit(1)
            j_file.close()
            line = line.rstrip()
            words = line.split(" ")
            counter = 0
            if not is_analysis:
                for word in words:
                    if "class" in word:
                        front = ''.join(random.choices(string.ascii_uppercase, k=7))
                        back = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
                        words[counter + 1] = front + back
                        break
                    counter += 1
            line = " ".join(words)
            line = line + " "
        except Exception:
            print("failed to open", path)
            traceback.print_exc()
            exit(1)

        return line

    # _extract_code: receives a `path` to a Java file, removes all comments,
    # and returns the contents of the file without comments
    
    def _extract_code(path):
        content_file = open(path, 'r')
        string = content_file.read()
        #contents = re.sub(re.compile("/\*.*?\*/", re.DOTALL), "", contents)
        #contents = re.sub(re.compile("//.*?\n"),  "", contents)
        #contents = JavaClass.remove_whitespace(contents)
        pattern = r"(\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)"
        # first group captures quoted strings (double or single)
        # second group captures comments (//single-line or /* multi-line */)
        regex = re.compile(pattern, re.MULTILINE | re.DOTALL)

        def _replacer(match):
            # if the 2nd group (capturing comments) is not None,
            # it means we have captured a non-quoted (real) comment string.
            if match.group(2) is not None:
                return ""  # so we will return empty to remove the comment
            else:  # otherwise, we will return the 1st group
                return match.group(1)  # captured quoted-string
        content_file.close()
        return regex.sub(_replacer, string)
        #return contents

    def remove_whitespace(cl):
        cl = cl.replace("\n", " ")
        cl = cl.replace("\r", " ")
        cl = cl.replace("\t", " ")
        return cl

    # tokens: A getter that returns a 1-dimensional space-delimited
    # string of tokens for the whole source file.
    def tokens(self):
        tokens = javalang.tokenizer.tokenize(self.src)
        return [" ".join(token.value for token in tokens)][0]

    # find_occurences: Returns a list of all occurrences of
    # a character `ch` in a string `s`.
    def find_occurrences(s, ch):
        return [i for i, letter in enumerate(s) if letter == ch]

    # _allman_to_knr: Converts a string `contents` from the style of
    # allman to K&R. This is required for `chunker` to work correctly.
    def _allman_to_knr(contents):
        s, contents = [], contents.split("\n")
        line = 0
        while line < len(contents):
            if contents[line].strip() == "{":
                s[-1] = s[-1].rstrip() + " {"
            else:
                s.append(contents[line])
            line += 1
        return "\n".join(s)

    # chunker: Extracts the methods from `contents` and returns
    # a list of `JavaMethod` objects.
    def chunker(contents):
        r_brace = JavaClass.find_occurrences(contents, "}")
        l_brace = JavaClass.find_occurrences(contents, "{")
        tokens = javalang.tokenizer.tokenize(contents)
        guide, chunks = "", []
        _blocks = ["enum", "finally", "catch", "do", "else", "for",
                   "if", "try", "while", "switch", "synchronized"]

        for token in tokens:
            if token.value in ["{", "}"]:
                guide += token.value

        while len(guide) > 0:
            i = guide.find("}")
            l, r = l_brace[i - 1], r_brace[0]
            l_brace.remove(l)
            r_brace.remove(r)

            ln = contents[0:l].rfind("\n")
            chunk = contents[ln:r + 1]
            if len(chunk.split()) > 1:
                if chunk.split()[0] in ["public", "private", "protected"] and "class" not in chunk.split()[1]:
                    chunks.append(JavaMethod(chunk))
            guide = guide.replace("{}", "", 1)
        return chunks


# JavaMethod: receives a `chunk`, which is the method string.
class JavaMethod:
    def __init__(self, chunk):
        self.method = chunk
        self.name = chunk[:chunk.find("(")].split()[-1]

    # tokens: a getter that returns a 1-dimensional space-delimited
    # string of tokens for the method.
    def tokens(self):
        tokens = javalang.tokenizer.tokenize(self.method)
        return [" ".join(token.value for token in tokens)][0]

    # __str__: String representation for a method.
    def __str__(self):
        return self.method

    # __iter__: Iterator for the tokens of each method.
    def __iter__(self):
        tokens = javalang.tokenizer.tokenize(self.method)
        return iter([tok.value for tok in tokens])
