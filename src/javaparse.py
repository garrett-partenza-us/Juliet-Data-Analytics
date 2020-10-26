import javalang
import re
import random
import string
import numpy as np
import csv
import time
import traceback
from sklearn.utils.extmath import softmax
from sklearn.utils import shuffle
from datetime import datetime
from modelachilles import *

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

