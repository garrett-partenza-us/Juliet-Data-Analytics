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



# This class was originally used by Achilles to handle various things (javalect.py)
# I have extracted the label splitting and java code preprocessing from it for use in CWE ASTNN
# This file is basically the pre-processing frontend that is run on java files before prepare.py converts methods to
# trees. This is NOT perfect, as it was designed for chunking methods in the style of the Juliet Test Suite
# This file is also used for prepping input files to analyze.py, a separate method is provided for that

# Many of the comments in here are from the original author: Nick Saccente

# JavaClass: receives a `path` of a Java file, extracts the code,
# converts the code from Allman to K&R, extracts the methods,
# and creates a list of JavaMethod objects.
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

# Javalect: contains functions that are responsible for
# Achilles' core functionality.
# This portion of the code is modified and used heavily by CWE ASTNN
class Javalect:
    def preprocess(folder_name, cwe_paths):
        # this list holds the data to train on
        odf = []  # cwe astnn
        # this list holds the oversampling results to extend the lists above
        odf2 = []
        # these variables aid in create an id number and counting the number of labels
        counter = 0
        goodNum = 0
        badNum = 0
        print("populating list (1st pass) . . . ")
        # find and assign initial number of labels
        counter, goodNum, badNum, odf = Javalect.make_labels(cwe_paths, counter, goodNum, badNum, False)
        print("Current balance is: Good: ", str(goodNum), "Bad:", str(badNum))
        print("Balancing Data by oversampling (2nd pass) . . .")
        # continue to grab labels until both labels are equal (oversample)
        counter, goodNum, badNum, odf2 = Javalect.make_labels(cwe_paths, counter, goodNum, badNum, True)
        # extend the list
        odf.extend(odf2)

        print("Balancing Complete\nGood:", str(goodNum), "Bad:", str(badNum))
        print("making dataframe . . . ")
        # turn the list into a pandas dataframe so we can serialize it
        odframe = pd.DataFrame(odf, columns=["id", "code", "label"])
        print("Number of rows: ", str(odframe.shape[0]))
        # randomize the rows so we don't have all the same label at the end
        # please note I made have found another shuffling scheme in prepare.py, this step may not be needed
        # if you want to duplicate seeds, I recommend commenting out this shuffle and testing the one in prepare.py
        print("randomizing dataframe . . .")
        odframe = shuffle(odframe)
        print("making pickle. . . ")
        # could use this function to check if path exists or not
        # def check_or_create(path):
        #    if not os.path.exists(path):
        #        os.mkdir(path)

        # serialize the dataframe, put it in the correct directory for cwe astnn to look for
        odframe.to_pickle("data/java/programs.pkl")
        print("making csv . . . ")
        # make a csv so we can make sure this stage happened properly
        file_name = "data/zCSV/" + folder_name + ".csv"
        odframe.to_csv(file_name, index=False)
        print("finished making labels!")

    
    # this method splits classes into good and bad method examples, cwe astnn also creates a class to wrap the method in
    def make_labels(cwe_paths, counter, goodNum, badNum, balance):
        # cwe astnn list
        odf = []
        # number of methods that failed to parse
        failed_methods = 0
        # number of files that failed preprocessing
        failed_count = 0  # counts how many times the loop try block failed
        # flags for balancing data
        contents = ""
        goodGreater = False
        balanced = False
        if balance and goodNum > badNum:
            goodGreater = True
        # while the dataset is not balanced and the setting is set to balance, continue to produce labels
        # this is a simple form of oversampling
        while not balanced:
            # we only want this to loop once if we aren't balancing
            if not balance:
                balanced = True

            # which file you are trying to process
            file_counter = 0

            # loop through every file path in the directory path
            for path in os.listdir(cwe_paths):
                file_counter = file_counter+1
                #print(str(file_counter))
                # stop making labels when balanced
                if balance and balanced:
                    break
                try:
                    j = JavaClass(path, cwe_paths)
                    # classHeader = j.header
                    for method in j.methods:
                        focus = method.tokens().split("(", 1) # this is causing it to fail
                        rand = Javalect.randomize()
                        # this code is to randomize the class name
                        # classList = classHeader.split(" ")
                        # for i in range(0, len(classList), 1):
                        #    if classList[i].find("CWE") != -1:
                        #        rand = Javalect.randomize()
                        #        classList[i] = rand
                        #        break
                        # classHeader = " ".join(classList)

                        # if we find good or bad in the method header, set the good variable
                        # Otherwise we discard the method- we don't want to incorrectly label inputs to training
                        # You could modify this to look for only one keyword and label the other keyword appropriately
                        good = True
                        if "good" in focus[0] and "Sink" not in focus[0] and "B2GSource" not in focus[0]:
                            temp = focus[0].replace("good", rand) + "(" + focus[1]
                        elif "bad" in focus[0]:
                            temp = focus[0].replace("bad", rand) + "(" + focus[1]
                            good = False
                        else:
                            continue
                        # obfuscate removes the words good, bad, and CWE from the training input
                        # this is to prevent memorization of the node names
                        contents = Javalect.obfuscate(temp)

                        # used for whole bad file, a previous experiment
                        #if not good:
                        #    contents = Javalect.obfuscate(j.src)
                        #    contents = Javalect.findStart(contents)
                        #else:
                        # contents = classHeader + " { " + contents + " }"

                        # contents_astnn = classHeader + " { " + contents + " }"

                        # make sure that the method will pass parsing by Javalect
                        # if the method will not parse, then it will be discarded
                        # we can't create a tree unless we parse
                        parse_able = Javalect.parseTest(contents)
                        # labels are 1 and 2 due to an off-by-one indexing error introduced by the original authors
                        # you can potentially fix it in train.py if you are motivated, however I
                        # manage labels in tensors in train.py using 0 and 1
                        if parse_able:
                            # if the flag is not set to balance, add what label it is
                            if not balance:
                                if good:
                                    goodNum += 1
                                    odf.append([counter, contents, "1"])
                                    counter += 1
                                elif not good:
                                    badNum += 1
                                    odf.append([counter, contents, "2"])
                                    counter += 1
                            # the flag is set to balance, add it only if it is the lesser label
                            else:
                                if good and not goodGreater:
                                    goodNum += 1
                                    odf.append([counter, contents, "1"])
                                    counter += 1
                                elif not good and goodGreater:
                                    badNum += 1
                                    odf.append([counter, contents, "2"])
                                    counter += 1
                                if goodGreater and (badNum >= goodNum):
                                    balanced = True
                                elif not goodGreater and (goodNum >= badNum):
                                    balanced = True
                        else:
                            failed_methods = failed_methods + 1
                # sometimes things go wrong, this catch will tell you what happened and skip that method
                except Exception as e:
                    print("make_labels failed", e)
                    traceback.print_exc()
                    failed_count = failed_count+1
                    #exit(1)
                    pass

        if failed_methods > 0 and not balance:
            print(str(failed_methods), "methods failed the parse test and were not included in the training set.")
            print("These files will not be selected for oversampling")
        if failed_count > 0 and not balance:
            print(str(failed_count), "files failed to preprocess, these files were skipped")
        return counter, goodNum, badNum, odf

    # This method is similar to preprocess but is used solely for analyze.py
    # See the method preprocess above for better comments
    
    def analyze_prep(dir_path):
        # we want to create a dataframe that contains the file_number, the contents, then a dummy label
        print("running analysis preparation...")
        # reset the failed file
        file = open("failed.txt", "w+")
        file.write("Init time: " + str(time.time()) + "\n")
        file.close()
        # init variables
        file_counter = 0
        failed_methods = 0
        failed_count = 0
        counter = 0
        abstract_count = 0
        method_list = []
        skipped_list = []
        failed_methods_list = []
        for path in os.listdir(dir_path):
            file_counter = file_counter + 1
            try:
                j = JavaClass(path, dir_path, analyze=True)
                # classHeader = j.header
                for method in j.methods:
                    focus = method.tokens().split("(", 1)# this is causing it to fail

                    # Bugfix by Garrett Partenza to prevent indexing errors
                    m = " ".join(focus)
                    if len(focus)==1:
                        contents=focus[0]
                    else:
                        contents = focus[0] + "(" + focus[1]
                    #
                    parse_able = Javalect.parseTest(contents)
                    if "abstract" in m or "interface" in m:
                        parse_able = False
                        abstract_count += 1

                    if parse_able:
                        method_list.append([file_counter, contents, "2", path]) # 2 is good, doesn't really matter
                        # 1 bad, 2 good
                        counter += 1
                    else:
                        failed_methods = failed_methods + 1
                        failed_methods_list.append(contents)

            except Exception as e:
                print("analyze file prep failed for path: ", path, " error: ", e)
                traceback.print_exc()
                failed_count = failed_count + 1
                skipped_list.append(str(path))
                # exit(1)
                pass

        ##### Error reporting #####
        if failed_count > 0:
            print(str(failed_count), "files failed to open, these files were skipped.",
                  "Failed files will be output to failed.txt")
            file = open("failed.txt", "w+")
            file.write("Failed files, time: " + str(time.time()) + "\n")
            for failed in skipped_list:
                file.write(str(failed) + "\n")
            file.close()
        if failed_methods > 0:
            print(str(failed_methods), "methods failed the parse test and can not be analyzed.",
                                       "Code provided must be parsable by Javalang and can't be abstract.",
                  "Failed methods will be output to failed.txt")
            file = open("failed.txt", "a+")
            file.write("Files that passed, but methods that failed, time: " + str(time.time()) + "\n")
            for failed in failed_methods_list:
                file.write(str(failed) + "\n")
            file.close()
        if abstract_count > 0:
            print(str(abstract_count), "methods failed because they are abstract and have no iterable tree.")
        ###############################
        print("Creating dataframe...")
        # turn the list into a pandas dataframe so we can serialize it
        df = pd.DataFrame(method_list, columns=["id", "code", "label", "file_name"])
        print("Number of rows (methods): ", str(df.shape[0]))

        # serialize the dataframe, put it in the correct directory for cwe astnn to look for
        df.to_pickle("data/java/analyze.pkl")
        print("making csv . . . ")
        # make a csv so we can make sure this stage happened properly
        file_name = "data/zCSV/analyze.csv"
        df.to_csv(file_name, index=False)
        print("Preparation complete.")

        return df

    
    def obfuscate(cl):
        cl = cl.replace("\n", " ")
        cl = cl.replace("\r", " ")
        cl = cl.replace("\t", " ")
        rand = Javalect.randomize()
        cl = cl.replace("good", rand)
        rand = Javalect.randomize()
        cl = cl.replace("bad", rand)
        rand = Javalect.randomize()
        cl = cl.replace("Good", rand)
        rand = Javalect.randomize()
        cl = cl.replace("Bad", rand)
        rand = Javalect.randomize()
        cl = cl.replace("CWE", rand)
        return cl

    
    def randomize():
        front = ''.join(random.choices(string.ascii_uppercase, k=7))
        back = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        rand = front + back
        return rand

    # returns the contents of the class starting from class header
    # this was used for whole bad file
    
    def findStart(whole):
        array = whole.split(" ")
        index = 0
        # find keyword class or interface
        try:
            index = array.index("class")
        except Exception:
            traceback.print_exc()
            try:
                index = array.index("interface")
            except Exception:
                traceback.print_exc()
        # go back one index
        start = index-1
        # set array of words to the start position and return a string
        array = array[start:]
        contents = " ".join(array)
        return contents

    
    def parseTest(code):
        try:
            tokens = javalang.tokenizer.tokenize(code)
            parser = javalang.parser.Parser(tokens)
            tree = parser.parse_member_declaration()
            return True
        except Exception:
            return False


   
