import pandas as pd
import sys
import os
# Disables printing "Using XXX backend"
stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')
from keras.callbacks import EarlyStopping
from keras.layers import LSTM, Activation, Dense, Dropout, Input, Embedding
from keras.models import Model
from keras.optimizers import RMSprop
from keras.preprocessing import sequence
from keras.preprocessing.text import Tokenizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from constants import *
import warnings
warnings.filterwarnings("ignore")


# This class is from Project Achilles by Nick Saccente
# It is included for compatibility reasons

class AchillesModel:
    @staticmethod
    def RNN():
        inputs = Input(name='inputs', shape=[MAX_LEN])
        layer = Embedding(MAX_WORDS, 50, input_length=MAX_LEN)(inputs)
        layer = LSTM(64)(layer)
        layer = Dense(256, name='FC1')(layer)
        layer = Activation(ACTIVATION_FUNCT)(layer)
        layer = Dropout(DROPOUT_RATE)(layer)
        layer = Dense(1, name='out_layer')(layer)
        layer = Activation('sigmoid')(layer)
        model = Model(inputs=inputs, outputs=layer)
        return model

    @staticmethod
    def train(df, write_h5_to):
        if isinstance(df, str):
            df = pd.read_csv(df)
        X = df.input
        Y = df.label
        le = LabelEncoder()
        Y = le.fit_transform(Y)
        Y = Y.reshape(-1, 1)
        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=TEST_SIZE)

        tok = Tokenizer(num_words=MAX_WORDS)
        tok.fit_on_texts(X_train)
        sequences = tok.texts_to_sequences(X_train)
        sequences_matrix = sequence.pad_sequences(sequences, maxlen=MAX_LEN)

        model = AchillesModel.RNN()
        model.summary()
        model.compile(loss=LOSS_FUNCT, optimizer=RMSprop(), metrics=['accuracy'])
        #hist = model.fit(sequences_matrix, Y_train, batch_size=BATCH_SIZE, epochs=EPOCHS,
        #                 validation_split=VALIDATION_SPLIT, callbacks=[EarlyStopping(monitor='val_loss', min_delta=MIN_DELTA)])
        hist = model.fit(sequences_matrix, Y_train, batch_size=BATCH_SIZE, epochs=EPOCHS,
                                          validation_split=VALIDATION_SPLIT)
        test_sequences = tok.texts_to_sequences(X_test)
        test_sequences_matrix = sequence.pad_sequences(test_sequences, maxlen=MAX_LEN)
        accr = model.evaluate(test_sequences_matrix, Y_test)
        model.save(write_h5_to, overwrite=True)
        print('Test set\n  Loss: {:0.3f}\n  Accuracy: {:0.3f}\n'.format(accr[0], accr[1]))
