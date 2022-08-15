# import required packages

import glob
import time
import pandas as pd
# from xml.dom import minidom
from nltk import ngrams
from nltk.tokenize import sent_tokenize
import nltk
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
from nltk.stem import PorterStemmer
from nltk.stem import PorterStemmer
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.corpus import stopwords 
from nltk.tokenize import word_tokenize
import keras
import os
import math
import numpy as np
import pickle

df=pd.read_csv('sqli.csv',encoding='utf-16')

df = df.sample(frac=1).reset_index(drop=True)

sentences=df['Sentence'].astype(str).tolist()
labels=df['Label'].tolist()

training_size = int(len(sentences) * 0.8)

X_train = sentences[0:training_size]
X_test = sentences[training_size:]
training_labels = labels[0:training_size]
testing_labels = labels[training_size:]

y_train = np.array(training_labels)
y_test = np.array(testing_labels)

# print(X_train[10])

import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

vocab_size = 4096
embedding_dim = 16
max_length = 40
trunc_type = 'post'
padding_type = 'post'
oov_tok = '<OOV>'

tokenizer = Tokenizer(num_words=vocab_size, oov_token=oov_tok)
tokenizer.fit_on_texts(X_train)
word_index = tokenizer.word_index
sequences = tokenizer.texts_to_sequences(X_train)
padded = pad_sequences(sequences, maxlen=max_length, padding=padding_type, truncating=trunc_type)

testing_sequences = tokenizer.texts_to_sequences(X_test)
testing_padded = pad_sequences(testing_sequences, maxlen=max_length, padding=padding_type, truncating=trunc_type)

reverse_word_index = dict([(value,key) for (key, value) in word_index.items()])

def decode_review(text):
  return " ".join([reverse_word_index.get(i,'?') for i in text])

print(padded[1])
print(X_train[1])

callback = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, mode='auto', baseline=None, restore_best_weights=True)

model = tf.keras.Sequential([
    tf.keras.layers.Embedding(vocab_size, embedding_dim, input_length=max_length),
    tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(8, return_sequences=True)),
    tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(7)),
    tf.keras.layers.Dense(9, activation='relu'),
    tf.keras.layers.Dense(9, activation='softmax')
])

# learning_rate = 0.0001
model.compile(loss='sparse_categorical_crossentropy',
                  optimizer='adam', 
                  metrics=['accuracy'])
print(model.summary())

BATCH_SIZE = 32
num_x_train = len(X_train)
print("num train" + str(num_x_train))

classifier_nn = model.fit(padded,y_train,
                    epochs=500,
                    verbose=True,
                    validation_data=(testing_padded, y_test),
                    steps_per_epoch=math.ceil(num_x_train/BATCH_SIZE),
                    callbacks=[callback]
                    )

import matplotlib.pyplot as plt
plt.plot(classifier_nn.history['loss'])
plt.plot(classifier_nn.history['val_loss'])
plt.title('model loss')
plt.ylabel('loss')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='upper left')
plt.show()

plt.plot(classifier_nn.history['accuracy'])
plt.plot(classifier_nn.history['val_accuracy'])
plt.title('model accuracy')
plt.ylabel('accuracy')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='upper left')
plt.show()

predict=model.predict(testing_padded)

pred = []

for i in range(len(predict)):
    # pred = np.argmax(predict[i])
    pred.append(np.argmax(predict[i]))

#accuracy
from sklearn.metrics import accuracy_score
print("\naccuracy : ")
print(accuracy_score(y_test,pred))
print("\n")

#confusion matrix
from sklearn.metrics import confusion_matrix
print("conf matrix : ")
print(confusion_matrix(y_test,pred))
print("\n")

# Recall
from sklearn.metrics import recall_score
print("recall : ")
print(recall_score(y_test,pred, average=None))
print("\n")

# Precision
from sklearn.metrics import precision_score
print("precision : ")
print(precision_score(y_test,pred, average=None))
print("\n")

#f1 score
from sklearn.metrics import f1_score
print("f1 score : ")
print(f1_score(y_test,pred, average=None))
print("\n")

for i,j in zip(y_test,pred):
    # print(i==j)
    if i==j :
        temp = 0

from keras.models import load_model
import pickle

model.save('bi-rnn.h5')

# saving
with open('bi-rnn.pickle', 'wb') as handle:
    pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)