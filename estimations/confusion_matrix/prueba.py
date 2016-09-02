import pandas
from sklearn import cross_validation
from sklearn import preprocessing
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix, classification_report,accuracy_score

import numpy as np
import matplotlib.pyplot as plt

#names = ['ssh','ftp','whatsapp','BitTorrent','Skype']

names = ['whatsapp','ssh','ftp','BitTorrent','Tor','Skype']
#names = ['whatsapp','ssh','ftp','BitTorrent','Tor']

#ds = 'dataset_15p-sample-100l.ds'
#ds = 'prueba_5sample.ds'

#ds = 'dataset_5p-250l.ds'
ds = 'dataset_15p-250l.ds'
#ds = 'dataset_30p-150l.ds'
ds_test = 'prueba_eval.ds'

dataframe2 = pandas.read_csv(ds_test)
array2 = dataframe2.values
X_unk = array2[:,0:17]
y_unk = array2[:,17]

dataframe = pandas.read_csv(ds)
array = dataframe.values
X = array[:,0:17]
Y = array[:,17]

model = DecisionTreeClassifier().fit(X,Y)
y_pred = model.predict(X_unk)

print y_unk
print y_pred
print accuracy_score(y_unk,y_pred)
exit()

def plot_confusion_matrix(cm, title='Confusion matrix', cmap=plt.cm.Blues):
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(names))
    plt.xticks(tick_marks, names, rotation=45)
    plt.yticks(tick_marks, names)
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')

# Compute confusion matrix
cm = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)
print('Confusion matrix, without normalization')
print(cm)
plt.figure()
plot_confusion_matrix(cm)

# Normalize the confusion matrix by row (i.e by the number of samples
# in each class)
cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
print('Normalized confusion matrix')
print(cm_normalized)
plt.figure()
plot_confusion_matrix(cm_normalized, title='Normalized confusion matrix')

plt.show()

score = model.score(X_test, y_test)
print score

print '\nStats:'
print(classification_report(y_test, y_pred, target_names=names))


acc_score = accuracy_score(y_test, y_pred)
print '\nAccuracy Score: ' + str(acc_score)
