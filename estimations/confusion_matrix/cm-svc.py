import pandas
from sklearn.preprocessing import MinMaxScaler
from sklearn import cross_validation
from sklearn import preprocessing
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.metrics import confusion_matrix, classification_report,accuracy_score
import numpy as np
import matplotlib.pyplot as plt

#names = ['ssh','ftp','whatsapp','BitTorrent','Skype']

names = ['whatsapp','ssh','ftp','BitTorrent','Tor','Skype']
#names = ['whatsapp','ssh','ftp','BitTorrent','Tor']

#ds = 'dataset_15p-sample-100l.ds'
#ds = 'prueba_5sample.ds'

#ds = 'dataset_5p-250l.ds'
#ds = 'dataset_15p-250l.ds'
#ds = 'dataset_30p-150l.ds'
ds = 'dataset_45p-150l.ds'

dataframe = pandas.read_csv(ds)
array = dataframe.values
X = array[:,0:17]
Y = array[:,17]
#X = preprocessing.scale(X)
X_train, X_test, y_train, y_test = cross_validation.train_test_split(X,Y, random_state=0)

print len(X_train)
print len(y_train)
print len(X_test)
print len(y_test)


scaler = MinMaxScaler(feature_range=(0, 1))
X_train = scaler.fit_transform(X_train)

X_test = scaler.fit_transform(X_test)


model = SVC().fit(X_train, y_train)
print 'X_test values:'
print X_test
y_pred = model.predict(X_test)
print 'ypred values:'
print y_pred

score = model.score(X_test, y_test)
print 'Score: ' + str(score)

print '\nStats:'
print(classification_report(y_test, y_pred, target_names=names))


acc_score = accuracy_score(y_test, y_pred)
print '\nAccuracy Score: ' + str(acc_score)

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
print('Normalized confusion matrix - 5 Packet/sample dataset')
print(cm_normalized)
plt.figure()
plot_confusion_matrix(cm_normalized, title='Normalized confusion matrix - 45 Packet/sample dataset')

plt.show()

