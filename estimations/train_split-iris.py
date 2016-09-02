import pandas
from sklearn import cross_validation
from sklearn.tree import DecisionTreeClassifier

from sklearn.datasets import load_iris

iris = load_iris()


X, Y = iris.data, iris.target
X_train, X_test, y_train, y_test =\
cross_validation.train_test_split(X,Y,test_size=0.25,random_state=0)

print 'Length of test data:'
print len(X_test)
print len(y_test)
print 'Length of train data:'
print len(X_train)
print len(y_train)
#print y_test
#print y_train

clf = DecisionTreeClassifier().fit(X_train,y_train)
print clf.score(X_test,y_test)

#print clf.predict(X_test)
