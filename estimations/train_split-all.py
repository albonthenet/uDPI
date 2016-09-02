import pandas
from sklearn import cross_validation
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from termcolor import colored

datasets = ['dataset_5p-250l.ds','dataset_15p-250l.ds','dataset_30p-150l.ds','dataset_45p-150l.ds']
models = ['DecisionTreeClassifier','GaussianNB','KNeighborsClassifier','SVC']

for model in models:
    print colored('Model: ' + model,'blue')
    for ds in datasets:
        dataframe = pandas.read_csv(ds)
        array = dataframe.values
        X = array[:,0:17]
        Y = array[:,17]
        test_size_in=0.15
        print colored('Dataset: ' + ds,'green')
        while (test_size_in<1):
            X_train, X_test, y_train, y_test\
            =cross_validation.train_test_split(X,Y,test_size=test_size_in, random_state=0)
            clf = globals()[model]().fit(X_train,y_train)
            #print 'Score obtained for ' + str(test_size_in*100) + '% test data: ' + str(clf.score(X_test,y_test))
            print 'Score obtained for %d test data: %0.3f' % ((test_size_in*100),clf.score(X_test,y_test))
            test_size_in+=0.15

#print 'Length of test data:'
#print len(X_test)
#print len(y_test)
#print 'Length of train data:'
#print len(X_train)
#print len(y_train)
#print y_test
#print y_train


#print clf.predict(X_test)
