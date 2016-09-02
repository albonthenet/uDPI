from termcolor import colored
import pandas
from sklearn import cross_validation
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler

##Models libraries
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB, MultinomialNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC,NuSVC,LinearSVC
from sklearn.ensemble import AdaBoostClassifier,RandomForestClassifier,GradientBoostingClassifier

##Datasets to be used
#ds = 'prueba_5sample.ds'
#ds = 'dataset_15p-sample-100l.ds'
#ds = 'dataset_5p-sample-100l.ds'
#ds = 'dataset_5p-250l.ds'

##Data extraction

def Data_extraction(ds):
    dataframe = pandas.read_csv(ds)
    array = dataframe.values
    X = array[:,0:17]
    Y = array[:,17]
    return X,Y

#Cross Validation parameters
def cv_parameters(X):
    num_folds = 10
    num_instances = len(X)
    seed = 7
    return num_folds,num_instances,seed

#datasets = ['dataset_15p-sample-100l.ds','dataset_5p-sample-100l.ds']
datasets = ['dataset_5p-250l.ds','dataset_15p-250l.ds','dataset_30p-150l.ds','dataset_45p-150l.ds']

models = ['DecisionTreeClassifier','GaussianNB','KNeighborsClassifier','SVC']
"""
models = ['DecisionTreeClassifier','GaussianNB','MultinomialNB',\
'KNeighborsClassifier','SVC','NuSVC','LinearSVC',\
'AdaBoostClassifier','RandomForestClassifier','GradientBoostingClassifier']
"""


for ds in datasets:
    print colored('Dataset: ' + ds,'green')
    X,Y = Data_extraction(ds)
    num_folds,num_instances,seed = cv_parameters(X)
    scaler = MinMaxScaler(feature_range=(0, 1))
    X = scaler.fit_transform(X)
    for model in models:
        
        kfold =cross_validation.KFold(n=num_instances,n_folds=num_folds,random_state=seed,shuffle=True)
        #kfold = cross_validation.ShuffleSplit(num_instances, n_iter=3,test_size=0.3,random_state=0)
        
        clf = globals()[model]()
        results = cross_validation.cross_val_score(clf, X, Y, cv=kfold)
        
        print("\tAccuracy: %0.2f (+/- %0.2f)" % (results.mean(), results.std() *2)\
        + " [" + model + "]")
