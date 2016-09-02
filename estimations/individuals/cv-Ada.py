import pandas
from sklearn import cross_validation
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import AdaBoostClassifier


#ds = 'prueba_5sample.ds'
ds = 'dataset_15p-sample-100l.ds'
#ds = 'dataset_5p-sample-100l.ds'
dataframe = pandas.read_csv(ds)
array = dataframe.values
X = array[:,0:17]
Y = array[:,17]

#print Y
#scaler = MinMaxScaler(feature_range=(0, 1))
#X = scaler.fit_transform(X)
#print X

#Cross Validation parameters
num_folds = 10
num_instances = len(X)
seed = 7

kfold = cross_validation.KFold(n=num_instances, n_folds=num_folds,random_state=seed)
#model = DecisionTreeClassifier(criterion="entropy",max_depth=11)
model = AdaBoostClassifier(DecisionTreeClassifier(max_depth=5),n_estimators=600,\
learning_rate=1.5,algorithm="SAMME")

print '\n'
print kfold
print '\n'
results = cross_validation.cross_val_score(model, X, Y, cv=kfold)

print results
print '\n'
print("Accuracy: %0.2f (+/- %0.2f)" % (results.mean(), results.std() * 2))
