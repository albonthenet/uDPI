
from pandas_confusion import ConfusionMatrix
import matplotlib.pyplot as plt
"""
y_test = ['business', 'business', 'business', 'business', 'business',\
        'business', 'business', 'business', 'business', 'business',\
                'business', 'business', 'business', 'business', 'business',\
                        'business', 'business', 'business', 'business',\
                        'business']

y_pred = ['health', 'business', 'business', 'business', 'business',\
       'business', 'health', 'health', 'business', 'business', 'business',\
              'business', 'business', 'business', 'business', 'business',\
'health', 'health', 'business', 'health']
"""
y_test = [2, 1, 1, 5, 5, 2, 7, 5, 3, 3, 1, 1, 5, 1, 3, 7, 5, 7, 3, 2, 1, 7, 1,\
3, 2, 5, 2, 7, 2, 1, 7, 3, 3, 3, 7, 5, 7, 5, 7, 1, 7, 2, 5, 1, 2, 2, 1, 7, 5,\
3, 7, 3, 7, 3, 3, 2, 7, 3, 1, 7, 2, 1, 7, 5, 7, 3, 2, 5, 1, 2, 3, 2, 7, 7, 3,\
7, 1, 3, 5, 1, 7, 1, 7, 1, 7, 7, 5, 3, 7, 2, 1, 5, 7, 1, 3, 7, 2, 5, 2, 1, 3,\
5, 2, 5, 2, 5, 3, 1, 7, 3, 1, 2, 3, 2, 5, 5, 7, 1, 1, 3, 5, 2, 3, 7, 7]
y_pred = [2, 5, 1, 5, 5, 2, 7, 5, 3, 3, 1, 1, 5, 1, 3, 7, 5, 7, 3, 2, 1, 7, 1,\
3, 2, 5, 2, 5, 2, 1, 7, 3, 3, 3, 7, 5, 7, 5, 3, 5, 7, 2, 5, 1, 2, 2, 1, 7, 5,\
3, 7, 3, 7, 3, 3, 2, 7, 3, 1, 7, 2, 1, 7, 5, 7, 3, 2, 5, 1, 2, 3, 2, 7, 7, 3,\
7, 1, 2, 5, 1, 7, 3, 7, 3, 7, 7, 5, 3, 7, 2, 1, 5, 5, 1, 3, 1, 2, 5, 2, 1, 3,\
5, 2, 5, 2, 1, 3, 2, 7, 3, 1, 2, 1, 2, 5, 5, 7, 1, 1, 3, 5, 2, 3, 7, 7]

"""
y_test = [600, 200, 200, 200, 200, 200, 200, 200, 500, 500, 500, 200, 200,200,\
200, 200, 200, 200, 200, 200]
y_pred = [100, 200, 200, 100, 100, 200, 200, 200, 100, 200, 500, 100, 100,100,\
100, 100, 100, 100, 500, 200]
"""


#print type(y_pred)
#test_str = map(str,y_test)
#pred_str = map(str,y_pred)

cm = ConfusionMatrix(y_test, y_pred)
#cm = ConfusionMatrix(test_str, pred_str)
print cm


cm.print_stats()
