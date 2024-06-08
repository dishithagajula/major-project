from django.shortcuts import render
import pymysql
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn import svm

from sklearn.ensemble import RandomForestClassifier
import seaborn as sns
import numpy as np
import random
import joblib
from joblib import load

# Create your views here.
def index(request):
    return render(request,'AdminApp/index.html')
def login(request):
    return render(request,'AdminApp/Admin.html')
def LogAction(request):
    username=request.POST.get('username')
    password=request.POST.get('password')
    if username=='Admin' and password=='Admin':      
        return render(request,'AdminApp/AdminHome.html')
    else:
        context={'data':'Login Failed ....!!'}
        return render(request,'AdminApp/Admin.html',context)
def home(request):
    return render(request,'AdminApp/AdminHome.html')
global df
def LoadData(request):
    global df
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    df=pd.read_csv(BASE_DIR+"\\dataset\\Trojan_Detection.csv")
    #data.fillna(0, inplace=True)
    context={'data':"Dataset Loaded\n"}
    
    return render(request,'AdminApp/AdminHome.html',context)
global X
global y
global X_train,X_test,y_train,y_test
def split(request):
    global X_train,X_test,y_train,y_test
    global df
    df=df.drop(columns=['Flow ID',' Source IP',' Destination IP',' Timestamp'])
    df['Class']=df['Class'].map({'Trojan':1,'Benign':2})
    X=df.values[:, 0:80]
    y=df.values[:, 80:81]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=2)
    table="<table  border='1' style='margin-top:100px;'><tr><th>Total Dataset Records</th><th>80% records as training data</th><th>20% records as test data</th></tr>"
    table+="<tr><td>"+str(len(df))+"</td><td>"+str(len(X_train))+"</td><td>"+str(len(y_test))+"</td></tr>"
    table+="</table>"
    context={"data":table,"data2":"DataSet Preprocessed and Splitted Data"}
    return render(request,'AdminApp/AdminHome.html',context)

global RRacc
global Rmodel
def runRandomRegression(request):
    global RRacc
    global Rmodel
    #Rmodel = RandomForestClassifier()
    #Rmodel.fit(X_train, y_train)
    #joblib.dump(Rmodel, 'model/RandomModel.joblib')
    Rmodel=joblib.load('model/RandomModel.joblib')

    RRacc=Rmodel.score(X_train, y_train)*100
    context={"data":"RandomForest Accurary: "+str(RRacc)}
    return render(request,'AdminApp/AdminHome.html',context)
  


def PredAction(request):
    global Rmodel
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_data=pd.read_csv(BASE_DIR+"\\test\\test1.csv")
    testvalues = test_data.values[:, 0:80]
    Pred=Rmodel.predict(testvalues)
    extend_list = []
    for i in range(len(testvalues)):
        source_port=test_data.iloc[i,0]
        print(f"predicted value:{Pred[i]}, row: {i+1}")
        if str(Pred[i]) == "1.0":
            extend_list.append(f"At row {i+1} file detected as : Trojen".format(i+1))
        else:
            extend_list.append(f"At row {i+1} file detected as : Benign".format(i+1))

    context = {'data': extend_list}
    return render(request, 'AdminApp/PredictedData.html', context)









  

        
           
    
        
        
    
    



    




    

