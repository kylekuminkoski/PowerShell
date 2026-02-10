import pandas as pd

import numpy as np

import seaborn as sns

import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.metrics import (
confusion_matrix, accuracy_score, precision_score, recall_score,
f1_score, matthews_corrcoef, cohen_kappa_score, roc_auc_score, roc_curve)

# Load dataset

df = pd.read_csv("C:\Users\kkuminkoski\PowerShell\CYBR\spambase.csv")

# Clean target column
df["type"] = df["type"].str.lower().str.strip()
df["type"]= df["type"].replace({"nonspam": 0, "spam": 1})