import pandas as pd 
import numpy as np
mat = pd.read_csv('weekday1.csv')
mat_dropna = mat.replace([np.inf,-np.inf],np.nan).dropna()
print(mat_dropna.columns.values.tolist())
mat_drop_bot = mat_dropna[~mat_dropna[' Label'].isin(['Bot'])]
mat_drop_bot.to_csv('weekday1_final.csv',index=False)

#!pip install PyQt5==5.9.2