import pandas as pd 
import numpy as np
#!unzip weekday1.csv.zip
source2017 = pd.read_csv('weekday1.csv')
source2017 = source2017.replace([np.inf,-np.inf],np.nan).dropna()
source2017 = source2017[~source2017[' Label'].isin(['Bot'])]
source2017 = source2017.drop(['Fwd PSH Flags',' Bwd PSH Flags',' Fwd URG Flags',' Bwd URG Flags','FIN Flag Count',' SYN Flag Count',' RST Flag Count',' PSH Flag Count',' ACK Flag Count',' URG Flag Count',' CWE Flag Count',' ECE Flag Count',' Down/Up Ratio','Subflow Fwd Packets',' Subflow Fwd Bytes',' Subflow Bwd Packets',' Subflow Bwd Bytes','Idle Mean',' Idle Std',' Idle Max','Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate',' Fwd Header Length.1',' Idle Min'],axis=1)

print(source2017.columns.values.tolist())
print(len(source2017.columns.values.tolist()))
source2017.to_csv('weekday1_final.csv',index=False)