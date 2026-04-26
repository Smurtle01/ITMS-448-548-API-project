# api_client.py
import pandas as pd
import numpy as np

# Getters for all the API requests for the data we will analyse
def get_dataset_1():
    return pd.DataFrame({
        "time": range(50),
        "value": np.random.randint(0, 100, 50)
    })

def get_dataset_2():
    return pd.DataFrame({
        "category": ["A","B","C","D"],
        "count": [10, 25, 15, 30]
    })

def get_dataset_3():
    return pd.DataFrame({
        "x": np.random.randn(100),
        "y": np.random.randn(100)
    })

def get_dataset_4():
    return pd.DataFrame({
        "date": pd.date_range("2024-01-01", periods=30),
        "sales": np.random.randint(100, 500, 30)
    })