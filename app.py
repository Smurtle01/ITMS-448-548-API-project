# app.py
import tkinter as tk
from tkinter import ttk
from api_client import *
from analysis import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class DataApp:
    # the basic GUI
    def __init__(self, root):
        self.root = root
        self.root.title("Data Analysis Dashboard")

        ttk.Button(root, text="Load Data", command=self.load_data).pack()

        self.output = tk.Text(root, height=10)
        self.output.pack()

        self.canvas_frame = tk.Frame(root)
        self.canvas_frame.pack()

    # Basic loading of the datasets
    def load_data(self):
        self.df1 = get_dataset_1()
        self.df2 = get_dataset_2()
        self.df3 = get_dataset_3()
        self.df4 = get_dataset_4()

        self.run_analysis()
        
    # Running the analysis program
    def run_analysis(self):
        result = analyze_time_series(self.df1)

        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, f"Mean: {result['mean']}\n")
        self.output.insert(tk.END, f"Max: {result['max']}\n")

        self.plot_data()

    def plot_data(self):
        fig, ax = plt.subplots()
        ax.plot(self.df1["time"], self.df1["value"])

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

if __name__ == "__main__":
    root = tk.Tk()
    app = DataApp(root)
    root.mainloop()