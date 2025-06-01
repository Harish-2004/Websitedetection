#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
import urllib.parse

# Suppress all warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

from feature import FeatureExtraction

file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()


app = Flask(__name__)

def split_url_components(url):
    """Split URL into static and dynamic components"""
    parsed = urllib.parse.urlparse(url)
    
    # Static part includes scheme, netloc, and path
    static_url = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        '',  # params
        '',  # query
        ''   # fragment
    ))
    
    # Dynamic part is the query string
    dynamic_url = parsed.query
    
    return static_url, dynamic_url

def get_prediction(url):
    """Get prediction for a given URL"""
    obj = FeatureExtraction(url)
    x = np.array(obj.getFeaturesList()).reshape(1,30)
    y_pred = gbc.predict(x)[0]
    y_pro_phishing = gbc.predict_proba(x)[0,0]
    y_pro_non_phishing = gbc.predict_proba(x)[0,1]
    return y_pred, y_pro_phishing, y_pro_non_phishing

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        
        # Split URL into static and dynamic parts
        static_url, dynamic_url = split_url_components(url)
        
        # Get predictions for full URL
        full_pred, full_pro_phishing, full_pro_non_phishing = get_prediction(url)
        
        # Get predictions for static part
        static_pred, static_pro_phishing, static_pro_non_phishing = get_prediction(static_url)
        
        # Get predictions for dynamic part if it exists
        dynamic_pred = None
        dynamic_pro_phishing = None
        dynamic_pro_non_phishing = None
        if dynamic_url:
            dynamic_pred, dynamic_pro_phishing, dynamic_pro_non_phishing = get_prediction(url)  # Using full URL for dynamic part
            
        return render_template('index.html',
                             full_url=url,
                             static_url=static_url,
                             dynamic_url=dynamic_url,
                             full_pred=full_pred,
                             full_pro_phishing=round(full_pro_phishing*100, 2),
                             full_pro_non_phishing=round(full_pro_non_phishing*100, 2),
                             static_pred=static_pred,
                             static_pro_phishing=round(static_pro_phishing*100, 2),
                             static_pro_non_phishing=round(static_pro_non_phishing*100, 2),
                             dynamic_pred=dynamic_pred,
                             dynamic_pro_phishing=round(dynamic_pro_phishing*100, 2) if dynamic_pro_phishing else None,
                             dynamic_pro_non_phishing=round(dynamic_pro_non_phishing*100, 2) if dynamic_pro_non_phishing else None)
    
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)