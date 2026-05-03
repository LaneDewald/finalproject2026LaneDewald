# Final Project 26
### INF601 - Advanced Programming in Python
### Lane Dewald
### Mini Project 3
from flask import Flask, render_template, request, session, redirect, url_for
import requests
import json
import os
from datetime import datetime

app = Flask(__name__)
